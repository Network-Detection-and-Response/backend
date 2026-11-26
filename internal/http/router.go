package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/Network-Detection-and-Response/backend/internal/config"
	"github.com/Network-Detection-and-Response/backend/internal/http/handlers"
	"github.com/Network-Detection-and-Response/backend/internal/http/middleware"
	"github.com/Network-Detection-and-Response/backend/internal/realtime"
	authsvc "github.com/Network-Detection-and-Response/backend/internal/service/auth"
	"github.com/Network-Detection-and-Response/backend/internal/service/flows"
	"github.com/Network-Detection-and-Response/backend/internal/service/incidents"
	"github.com/Network-Detection-and-Response/backend/internal/service/stats"
	"github.com/Network-Detection-and-Response/backend/internal/service/topology"
	"github.com/gin-gonic/gin"
)

// Dependencies wired into the HTTP layer.
type Dependencies struct {
	Config          config.Config
	Log             *slog.Logger
	DB              handlers.DBPinger
	FlowEnqueuer    handlers.FlowEnqueuer
	FlowListService *flows.Service
	IncidentService *incidents.Service
	TopologyService *topology.Service
	StatsService    *stats.Service
	AuthService     *authsvc.Service
	Realtime        *realtime.Hub
}

// NewRouter builds the Gin engine with health, auth, flows, incidents, topology, stats and WebSocket.
func NewRouter(deps Dependencies) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestLogger(deps.Log))
	r.Use(middleware.CORS(deps.Config.CORSAllowedOrigins))
	r.Use(middleware.LimitRequestBody(deps.Config.MaxBodyBytes))
	r.MaxMultipartMemory = deps.Config.MaxBodyBytes

	health := &handlers.Health{DB: deps.DB}
	r.GET("/healthz", health.Healthz)
	r.GET("/readyz", health.Readyz)

	if deps.Realtime != nil {
		ws := &handlers.Stream{Hub: deps.Realtime}
		r.GET("/ws/stream", ws.Serve)
	}

	flowHandlers := &handlers.Flows{
		Enqueuer:         deps.FlowEnqueuer,
		MaxFlowsPerBatch: deps.Config.MaxFlowsPerBatch,
		ListService:      deps.FlowListService,
	}
	v1 := r.Group("/api/v1")
	{
		v1.POST("/flows", middleware.SensorAPIKey(deps.Config.SensorAPIKey), flowHandlers.AcceptBatch)
		if deps.FlowListService != nil {
			v1.GET("/flows", flowHandlers.List)
		}
		if deps.IncidentService != nil {
			inc := &handlers.Incidents{Service: deps.IncidentService}
			v1.GET("/incidents", inc.List)
			v1.GET("/incidents/:id", inc.Get)
			v1.PATCH("/incidents/:id", inc.Patch)
		}
		if deps.TopologyService != nil {
			topo := &handlers.Topology{Service: deps.TopologyService}
			v1.GET("/topology", topo.Get)
		}
		if deps.StatsService != nil {
			st := &handlers.Stats{Service: deps.StatsService}
			v1.GET("/stats/overview", st.Overview)
			v1.GET("/stats/timeseries", st.Timeseries)
		}

		if deps.AuthService != nil {
			authHandlers := &handlers.Auth{
				Service:      deps.AuthService,
				CookieName:   deps.Config.AuthCookieName,
				CookieSecure: deps.Config.AuthCookieSecure,
				SameSite:     http.SameSiteLaxMode,
			}
			registerLimiter := middleware.NewRateLimiter(
				deps.Config.AuthRateLimitRegister,
				deps.Config.AuthRateLimitWindow,
			)
			loginLimiter := middleware.NewRateLimiter(
				deps.Config.AuthRateLimitLogin,
				deps.Config.AuthRateLimitWindow,
			)
			csrf := middleware.ProtectStateChange(deps.Config.CORSAllowedOrigins)

			authGroup := v1.Group("/auth")
			{
				authGroup.POST("/register",
					csrf,
					middleware.LimitByIP(registerLimiter, "register"),
					authHandlers.Register,
				)
				authGroup.POST("/login",
					csrf,
					middleware.LimitByIP(loginLimiter, "login"),
					authHandlers.Login,
				)
				authGroup.POST("/logout", csrf, authHandlers.Logout)
				authGroup.GET("/me", authHandlers.Me)
			}
		}
	}

	return r
}

func requestLogger(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if log == nil {
			return
		}
		log.Info("http_request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"client_ip", c.ClientIP(),
		)
	}
}
