package httpapi

import (
	"log/slog"

	"github.com/Network-Detection-and-Response/backend/internal/config"
	"github.com/Network-Detection-and-Response/backend/internal/http/handlers"
	"github.com/Network-Detection-and-Response/backend/internal/http/middleware"
	"github.com/gin-gonic/gin"
)

// Dependencies wired into the HTTP layer.
type Dependencies struct {
	Config       config.Config
	Log          *slog.Logger
	DB           handlers.DBPinger
	FlowEnqueuer handlers.FlowEnqueuer
}

// NewRouter builds the Gin engine with health and flow ingestion endpoints.
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

	flows := &handlers.Flows{
		Enqueuer:         deps.FlowEnqueuer,
		MaxFlowsPerBatch: deps.Config.MaxFlowsPerBatch,
	}
	v1 := r.Group("/api/v1")
	{
		v1.POST("/flows", middleware.SensorAPIKey(deps.Config.SensorAPIKey), flows.AcceptBatch)
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
