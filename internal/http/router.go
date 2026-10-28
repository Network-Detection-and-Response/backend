package httpapi

import (
	"log/slog"

	"github.com/Network-Detection-and-Response/backend/internal/config"
	"github.com/Network-Detection-and-Response/backend/internal/http/handlers"
	"github.com/Network-Detection-and-Response/backend/internal/http/middleware"
	"github.com/gin-gonic/gin"
)

// Dependencies wired into the HTTP layer for the bootstrap stage.
type Dependencies struct {
	Config config.Config
	Log    *slog.Logger
	DB     handlers.DBPinger
}

// NewRouter builds the Gin engine with health endpoints and baseline middleware.
func NewRouter(deps Dependencies) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestLogger(deps.Log))
	r.Use(middleware.CORS(deps.Config.CORSAllowedOrigins))
	r.MaxMultipartMemory = deps.Config.MaxBodyBytes

	health := &handlers.Health{DB: deps.DB}
	r.GET("/healthz", health.Healthz)
	r.GET("/readyz", health.Readyz)

	return r
}

func requestLogger(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		log.Info("http_request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"client_ip", c.ClientIP(),
		)
	}
}
