package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorBody is the standard API error envelope from API_CONTRACTS.md.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail describes a failed request.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WriteError writes a structured error response without stack traces or secrets.
func WriteError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, ErrorBody{
		Error: ErrorDetail{Code: code, Message: message},
	})
}

// WriteData writes a successful REST envelope { "data": ... }.
func WriteData(c *gin.Context, status int, data any) {
	c.JSON(status, gin.H{"data": data})
}

// Convenience statuses.
const (
	CodeValidation      = "VALIDATION_ERROR"
	CodeUnauthorized    = "UNAUTHORIZED"
	CodePayloadTooLarge = "PAYLOAD_TOO_LARGE"
	CodeQueueFull       = "QUEUE_FULL"
	CodeInternal        = "INTERNAL_ERROR"
)

// WriteUnauthorized is used by sensor auth middleware.
func WriteUnauthorized(c *gin.Context, message string) {
	WriteError(c, http.StatusUnauthorized, CodeUnauthorized, message)
}
