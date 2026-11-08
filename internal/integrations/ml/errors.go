package ml

import "errors"

var (
	// ErrNotConfigured means ML_SERVICE_URL is empty.
	ErrNotConfigured = errors.New("ml client is not configured")
	// ErrInvalidResponse means the ML HTTP body could not be parsed or validated.
	ErrInvalidResponse = errors.New("ml response is invalid")
	// ErrInvalidProbabilities means class probabilities failed validation.
	ErrInvalidProbabilities = errors.New("ml probabilities are invalid")
	// ErrHTTPStatus means a non-2xx status was returned.
	ErrHTTPStatus = errors.New("ml service returned non-success status")
)
