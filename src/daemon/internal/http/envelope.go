package http

import (
	"encoding/json"
	"net/http"
)

type Envelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func SuccessEnvelope(data any) Envelope {
	raw, _ := json.Marshal(data)
	return Envelope{
		Code:    0,
		Message: "ok",
		Data:    raw,
	}
}

func ErrorEnvelope(code string, message string) Envelope {
	return Envelope{
		Code:    -1,
		Message: message,
	}
}

func WriteSuccess(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, SuccessEnvelope(data))
}

func WriteError(w http.ResponseWriter, httpStatus int, code string, message string) {
	writeJSON(w, httpStatus, ErrorEnvelope(code, message))
}

func WriteBadRequest(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusBadRequest, "bad_request", message)
}

func WriteNotFound(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusNotFound, "not_found", message)
}

func WriteInternalError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusInternalServerError, "internal_error", message)
}

func WriteServiceUnavailable(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusServiceUnavailable, "service_unavailable", message)
}
