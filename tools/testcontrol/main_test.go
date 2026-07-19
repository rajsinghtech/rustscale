package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/tstest/integration/testcontrol"
)

func TestAuditLogStatsEndpoint(t *testing.T) {
	h := handleAuditLogStats(&testcontrol.Server{})

	recorder := httptest.NewRecorder()
	h(recorder, httptest.NewRequest(http.MethodGet, "/testapi/audit-log", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d", recorder.Code)
	}
	var got auditLogStatsResponse
	if err := json.NewDecoder(recorder.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got != (auditLogStatsResponse{}) {
		t.Fatalf("unexpected initial stats: %+v", got)
	}

	recorder = httptest.NewRecorder()
	h(recorder, httptest.NewRequest(http.MethodPost, "/testapi/audit-log", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status=%d", recorder.Code)
	}
}
