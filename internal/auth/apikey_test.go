package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T) {
	tests := []struct {
		name        string
		header      http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "valid header",
			header:      http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectedErr: nil,
		},
		{
			name:        "missing header",
			header:      http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed header - missing ApiKey prefix",
			header:      http.Header{"Authorization": []string{"Bearer token123"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "malformed header - no token",
			header:      http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.header)
			if key != tt.expectedKey {
				t.Errorf("expected key: %s, got: %s", tt.expectedKey, key)
			}

			if err != nil && tt.expectedErr == nil {
				t.Errorf("expected no error got: %v", err)
			} else if err == nil && tt.expectedErr != nil {
				t.Errorf("expected error: %v, got none", tt.expectedErr)
			} else if err != nil && tt.expectedErr != nil && err.Error() != tt.expectedErr.Error() {
				t.Errorf("expected error: %v, got: %v", tt.expectedErr, err)
			}
		})
	}
}
