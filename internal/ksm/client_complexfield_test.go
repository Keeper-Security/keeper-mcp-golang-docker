package ksm

import "testing"

// TestIsUnsupportedComplexFieldUpdate verifies that UpdateSecret's guard correctly
// distinguishes scalar fields (settable via SetFieldValueSingle) from structured /
// complex fields and flattened sub-field paths (which would silently no-op).
func TestIsUnsupportedComplexFieldUpdate(t *testing.T) {
	cases := map[string]bool{
		// Scalar fields — supported via SetFieldValueSingle.
		"login":       false,
		"password":    false,
		"url":         false,
		"text":        false,
		"multiline":   false,
		"secret":      false,
		"note":        false,
		"oneTimeCode": false,
		"otp":         false,

		// Bare complex base types — unsupported (object-valued).
		"host":             true,
		"keyPair":          true,
		"name":             true,
		"address":          true,
		"phone":            true,
		"paymentCard":      true,
		"bankAccount":      true,
		"securityQuestion": true,
		"pamHostname":      true,
		"passkey":          true,
		"appFiller":        true,
		"pamResources":     true,
		"script":           true,

		// Flattened sub-field paths — unsupported.
		"host.port":          true,
		"host.hostName":      true,
		"keyPair.privateKey": true,
		"keyPair.publicKey":  true,
		"name.first":         true,
		"address.city":       true,
	}

	for fieldType, want := range cases {
		if got := isUnsupportedComplexFieldUpdate(fieldType); got != want {
			t.Errorf("isUnsupportedComplexFieldUpdate(%q) = %v, want %v", fieldType, got, want)
		}
	}
}
