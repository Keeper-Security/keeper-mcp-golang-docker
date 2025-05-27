package ksm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFieldTypesForRecordType(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name           string
		recordType     string
		expectedFields []string
	}{
		{
			name:           "login record",
			recordType:     "login",
			expectedFields: []string{"login", "password", "url", "oneTimeCode", "otp"},
		},
		{
			name:           "SSH keys record",
			recordType:     "sshKeys",
			expectedFields: []string{"login", "host", "keyPair", "passphrase", "password"},
		},
		{
			name:           "bank card record",
			recordType:     "bankCard",
			expectedFields: []string{"paymentCard", "text", "pinCode", "addressRef", "cardRef"},
		},
		{
			name:           "PAM user record",
			recordType:     "pamUser",
			expectedFields: []string{"login", "password", "host", "pamHostname", "pamResources", "pamSettings"},
		},
		{
			name:           "PAM machine record",
			recordType:     "pamMachine",
			expectedFields: []string{"pamHostname", "host", "login", "password", "pamResources", "pamSettings", "keyPair"},
		},
		{
			name:           "PAM database record",
			recordType:     "pamDatabase",
			expectedFields: []string{"host", "login", "password", "databaseType", "pamResources", "pamSettings"},
		},
		{
			name:           "PAM remote browser record",
			recordType:     "pamRemoteBrowser",
			expectedFields: []string{"url", "login", "password", "pamRemoteBrowserSettings", "rbiUrl"},
		},
		{
			name:           "database credentials record",
			recordType:     "databaseCredentials",
			expectedFields: []string{"host", "login", "password", "databaseType", "text"},
		},
		{
			name:           "server credentials record",
			recordType:     "serverCredentials",
			expectedFields: []string{"host", "login", "password", "text"},
		},
		{
			name:           "wireless record",
			recordType:     "wireless",
			expectedFields: []string{"text", "password", "wifiEncryption", "isSSIDHidden"},
		},
		{
			name:           "passkey record",
			recordType:     "passkey",
			expectedFields: []string{"passkey", "login", "url", "text"},
		},
		{
			name:           "script record",
			recordType:     "script",
			expectedFields: []string{"script", "text", "multiline", "fileRef"},
		},
		{
			name:       "unknown record type",
			recordType: "unknownType",
			expectedFields: []string{
				"login", "password", "url", "text", "multiline", "host", "name", "email", "phone", "address",
				"oneTimeCode", "otp", "keyPair", "paymentCard", "bankAccount", "accountNumber", "licenseNumber",
				"secret", "note", "date", "birthDate", "expirationDate", "pinCode", "fileRef", "addressRef",
				"cardRef", "pamHostname", "pamResources", "pamSettings", "pamRemoteBrowserSettings",
				"databaseType", "directoryType", "wifiEncryption", "isSSIDHidden", "passkey", "appFiller",
				"script", "rbiUrl", "dropdown", "checkbox", "recordRef", "schedule", "trafficEncryptionSeed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.getFieldTypesForRecordType(tt.recordType)
			assert.ElementsMatch(t, tt.expectedFields, result, "Field types should match for record type %s", tt.recordType)
		})
	}
}

func TestProcessPaymentCardField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "valid payment card - masked",
			value: []interface{}{
				map[string]interface{}{
					"cardNumber":         "4111111111111111",
					"cardExpirationDate": "12/25",
					"cardSecurityCode":   "123",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"cardNumber":         "411***111",
				"cardExpirationDate": "12/25",
				"cardSecurityCode":   "******",
			},
			found: true,
		},
		{
			name: "valid payment card - unmasked",
			value: []interface{}{
				map[string]interface{}{
					"cardNumber":         "4111111111111111",
					"cardExpirationDate": "12/25",
					"cardSecurityCode":   "123",
				},
			},
			unmask: true,
			expected: map[string]interface{}{
				"cardNumber":         "4111111111111111",
				"cardExpirationDate": "12/25",
				"cardSecurityCode":   "123",
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
		{
			name:     "invalid structure",
			value:    "invalid",
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processPaymentCardField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Payment card data should match")
			}
		})
	}
}

func TestProcessAddressField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "valid address",
			value: []interface{}{
				map[string]interface{}{
					"street1": "123 Main St",
					"street2": "Apt 4B",
					"city":    "New York",
					"state":   "NY",
					"country": "USA",
					"zip":     "10001",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"street1": "123 Main St",
				"street2": "Apt 4B",
				"city":    "New York",
				"state":   "NY",
				"country": "USA",
				"zip":     "10001",
			},
			found: true,
		},
		{
			name: "partial address",
			value: []interface{}{
				map[string]interface{}{
					"street1": "456 Oak Ave",
					"city":    "Los Angeles",
					"state":   "CA",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"street1": "456 Oak Ave",
				"city":    "Los Angeles",
				"state":   "CA",
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processAddressField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Address data should match")
			}
		})
	}
}

func TestProcessPhoneField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "valid phone number",
			value: []interface{}{
				map[string]interface{}{
					"region": "US",
					"number": "555-123-4567",
					"ext":    "123",
					"type":   "Mobile",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"region": "US",
				"number": "555-123-4567",
				"ext":    "123",
				"type":   "Mobile",
			},
			found: true,
		},
		{
			name: "minimal phone number",
			value: []interface{}{
				map[string]interface{}{
					"number": "555-987-6543",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"number": "555-987-6543",
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processPhoneField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Phone data should match")
			}
		})
	}
}

func TestProcessKeyPairField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "SSH key pair - masked",
			value: []interface{}{
				map[string]interface{}{
					"publicKey":  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...",
					"privateKey": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"publicKey":  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...",
				"privateKey": "---***...",
			},
			found: true,
		},
		{
			name: "SSH key pair - unmasked",
			value: []interface{}{
				map[string]interface{}{
					"publicKey":  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...",
					"privateKey": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
				},
			},
			unmask: true,
			expected: map[string]interface{}{
				"publicKey":  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...",
				"privateKey": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processKeyPairField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Key pair data should match")
			}
		})
	}
}

func TestProcessBankAccountField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "bank account - masked",
			value: []interface{}{
				map[string]interface{}{
					"accountType":   "Checking",
					"routingNumber": "123456789",
					"accountNumber": "987654321",
					"otherType":     "",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"accountType":   "Checking",
				"routingNumber": "123***789",
				"accountNumber": "987***321",
				"otherType":     "",
			},
			found: true,
		},
		{
			name: "bank account - unmasked",
			value: []interface{}{
				map[string]interface{}{
					"accountType":   "Savings",
					"routingNumber": "987654321",
					"accountNumber": "123456789",
				},
			},
			unmask: true,
			expected: map[string]interface{}{
				"accountType":   "Savings",
				"routingNumber": "987654321",
				"accountNumber": "123456789",
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processBankAccountField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Bank account data should match")
			}
		})
	}
}

func TestProcessHostField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "host with port",
			value: []interface{}{
				map[string]interface{}{
					"hostName": "server.example.com",
					"port":     "22",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"hostName": "server.example.com",
				"port":     "22",
			},
			found: true,
		},
		{
			name: "host without port",
			value: []interface{}{
				map[string]interface{}{
					"hostName": "database.internal",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"hostName": "database.internal",
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processHostField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Host data should match")
			}
		})
	}
}

func TestProcessNameField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "full name",
			value: []interface{}{
				map[string]interface{}{
					"first":  "John",
					"middle": "Q",
					"last":   "Doe",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"first":  "John",
				"middle": "Q",
				"last":   "Doe",
			},
			found: true,
		},
		{
			name: "partial name",
			value: []interface{}{
				map[string]interface{}{
					"first": "Jane",
					"last":  "Smith",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"first": "Jane",
				"last":  "Smith",
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processNameField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Name data should match")
			}
		})
	}
}

func TestProcessSecurityQuestionField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "security question - masked",
			value: []interface{}{
				map[string]interface{}{
					"question": "What is your mother's maiden name?",
					"answer":   "Johnson",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"question": "What is your mother's maiden name?",
				"answer":   "Joh***son",
			},
			found: true,
		},
		{
			name: "security question - unmasked",
			value: []interface{}{
				map[string]interface{}{
					"question": "What was your first pet's name?",
					"answer":   "Fluffy",
				},
			},
			unmask: true,
			expected: map[string]interface{}{
				"question": "What was your first pet's name?",
				"answer":   "Fluffy",
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processSecurityQuestionField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Security question data should match")
			}
		})
	}
}

func TestProcessPamHostnameField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "PAM hostname with port",
			value: []interface{}{
				map[string]interface{}{
					"hostName": "pam-server.corp.com",
					"port":     "443",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"hostName": "pam-server.corp.com",
				"port":     "443",
			},
			found: true,
		},
		{
			name: "PAM hostname without port",
			value: []interface{}{
				map[string]interface{}{
					"hostName": "pam.internal",
				},
			},
			unmask: false,
			expected: map[string]interface{}{
				"hostName": "pam.internal",
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processPamHostnameField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "PAM hostname data should match")
			}
		})
	}
}

func TestProcessPamResourcesField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "PAM resources",
			value: []interface{}{
				map[string]interface{}{
					"controllerUid": "ctrl-123",
					"folderUid":     "folder-456",
					"resourceRef":   []interface{}{"res-1", "res-2"},
					"allowedSettings": map[string]interface{}{
						"connections":         true,
						"portForwards":        false,
						"rotation":            true,
						"sessionRecording":    true,
						"typescriptRecording": false,
					},
				},
				map[string]interface{}{
					"controllerUid": "ctrl-789",
					"folderUid":     "folder-012",
				},
			},
			unmask: false,
			expected: []map[string]interface{}{
				{
					"controllerUid": "ctrl-123",
					"folderUid":     "folder-456",
					"resourceRef":   []interface{}{"res-1", "res-2"},
					"allowedSettings": map[string]interface{}{
						"connections":         true,
						"portForwards":        false,
						"rotation":            true,
						"sessionRecording":    true,
						"typescriptRecording": false,
					},
				},
				{
					"controllerUid": "ctrl-789",
					"folderUid":     "folder-012",
				},
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processPamResourcesField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "PAM resources data should match")
			}
		})
	}
}

func TestProcessPasskeyField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "passkey - masked",
			value: []interface{}{
				map[string]interface{}{
					"credentialId": "cred-123",
					"userId":       "user-456",
					"relyingParty": "example.com",
					"username":     "john.doe",
					"createdDate":  float64(1640995200),
					"signCount":    float64(5),
					"privateKey": map[string]interface{}{
						"crv": "P-256",
						"d":   "secret-key-data",
						"kty": "EC",
					},
				},
			},
			unmask: false,
			expected: []map[string]interface{}{
				{
					"credentialId": "cred-123",
					"userId":       "user-456",
					"relyingParty": "example.com",
					"username":     "john.doe",
					"createdDate":  float64(1640995200),
					"signCount":    float64(5),
					"privateKey":   "***MASKED***",
				},
			},
			found: true,
		},
		{
			name: "passkey - unmasked",
			value: []interface{}{
				map[string]interface{}{
					"credentialId": "cred-789",
					"userId":       "user-012",
					"relyingParty": "test.com",
					"username":     "jane.smith",
					"privateKey": map[string]interface{}{
						"crv": "P-256",
						"d":   "another-secret-key",
						"kty": "EC",
					},
				},
			},
			unmask: true,
			expected: []map[string]interface{}{
				{
					"credentialId": "cred-789",
					"userId":       "user-012",
					"relyingParty": "test.com",
					"username":     "jane.smith",
					"privateKey": map[string]interface{}{
						"crv": "P-256",
						"d":   "another-secret-key",
						"kty": "EC",
					},
				},
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processPasskeyField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Passkey data should match")
			}
		})
	}
}

func TestProcessScriptField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name: "script - masked",
			value: []interface{}{
				map[string]interface{}{
					"fileRef":   "file-123",
					"command":   "sudo systemctl restart nginx",
					"recordRef": []interface{}{"rec-1", "rec-2"},
				},
			},
			unmask: false,
			expected: []map[string]interface{}{
				{
					"fileRef":   "file-123",
					"command":   "sud***inx",
					"recordRef": []interface{}{"rec-1", "rec-2"},
				},
			},
			found: true,
		},
		{
			name: "script - unmasked",
			value: []interface{}{
				map[string]interface{}{
					"fileRef": "file-456",
					"command": "docker-compose up -d",
				},
			},
			unmask: true,
			expected: []map[string]interface{}{
				{
					"fileRef": "file-456",
					"command": "docker-compose up -d",
				},
			},
			found: true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processScriptField(tt.value, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Script data should match")
			}
		})
	}
}

func TestProcessBooleanField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		value    interface{}
		unmask   bool
		expected interface{}
		found    bool
	}{
		{
			name:     "boolean true",
			value:    []interface{}{true},
			unmask:   false,
			expected: true,
			found:    true,
		},
		{
			name:     "boolean false",
			value:    []interface{}{false},
			unmask:   false,
			expected: false,
			found:    true,
		},
		{
			name:     "empty value",
			value:    []interface{}{},
			unmask:   false,
			expected: nil,
			found:    false,
		},
		{
			name:     "non-boolean value",
			value:    []interface{}{"not a boolean"},
			unmask:   false,
			expected: nil,
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processBooleanField(tt.value, "checkbox", tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Boolean data should match")
			}
		})
	}
}

func TestProcessSimpleField(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name      string
		value     interface{}
		fieldType string
		unmask    bool
		expected  interface{}
		found     bool
	}{
		{
			name:      "string field",
			value:     []interface{}{"test value"},
			fieldType: "text",
			unmask:    false,
			expected:  "test value",
			found:     true,
		},
		{
			name:      "sensitive field - masked",
			value:     []interface{}{"secret123"},
			fieldType: "password",
			unmask:    false,
			expected:  "sec***123",
			found:     true,
		},
		{
			name:      "sensitive field - unmasked",
			value:     []interface{}{"secret123"},
			fieldType: "password",
			unmask:    true,
			expected:  "secret123",
			found:     true,
		},
		{
			name:      "number field",
			value:     []interface{}{float64(42)},
			fieldType: "text",
			unmask:    false,
			expected:  "42",
			found:     true,
		},
		{
			name:      "boolean field",
			value:     []interface{}{true},
			fieldType: "text",
			unmask:    false,
			expected:  "true",
			found:     true,
		},
		{
			name:      "empty value",
			value:     []interface{}{},
			fieldType: "text",
			unmask:    false,
			expected:  nil,
			found:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := client.processSimpleField(tt.value, tt.fieldType, tt.unmask)
			assert.Equal(t, tt.found, found, "Found status should match")
			if tt.found {
				assert.Equal(t, tt.expected, result, "Simple field data should match")
			}
		})
	}
}

func TestIsSensitiveFieldComprehensive(t *testing.T) {
	tests := []struct {
		name      string
		field     string
		sensitive bool
	}{
		// Sensitive fields
		{"password", "password", true},
		{"secret", "secret", true},
		{"key", "privateKey", true},
		{"token", "accessToken", true},
		{"card number", "cardNumber", true},
		{"security code", "cardSecurityCode", true},
		{"account number", "accountNumber", true},
		{"routing number", "routingNumber", true},
		{"pin code", "pinCode", true},
		{"passphrase", "passphrase", true},
		{"license number", "licenseNumber", true},
		{"one time code", "oneTimeCode", true},
		{"otp", "otp", true},
		{"answer", "securityAnswer", true},
		{"payment card", "paymentCard", true},
		{"bank account", "bankAccount", true},
		{"key pair", "keyPair", true},

		// Non-sensitive fields
		{"username", "username", false},
		{"email", "email", false},
		{"title", "title", false},
		{"url", "url", false},
		{"notes", "notes", false},
		{"name", "name", false},
		{"address", "address", false},
		{"phone", "phone", false},
		{"host", "host", false},
		{"text", "text", false},
		{"multiline", "multiline", false},
		{"date", "date", false},
		{"birth date", "birthDate", false},
		{"expiration date", "expirationDate", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSensitiveField(tt.field)
			assert.Equal(t, tt.sensitive, result, "Sensitivity check should match for field %s", tt.field)
		})
	}
}
