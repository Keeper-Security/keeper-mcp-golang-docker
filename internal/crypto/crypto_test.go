package crypto

import (
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	password := "test-password-123"
	encryptor := NewEncryptor(password)

	tests := []struct {
		name      string
		plaintext string
	}{
		{"empty string", ""},
		{"simple text", "hello world"},
		{"json data", `{"key": "value", "number": 123}`},
		{"unicode text", "🔐 Security Test 🔒"},
		{"long text", strings.Repeat("a", 1000)},
		{"special chars", "!@#$%^&*()_+-=[]{}|;:,.<>?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := encryptor.Encrypt([]byte(tt.plaintext))
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Verify encrypted data structure
			if len(encrypted.Salt) != SaltSize {
				t.Errorf("Invalid salt size: expected %d, got %d", SaltSize, len(encrypted.Salt))
			}
			if len(encrypted.Nonce) != NonceSize {
				t.Errorf("Invalid nonce size: expected %d, got %d", NonceSize, len(encrypted.Nonce))
			}
			if len(encrypted.Ciphertext) == 0 {
				t.Error("Ciphertext is empty")
			}

			// Decrypt
			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Verify result
			if string(decrypted) != tt.plaintext {
				t.Errorf("Decrypted text doesn't match original: expected %q, got %q", tt.plaintext, string(decrypted))
			}
		})
	}
}

func TestEncryptDecryptString(t *testing.T) {
	password := "test-password-456"
	encryptor := NewEncryptor(password)

	plaintext := "This is a test string for encryption"

	// Encrypt
	encrypted, err := encryptor.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}

	// Verify it's base64 encoded
	if strings.Contains(encrypted, plaintext) {
		t.Error("Encrypted string contains original plaintext")
	}

	// Decrypt
	decrypted, err := encryptor.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}

	// Verify result
	if decrypted != plaintext {
		t.Errorf("Decrypted string doesn't match original: expected %q, got %q", plaintext, decrypted)
	}
}

func TestDifferentPasswords(t *testing.T) {
	plaintext := "secret data"

	encryptor1 := NewEncryptor("password1")
	encryptor2 := NewEncryptor("password2")

	// Encrypt with first password
	encrypted, err := encryptor1.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with second password (should fail)
	_, err = encryptor2.Decrypt(encrypted)
	if err == nil {
		t.Error("Expected decryption to fail with wrong password")
	}
}

func TestEncryptionDeterminism(t *testing.T) {
	password := "test-password-789"
	encryptor := NewEncryptor(password)
	plaintext := "test data for determinism"

	// Encrypt the same data twice
	encrypted1, err := encryptor.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := encryptor.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Results should be different (due to random salt and nonce)
	if string(encrypted1.Ciphertext) == string(encrypted2.Ciphertext) {
		t.Error("Encrypted data should be different for each encryption")
	}
	if string(encrypted1.Salt) == string(encrypted2.Salt) {
		t.Error("Salt should be different for each encryption")
	}
	if string(encrypted1.Nonce) == string(encrypted2.Nonce) {
		t.Error("Nonce should be different for each encryption")
	}

	// Both should decrypt to the same plaintext
	decrypted1, err := encryptor.Decrypt(encrypted1)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	decrypted2, err := encryptor.Decrypt(encrypted2)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	if string(decrypted1) != plaintext || string(decrypted2) != plaintext {
		t.Error("Both decryptions should result in original plaintext")
	}
}

func TestInvalidDecryption(t *testing.T) {
	password := "test-password"
	encryptor := NewEncryptor(password)

	tests := []struct {
		name string
		data *EncryptedData
	}{
		{
			"invalid salt size",
			&EncryptedData{
				Salt:       []byte("short"),
				Nonce:      make([]byte, NonceSize),
				Ciphertext: []byte("test"),
			},
		},
		{
			"invalid nonce size",
			&EncryptedData{
				Salt:       make([]byte, SaltSize),
				Nonce:      []byte("short"),
				Ciphertext: []byte("test"),
			},
		},
		{
			"empty ciphertext",
			&EncryptedData{
				Salt:       make([]byte, SaltSize),
				Nonce:      make([]byte, NonceSize),
				Ciphertext: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptor.Decrypt(tt.data)
			if err == nil {
				t.Error("Expected decryption to fail")
			}
		})
	}
}

func TestInvalidBase64Decoding(t *testing.T) {
	password := "test-password"
	encryptor := NewEncryptor(password)

	tests := []struct {
		name    string
		encoded string
	}{
		{"invalid base64", "not-base64!@#"},
		{"too short", "dGVzdA=="}, // "test" in base64, too short
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptor.DecryptString(tt.encoded)
			if err == nil {
				t.Error("Expected decryption to fail")
			}
		})
	}
}

func TestGeneratePassword(t *testing.T) {
	tests := []struct {
		name   string
		length int
		valid  bool
	}{
		{"valid short", 16, true},
		{"valid medium", 32, true},
		{"valid long", 64, true},
		{"too short", 8, false},
		{"zero length", 0, false},
		{"negative length", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := GeneratePassword(tt.length)

			if tt.valid {
				if err != nil {
					t.Errorf("Expected success, got error: %v", err)
				}
				if len(password) != tt.length {
					t.Errorf("Expected password length %d, got %d", tt.length, len(password))
				}
			} else {
				if err == nil {
					t.Error("Expected error for invalid length")
				}
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		valid    bool
	}{
		{"valid password", "secure-password-123", true},
		{"minimum length", "12characters", true},
		{"too short", "short", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)

			if tt.valid && err != nil {
				t.Errorf("Expected valid password, got error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Error("Expected invalid password to fail validation")
			}
		})
	}
}

func TestSecureZero(t *testing.T) {
	data := []byte("sensitive data")
	original := make([]byte, len(data))
	copy(original, data)

	SecureZero(data)

	// Verify all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d not zeroed: %d", i, b)
		}
	}

	// Verify original data was actually different
	allZero := true
	for _, b := range original {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Original data was already all zeros, test is invalid")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	password := "benchmark-password"
	encryptor := NewEncryptor(password)
	plaintext := []byte("benchmark data for encryption performance test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.Encrypt(plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	password := "benchmark-password"
	encryptor := NewEncryptor(password)
	plaintext := []byte("benchmark data for decryption performance test")

	encrypted, err := encryptor.Encrypt(plaintext)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.Decrypt(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}
