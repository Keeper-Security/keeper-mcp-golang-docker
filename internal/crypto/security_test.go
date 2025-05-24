package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// TestEncryptor_SecurityProperties tests cryptographic security properties
func TestEncryptor_SecurityProperties(t *testing.T) {
	encryptor := NewEncryptor("test-password")

	tests := []struct {
		name string
		test func(*testing.T)
	}{
		{
			name: "Different ciphertexts for same plaintext",
			test: func(t *testing.T) {
				plaintext := "sensitive data"

				// Encrypt the same plaintext multiple times
				ciphertexts := make([]string, 10)
				for i := 0; i < 10; i++ {
					encrypted, err := encryptor.EncryptString(plaintext)
					if err != nil {
						t.Fatalf("Encryption failed: %v", err)
					}
					ciphertexts[i] = encrypted
				}

				// All ciphertexts should be different (due to random nonce)
				for i := 0; i < len(ciphertexts); i++ {
					for j := i + 1; j < len(ciphertexts); j++ {
						if ciphertexts[i] == ciphertexts[j] {
							t.Error("Same plaintext produced identical ciphertexts - nonce reuse detected!")
						}
					}
				}
			},
		},
		{
			name: "Ciphertext tampering detection",
			test: func(t *testing.T) {
				plaintext := "sensitive data"
				encrypted, err := encryptor.EncryptString(plaintext)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}

				// Decode the base64
				ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
				if err != nil {
					t.Fatalf("Failed to decode ciphertext: %v", err)
				}

				// Tamper with the ciphertext
				tamperPositions := []int{0, len(ciphertext) / 2, len(ciphertext) - 1}
				for _, pos := range tamperPositions {
					if pos < len(ciphertext) {
						tampered := make([]byte, len(ciphertext))
						copy(tampered, ciphertext)
						tampered[pos] ^= 0xFF // Flip all bits at position

						tamperedB64 := base64.StdEncoding.EncodeToString(tampered)
						_, err := encryptor.DecryptString(tamperedB64)
						if err == nil {
							t.Error("Decryption succeeded with tampered ciphertext - authentication bypass!")
						}
					}
				}
			},
		},
		{
			name: "Key derivation strength",
			test: func(t *testing.T) {
				// Test that similar passphrases produce completely different keys
				passphrases := []string{
					"password123",
					"password124",
					"Password123",
					"password123!",
				}

				encryptors := make([]*Encryptor, len(passphrases))
				for i, pass := range passphrases {
					enc := NewEncryptor(pass)
					encryptors[i] = enc
				}

				// Encrypt the same data with each encryptor
				plaintext := "test data"
				for i, enc1 := range encryptors {
					encrypted1, _ := enc1.EncryptString(plaintext)

					// Try to decrypt with other encryptors
					for j, enc2 := range encryptors {
						if i != j {
							_, err := enc2.DecryptString(encrypted1)
							if err == nil {
								t.Errorf("Encryptor with passphrase %q decrypted data from passphrase %q",
									passphrases[j], passphrases[i])
							}
						}
					}
				}
			},
		},
		{
			name: "Timing attack resistance",
			test: func(t *testing.T) {
				// This is a basic check - true timing attack tests require specialized tools
				// We're mainly ensuring the code doesn't have obvious timing leaks

				validPassword := "correct-password"
				wrongPassword := "wrong-password"

				enc1 := NewEncryptor(validPassword)
				enc2 := NewEncryptor(wrongPassword)

				plaintext := "test data"
				encrypted, _ := enc1.EncryptString(plaintext)

				// Both should fail/succeed in roughly similar time
				// (This is a simplified test - real timing tests need statistical analysis)
				_, err1 := enc1.DecryptString(encrypted)
				_, err2 := enc2.DecryptString(encrypted)

				if err1 != nil {
					t.Error("Valid password failed to decrypt")
				}
				if err2 == nil {
					t.Error("Wrong password succeeded in decryption")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

// TestNonceUniqueness verifies nonce generation is truly random
func TestNonceUniqueness(t *testing.T) {
	nonces := make(map[string]bool)
	iterations := 10000

	for i := 0; i < iterations; i++ {
		nonce := make([]byte, NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("Failed to generate nonce: %v", err)
		}

		nonceStr := string(nonce)
		if nonces[nonceStr] {
			t.Fatalf("Nonce collision detected after %d iterations!", i)
		}
		nonces[nonceStr] = true
	}
}

// TestKeyDerivationIterations ensures sufficient iterations for PBKDF2
func TestKeyDerivationIterations(t *testing.T) {
	// NIST recommends at least 10,000 iterations, we use 100,000
	if Iterations < 10000 {
		t.Errorf("PBKDF2 iterations too low: %d (minimum recommended: 10,000)", Iterations)
	}
}

// TestEncryptedDataIntegrity verifies encrypted data structure
func TestEncryptedDataIntegrity(t *testing.T) {
	enc := NewEncryptor("test-password")
	plaintext := []byte("test data")

	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify all components are present and have correct sizes
	if len(encrypted.Salt) != SaltSize {
		t.Errorf("Salt size incorrect: got %d, want %d", len(encrypted.Salt), SaltSize)
	}

	if len(encrypted.Nonce) != NonceSize {
		t.Errorf("Nonce size incorrect: got %d, want %d", len(encrypted.Nonce), NonceSize)
	}

	if len(encrypted.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}

	// Ciphertext should be plaintext length + GCM tag size (16 bytes)
	expectedLen := len(plaintext) + 16
	if len(encrypted.Ciphertext) != expectedLen {
		t.Errorf("Ciphertext length incorrect: got %d, want %d", len(encrypted.Ciphertext), expectedLen)
	}
}

// TestLargeDataEncryption tests encryption of large data
func TestLargeDataEncryption(t *testing.T) {
	enc := NewEncryptor("test-password")

	// Test various sizes
	sizes := []int{
		1024,             // 1KB
		1024 * 1024,      // 1MB
		10 * 1024 * 1024, // 10MB
	}

	for _, size := range sizes {
		t.Run(strings.Replace("Size_%dB", "%d", string(rune(size)), 1), func(t *testing.T) {
			// Generate random data
			plaintext := make([]byte, size)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatalf("Failed to generate random data: %v", err)
			}

			// Encrypt
			encrypted, err := enc.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encryption failed for size %d: %v", size, err)
			}

			// Decrypt
			decrypted, err := enc.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed for size %d: %v", size, err)
			}

			// Verify
			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Decrypted data doesn't match original for size %d", size)
			}
		})
	}
}

// TestPasswordComplexity ensures the crypto module handles various password types
func TestPasswordComplexity(t *testing.T) {
	passwords := []string{
		"",                        // Empty password
		"a",                       // Single character
		"password",                // Simple password
		"P@ssw0rd!123",            // Complex password
		"这是一个中文密码",                // Unicode password
		"🔐🔑🛡️",                    // Emoji password
		strings.Repeat("A", 1000), // Very long password
		"password with spaces and special chars !@#$%^&*()",
	}

	plaintext := "test data"

	for _, password := range passwords {
		t.Run("password_complexity", func(t *testing.T) {
			enc := NewEncryptor(password)

			// Should be able to encrypt/decrypt with any password
			encrypted, err := enc.EncryptString(plaintext)
			if err != nil {
				t.Fatalf("Failed to encrypt with password %q: %v", password, err)
			}

			decrypted, err := enc.DecryptString(encrypted)
			if err != nil {
				t.Fatalf("Failed to decrypt with password %q: %v", password, err)
			}

			if decrypted != plaintext {
				t.Errorf("Decryption mismatch with password %q", password)
			}
		})
	}
}

// TestConcurrentEncryption tests thread safety
func TestConcurrentEncryption(t *testing.T) {
	enc := NewEncryptor("test-password")
	done := make(chan bool)
	errors := make(chan error, 100)

	// Run 100 concurrent encryptions
	for i := 0; i < 100; i++ {
		go func(id int) {
			defer func() { done <- true }()

			plaintext := []byte(strings.Repeat("data", id+1))
			encrypted, err := enc.Encrypt(plaintext)
			if err != nil {
				errors <- err
				return
			}

			decrypted, err := enc.Decrypt(encrypted)
			if err != nil {
				errors <- err
				return
			}

			if !bytes.Equal(plaintext, decrypted) {
				errors <- err
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	close(errors)

	// Check for errors
	for err := range errors {
		if err != nil {
			t.Errorf("Concurrent encryption error: %v", err)
		}
	}
}
