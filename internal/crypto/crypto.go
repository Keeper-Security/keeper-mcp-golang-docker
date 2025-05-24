package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// KeySize is the size of the encryption key in bytes (32 bytes = 256 bits)
	KeySize = 32
	// NonceSize is the size of the nonce for GCM mode (12 bytes is recommended)
	NonceSize = 12
	// SaltSize is the size of the salt for key derivation (32 bytes)
	SaltSize = 32
	// Iterations is the number of iterations for PBKDF2
	Iterations = 100000
)

// EncryptedData represents encrypted data with metadata
type EncryptedData struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Encryptor handles encryption and decryption operations
type Encryptor struct {
	password []byte
}

// NewEncryptor creates a new encryptor with the given password
func NewEncryptor(password string) *Encryptor {
	return &Encryptor{
		password: []byte(password),
	}
}

// Encrypt encrypts plaintext data using AES-256-GCM
func (e *Encryptor) Encrypt(plaintext []byte) (*EncryptedData, error) {
	// Generate random salt
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password using PBKDF2
	key := pbkdf2.Key(e.password, salt, Iterations, KeySize, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedData{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt decrypts encrypted data using AES-256-GCM
func (e *Encryptor) Decrypt(data *EncryptedData) ([]byte, error) {
	// Validate input
	if len(data.Salt) != SaltSize {
		return nil, fmt.Errorf("invalid salt size: expected %d, got %d", SaltSize, len(data.Salt))
	}
	if len(data.Nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce size: expected %d, got %d", NonceSize, len(data.Nonce))
	}
	if len(data.Ciphertext) == 0 {
		return nil, fmt.Errorf("empty ciphertext")
	}

	// Derive key from password using the same salt
	key := pbkdf2.Key(e.password, data.Salt, Iterations, KeySize, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the data
	plaintext, err := gcm.Open(nil, data.Nonce, data.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns base64-encoded result
func (e *Encryptor) EncryptString(plaintext string) (string, error) {
	data, err := e.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return e.encodeEncryptedData(data), nil
}

// DecryptString decrypts a base64-encoded string
func (e *Encryptor) DecryptString(encoded string) (string, error) {
	data, err := e.decodeEncryptedData(encoded)
	if err != nil {
		return "", err
	}

	plaintext, err := e.Decrypt(data)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// encodeEncryptedData encodes EncryptedData to a base64 string
func (e *Encryptor) encodeEncryptedData(data *EncryptedData) string {
	// Format: salt + nonce + ciphertext
	combined := make([]byte, 0, len(data.Salt)+len(data.Nonce)+len(data.Ciphertext))
	combined = append(combined, data.Salt...)
	combined = append(combined, data.Nonce...)
	combined = append(combined, data.Ciphertext...)
	
	return base64.StdEncoding.EncodeToString(combined)
}

// decodeEncryptedData decodes a base64 string to EncryptedData
func (e *Encryptor) decodeEncryptedData(encoded string) (*EncryptedData, error) {
	combined, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Minimum size check
	minSize := SaltSize + NonceSize
	if len(combined) < minSize {
		return nil, fmt.Errorf("invalid data size: expected at least %d bytes, got %d", minSize, len(combined))
	}

	// Extract components
	salt := combined[:SaltSize]
	nonce := combined[SaltSize : SaltSize+NonceSize]
	ciphertext := combined[SaltSize+NonceSize:]

	return &EncryptedData{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// GeneratePassword generates a random password for encryption
func GeneratePassword(length int) (string, error) {
	if length < 16 {
		return "", fmt.Errorf("password length must be at least 16 characters")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// ValidatePassword validates a password meets minimum requirements
func ValidatePassword(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters long")
	}
	return nil
}

// SecureZero securely zeros out sensitive byte slices
func SecureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}