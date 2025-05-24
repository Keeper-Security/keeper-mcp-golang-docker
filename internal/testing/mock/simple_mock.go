package mock

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SimpleRecord represents a simplified KSM record for testing
type SimpleRecord struct {
	UID       string                 `json:"uid"`
	Title     string                 `json:"title"`
	Type      string                 `json:"type"`
	FolderUID string                 `json:"folder_uid,omitempty"`
	Fields    map[string]interface{} `json:"fields"`
	Custom    map[string]interface{} `json:"custom,omitempty"`
	Files     []SimpleFile           `json:"files,omitempty"`
	Notes     string                 `json:"notes,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// SimpleFile represents a file attachment
type SimpleFile struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	Data []byte `json:"data"`
}

// Folder represents a folder in the vault
type Folder struct {
	UID    string `json:"uid"`
	Name   string `json:"name"`
	Parent string `json:"parent"`
}

// CapturedCall records API calls for testing
type CapturedCall struct {
	Method    string        `json:"method"`
	Args      []interface{} `json:"args"`
	Response  interface{}   `json:"response"`
	Error     error         `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// SimpleMockServer provides a simple mock KSM server for testing
type SimpleMockServer struct {
	mu      sync.RWMutex
	records map[string]*SimpleRecord
	folders map[string]*Folder
}

// NewSimpleMockServer creates a new simple mock server with test data
func NewSimpleMockServer() *SimpleMockServer {
	server := &SimpleMockServer{
		records: make(map[string]*SimpleRecord),
		folders: make(map[string]*Folder),
	}
	server.loadTestData()
	return server
}

func (s *SimpleMockServer) loadTestData() {
	// Create folders
	s.folders["dev-folder"] = &Folder{UID: "dev-folder", Name: "Development", Parent: ""}
	s.folders["prod-folder"] = &Folder{UID: "prod-folder", Name: "Production", Parent: ""}
	s.folders["test-folder"] = &Folder{UID: "test-folder", Name: "Testing", Parent: ""}

	// Development folder records
	s.records["dev-db-conn"] = &SimpleRecord{
		UID:       "dev-db-conn",
		Title:     "Database Connection",
		Type:      "databaseCredentials",
		FolderUID: "dev-folder",
		Fields: map[string]interface{}{
			"host":     "dev-db.example.com",
			"port":     "5432",
			"login":    "dev_user",
			"password": "DevPass123!",
		},
		Custom: map[string]interface{}{
			"Database":    "development_db",
			"Environment": "development",
			"SSL Mode":    "require",
		},
		CreatedAt: time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-2 * 24 * time.Hour),
	}

	s.records["dev-ssh-key"] = &SimpleRecord{
		UID:       "dev-ssh-key",
		Title:     "SSH Key",
		Type:      "sshKeys",
		FolderUID: "dev-folder",
		Fields: map[string]interface{}{
			"login":      "dev-admin",
			"host":       "dev-server.example.com",
			"privateKey": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...(mock key)...",
			"passphrase": "DevKeyPass123!",
		},
		Files: []SimpleFile{
			{
				Name: "id_rsa.pub",
				Type: "text/plain",
				Size: 381,
				Data: []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...(mock public key)... dev@example.com"),
			},
		},
		CreatedAt: time.Now().Add(-20 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-5 * 24 * time.Hour),
	}

	// Production folder records
	s.records["prod-api-creds"] = &SimpleRecord{
		UID:       "prod-api-creds",
		Title:     "Test API Credentials",
		Type:      "login",
		FolderUID: "prod-folder",
		Fields: map[string]interface{}{
			"login":    "prod-api-key-123456",
			"password": "ProdSecret789!",
			"url":      "https://api.example.com/v2",
		},
		Custom: map[string]interface{}{
			"Rate Limit": "1000 req/hour",
			"Version":    "v2.1.3",
		},
		Notes:     "Production API credentials\nDo not share\nRotate monthly",
		CreatedAt: time.Now().Add(-45 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-1 * 24 * time.Hour),
	}

	s.records["prod-card"] = &SimpleRecord{
		UID:       "prod-card",
		Title:     "Test Corporate Card",
		Type:      "bankCard",
		FolderUID: "prod-folder",
		Fields: map[string]interface{}{
			"cardNumber":         "4111111111111111",
			"cardExpirationDate": "12/2025",
			"cardSecurityCode":   "123",
			"text":               "Test User",
			"pinCode":            "1234",
		},
		Custom: map[string]interface{}{
			"Bank":         "Test Bank Corp",
			"Card Type":    "Corporate",
			"Credit Limit": "10000",
		},
		CreatedAt: time.Now().Add(-60 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-10 * 24 * time.Hour),
	}

	// Testing folder records
	s.records["test-db-login"] = &SimpleRecord{
		UID:       "test-db-login",
		Title:     "Test Database Login",
		Type:      "databaseCredentials",
		FolderUID: "test-folder",
		Fields: map[string]interface{}{
			"host":     "test-db.local",
			"port":     "3306",
			"login":    "test_user",
			"password": "TestPass456!",
		},
		Custom: map[string]interface{}{
			"Database": "test_database",
		},
		CreatedAt: time.Now().Add(-15 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-3 * 24 * time.Hour),
	}

	s.records["test-config-files"] = &SimpleRecord{
		UID:       "test-config-files",
		Title:     "Configuration Files",
		Type:      "file",
		FolderUID: "test-folder",
		Fields: map[string]interface{}{
			"text": "Test environment configuration files",
		},
		Files: []SimpleFile{
			{
				Name: "app.config",
				Type: "text/plain",
				Size: 2048,
				Data: []byte("# Test Application Configuration\napp.name=TestApp\napp.version=1.0.0\napp.env=test\n\n# Database Settings\ndb.host=test-db.local\ndb.port=3306\ndb.name=test_database\n\n# API Settings\napi.timeout=30\napi.retries=3"),
			},
			{
				Name: "test.env",
				Type: "text/plain",
				Size: 512,
				Data: []byte("NODE_ENV=test\nAPI_URL=http://localhost:3000\nDEBUG=true\nLOG_LEVEL=debug\nCACHE_TTL=300"),
			},
			{
				Name: "docker-compose.test.yml",
				Type: "text/yaml",
				Size: 1536,
				Data: []byte("version: '3.8'\n\nservices:\n  app:\n    image: testapp:latest\n    environment:\n      - NODE_ENV=test\n    ports:\n      - '3000:3000'\n    depends_on:\n      - db\n      - redis\n\n  db:\n    image: mysql:8.0\n    environment:\n      MYSQL_ROOT_PASSWORD: testroot\n      MYSQL_DATABASE: test_database\n    ports:\n      - '3306:3306'\n\n  redis:\n    image: redis:alpine\n    ports:\n      - '6379:6379'"),
			},
		},
		CreatedAt: time.Now().Add(-25 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-7 * 24 * time.Hour),
	}

	// Add remaining records to reach 12 total
	s.records["dev-server-login"] = &SimpleRecord{
		UID:       "dev-server-login",
		Title:     "Development Server Login",
		Type:      "login",
		FolderUID: "dev-folder",
		Fields: map[string]interface{}{
			"login":    "dev_admin",
			"password": "DevAdmin123!",
			"url":      "https://dev.example.com",
		},
		CreatedAt: time.Now().Add(-18 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-4 * 24 * time.Hour),
	}

	s.records["prod-aws-creds"] = &SimpleRecord{
		UID:       "prod-aws-creds",
		Title:     "AWS Production Credentials",
		Type:      "login",
		FolderUID: "prod-folder",
		Fields: map[string]interface{}{
			"login":    "AKIAIOSFODNN7EXAMPLE",
			"password": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		Custom: map[string]interface{}{
			"Region":     "us-east-1",
			"Account ID": "123456789012",
		},
		CreatedAt: time.Now().Add(-50 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-12 * 24 * time.Hour),
	}

	s.records["test-smtp-config"] = &SimpleRecord{
		UID:       "test-smtp-config",
		Title:     "Test SMTP Configuration",
		Type:      "serverCredentials",
		FolderUID: "test-folder",
		Fields: map[string]interface{}{
			"host":     "smtp.test.local",
			"port":     "587",
			"login":    "test@example.com",
			"password": "SmtpTest123!",
		},
		CreatedAt: time.Now().Add(-22 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-8 * 24 * time.Hour),
	}

	s.records["dev-gitlab-token"] = &SimpleRecord{
		UID:       "dev-gitlab-token",
		Title:     "GitLab Access Token",
		Type:      "login",
		FolderUID: "dev-folder",
		Fields: map[string]interface{}{
			"login":    "dev-ci-token",
			"password": "glpat-xxxxxxxxxxxxxxxxxxxx",
			"url":      "https://gitlab.example.com",
		},
		Custom: map[string]interface{}{
			"Scopes":  "api, read_repository, write_repository",
			"Expires": "2024-12-31",
		},
		CreatedAt: time.Now().Add(-35 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-6 * 24 * time.Hour),
	}

	s.records["prod-ssl-cert"] = &SimpleRecord{
		UID:       "prod-ssl-cert",
		Title:     "Production SSL Certificate",
		Type:      "sslCertificate",
		FolderUID: "prod-folder",
		Fields: map[string]interface{}{
			"text":       "*.example.com",
			"multiline":  "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKl...(mock cert)...",
			"privateKey": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B...(mock key)...",
		},
		Custom: map[string]interface{}{
			"Valid From":  "2024-01-01",
			"Valid Until": "2025-01-01",
			"Issuer":      "Test CA",
		},
		CreatedAt: time.Now().Add(-90 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-15 * 24 * time.Hour),
	}
}

// GetRecords returns all records or filtered by UIDs
func (s *SimpleMockServer) GetRecords(uids []string) ([]*SimpleRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*SimpleRecord

	if len(uids) == 0 {
		// Return all records
		for _, record := range s.records {
			result = append(result, record)
		}
	} else {
		// Return filtered records
		for _, uid := range uids {
			if record, exists := s.records[uid]; exists {
				result = append(result, record)
			}
		}
	}

	return result, nil
}

// GetRecordByTitle finds a record by title
func (s *SimpleMockServer) GetRecordByTitle(title string) (*SimpleRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, record := range s.records {
		if record.Title == title {
			return record, nil
		}
	}

	return nil, fmt.Errorf("record with title '%s' not found", title)
}

// SaveRecord saves or updates a record
func (s *SimpleMockServer) SaveRecord(record *SimpleRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if record.UID == "" {
		record.UID = fmt.Sprintf("new-record-%d", time.Now().UnixNano())
		record.CreatedAt = time.Now()
	}
	record.UpdatedAt = time.Now()

	s.records[record.UID] = record
	return nil
}

// DeleteRecords deletes records by UIDs
func (s *SimpleMockServer) DeleteRecords(uids []string) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make(map[string]string)
	for _, uid := range uids {
		if _, exists := s.records[uid]; exists {
			delete(s.records, uid)
			results[uid] = "success"
		} else {
			results[uid] = "not found"
		}
	}

	return results, nil
}

// AddFile adds a file to a record
func (s *SimpleMockServer) AddFile(recordUID string, file SimpleFile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.records[recordUID]
	if !exists {
		return fmt.Errorf("record '%s' not found", recordUID)
	}

	record.Files = append(record.Files, file)
	record.UpdatedAt = time.Now()
	return nil
}

// RemoveFile removes a file from a record
func (s *SimpleMockServer) RemoveFile(recordUID, fileName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.records[recordUID]
	if !exists {
		return fmt.Errorf("record '%s' not found", recordUID)
	}

	var newFiles []SimpleFile
	found := false
	for _, file := range record.Files {
		if file.Name != fileName {
			newFiles = append(newFiles, file)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("file '%s' not found", fileName)
	}

	record.Files = newFiles
	record.UpdatedAt = time.Now()
	return nil
}

// SearchRecords searches for records by term
func (s *SimpleMockServer) SearchRecords(searchTerm string) ([]*SimpleRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*SimpleRecord

	for _, record := range s.records {
		// Search in title
		if containsIgnoreCase(record.Title, searchTerm) {
			results = append(results, record)
			continue
		}

		// Search in notes
		if containsIgnoreCase(record.Notes, searchTerm) {
			results = append(results, record)
			continue
		}

		// Search in field values
		if searchInMap(record.Fields, searchTerm) || searchInMap(record.Custom, searchTerm) {
			results = append(results, record)
		}
	}

	return results, nil
}

// ExportData exports all data as JSON
func (s *SimpleMockServer) ExportData() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data := struct {
		Records map[string]*SimpleRecord `json:"records"`
		Folders map[string]*Folder       `json:"folders"`
	}{
		Records: s.records,
		Folders: s.folders,
	}

	return json.MarshalIndent(data, "", "  ")
}

// Helper functions
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func searchInMap(m map[string]interface{}, searchTerm string) bool {
	for _, v := range m {
		if str, ok := v.(string); ok && containsIgnoreCase(str, searchTerm) {
			return true
		}
	}
	return false
}
