package e2e

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestFileOperations(t *testing.T) {
	h := NewTestHarness(t)
	
	// Create test files
	testDir := t.TempDir()
	
	// Create a 2MB test file as requested
	largeFile := filepath.Join(testDir, "large_config.json")
	largeData := generateLargeFile(2 * 1024 * 1024) // 2MB
	err := ioutil.WriteFile(largeFile, largeData, 0644)
	require.NoError(t, err)
	
	// Create a medium file
	mediumFile := filepath.Join(testDir, "medium_data.csv")
	mediumData := generateCSVFile(500 * 1024) // 500KB
	err = ioutil.WriteFile(mediumFile, mediumData, 0644)
	require.NoError(t, err)
	
	// Create a small text file
	smallFile := filepath.Join(testDir, "config.yaml")
	smallData := []byte(`# Test Configuration
application:
  name: TestApp
  version: 1.0.0
  environment: test

database:
  host: localhost
  port: 5432
  name: testdb
  ssl: true

features:
  - authentication
  - logging
  - monitoring
`)
	err = ioutil.WriteFile(smallFile, smallData, 0644)
	require.NoError(t, err)
	
	t.Run("UploadLargeFile", func(t *testing.T) {
		// Mock the file read for upload
		h.mockClient.GetServer().CreateSecret("test-large-upload", "Large File Test", "file", map[string]interface{}{})
		
		// Upload file
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "upload_file",
			"arguments": map[string]interface{}{
				"uid":       "test-large-upload",
				"file_path": largeFile,
				"file_type": "application/json",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "File uploaded successfully")
		assert.Contains(t, result, "2097152 bytes") // 2MB
		
		// Verify file was added to record
		records, _ := h.mockClient.GetSecrets([]string{"test-large-upload"})
		require.Len(t, records, 1)
		assert.Len(t, records[0].Files, 1)
		assert.Equal(t, "large_config.json", records[0].Files[0].Name)
		assert.Equal(t, int64(2*1024*1024), records[0].Files[0].Size)
	})
	
	t.Run("UploadMultipleFiles", func(t *testing.T) {
		// Create a record for multiple files
		h.mockClient.GetServer().CreateSecret("test-multi-upload", "Multiple Files Test", "file", map[string]interface{}{})
		
		// Upload first file
		response1, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "upload_file",
			"arguments": map[string]interface{}{
				"uid":       "test-multi-upload",
				"file_path": mediumFile,
				"file_type": "text/csv",
			},
		})
		require.NoError(t, err)
		assert.Contains(t, extractToolResult(t, response1), "uploaded successfully")
		
		// Upload second file
		response2, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "upload_file",
			"arguments": map[string]interface{}{
				"uid":       "test-multi-upload",
				"file_path": smallFile,
				"file_type": "text/yaml",
			},
		})
		require.NoError(t, err)
		assert.Contains(t, extractToolResult(t, response2), "uploaded successfully")
		
		// List files
		listResponse, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "list_files",
			"arguments": map[string]interface{}{
				"uid": "test-multi-upload",
			},
		})
		require.NoError(t, err)
		
		listResult := extractToolResult(t, listResponse)
		assert.Contains(t, listResult, "2 files")
		assert.Contains(t, listResult, "medium_data.csv")
		assert.Contains(t, listResult, "config.yaml")
	})
	
	t.Run("DownloadFile", func(t *testing.T) {
		// Download from existing record with files
		downloadPath := filepath.Join(testDir, "downloaded_config.txt")
		
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "download_file",
			"arguments": map[string]interface{}{
				"uid":         "test-config-files",
				"file_name":   "app.config",
				"output_path": downloadPath,
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "File downloaded successfully")
		assert.Contains(t, result, "2048 bytes")
		
		// In real test, file would be written to disk
		// For mock, we just verify the response
	})
	
	t.Run("DeleteFile", func(t *testing.T) {
		// Create record with file to delete
		record := &ksm.Record{
			Uid:   "test-file-delete",
			Title: "File Delete Test",
			Type:  "file",
			Files: []*ksm.KeeperFile{
				{
					Name: "temp.txt",
					Type: "text/plain",
					Size: 100,
					Data: []byte("temporary file content"),
				},
				{
					Name: "keep.txt",
					Type: "text/plain",
					Size: 50,
					Data: []byte("keep this file"),
				},
			},
		}
		h.mockClient.GetServer().Save(record)
		
		// Delete specific file
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "delete_file",
			"arguments": map[string]interface{}{
				"uid":       "test-file-delete",
				"file_name": "temp.txt",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "File deleted successfully")
		
		// Verify file was removed
		records, _ := h.mockClient.GetSecrets([]string{"test-file-delete"})
		require.Len(t, records, 1)
		assert.Len(t, records[0].Files, 1)
		assert.Equal(t, "keep.txt", records[0].Files[0].Name)
	})
	
	t.Run("FileTypeValidation", func(t *testing.T) {
		// Test various file types
		fileTypes := map[string]string{
			"document.pdf":     "application/pdf",
			"image.png":        "image/png",
			"script.sh":        "text/x-shellscript",
			"data.xlsx":        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			"archive.zip":      "application/zip",
			"video.mp4":        "video/mp4",
			"certificate.pem":  "application/x-pem-file",
			"key.p12":          "application/x-pkcs12",
		}
		
		for fileName, fileType := range fileTypes {
			// Create test file
			testFile := filepath.Join(testDir, fileName)
			err := ioutil.WriteFile(testFile, []byte("test content"), 0644)
			require.NoError(t, err)
			
			// Try to upload
			h.mockClient.GetServer().CreateSecret("test-type-"+fileName, "Type Test: "+fileName, "file", map[string]interface{}{})
			
			response, err := h.SendRequest("tools/call", map[string]interface{}{
				"name": "upload_file",
				"arguments": map[string]interface{}{
					"uid":       "test-type-" + fileName,
					"file_path": testFile,
					"file_type": fileType,
				},
			})
			require.NoError(t, err)
			
			result := extractToolResult(t, response)
			assert.Contains(t, result, "uploaded successfully", "Failed for file type: %s", fileType)
		}
	})
}

func generateLargeFile(size int) []byte {
	// Generate a large JSON file with repeated structure
	data := []byte(`{
  "configurations": [`)
	
	entrySize := 1024 // Each entry is approximately 1KB
	numEntries := size / entrySize
	
	for i := 0; i < numEntries; i++ {
		if i > 0 {
			data = append(data, ',')
		}
		entry := fmt.Sprintf(`
    {
      "id": %d,
      "name": "Configuration Entry %d",
      "description": "This is a test configuration entry designed to fill space and create a large file for testing purposes. The content is repetitive but serves to test file upload and download capabilities with files of several megabytes in size.",
      "settings": {
        "enabled": %v,
        "threshold": %.2f,
        "timeout": %d,
        "retries": %d,
        "mode": "%s",
        "tags": ["test", "large", "file", "config", "entry%d"],
        "metadata": {
          "created": "2024-01-01T00:00:00Z",
          "modified": "2024-01-23T12:00:00Z",
          "version": "1.0.%d",
          "author": "test_generator",
          "checksum": "%x"
        }
      }
    }`, i, i, i%2 == 0, float64(i)/100, 30000+i, i%5, 
			[]string{"development", "testing", "staging", "production", "demo"}[i%5],
			i, i, i*31337)
		data = append(data, []byte(entry)...)
	}
	
	data = append(data, []byte(`
  ]
}`)...)
	
	// Trim to exact size
	if len(data) > size {
		data = data[:size]
	}
	
	return data
}

func generateCSVFile(size int) []byte {
	// Generate a CSV file with sample data
	data := []byte("id,timestamp,user,action,status,duration_ms,ip_address,user_agent,details\n")
	
	rowSize := 150 // Approximate size of each row
	numRows := size / rowSize
	
	actions := []string{"login", "logout", "create", "update", "delete", "read", "search", "export", "import"}
	statuses := []string{"success", "failure", "pending", "error", "timeout"}
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
	}
	
	for i := 0; i < numRows; i++ {
		row := fmt.Sprintf("%d,2024-01-23T%02d:%02d:%02d.%03dZ,user_%d,%s,%s,%d,192.168.1.%d,%s,\"Test action %d\"\n",
			i,
			i%24, i%60, i%60, i%1000,
			i%100,
			actions[i%len(actions)],
			statuses[i%len(statuses)],
			100 + (i%900),
			i%255,
			userAgents[i%len(userAgents)],
			i,
		)
		data = append(data, []byte(row)...)
	}
	
	// Trim to exact size
	if len(data) > size {
		data = data[:size]
	}
	
	return data
}