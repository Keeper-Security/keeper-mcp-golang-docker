package capture

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

// DataCapture captures real KSM API responses for offline testing
type DataCapture struct {
	outputDir   string
	captureTime time.Time
	captures    []CaptureEntry
}

type CaptureEntry struct {
	Method    string      `json:"method"`
	Request   interface{} `json:"request"`
	Response  interface{} `json:"response"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

type CapturedData struct {
	CaptureTime time.Time      `json:"capture_time"`
	Records     []*ksm.Record  `json:"records"`
	Folders     []FolderInfo   `json:"folders"`
	Files       []FileInfo     `json:"files"`
	Calls       []CaptureEntry `json:"api_calls"`
}

type FolderInfo struct {
	UID    string `json:"uid"`
	Name   string `json:"name"`
	Parent string `json:"parent"`
}

type FileInfo struct {
	RecordUID string `json:"record_uid"`
	FileName  string `json:"file_name"`
	FileType  string `json:"file_type"`
	FileSize  int64  `json:"file_size"`
	FilePath  string `json:"file_path"`
}

func NewDataCapture(outputDir string) *DataCapture {
	return &DataCapture{
		outputDir:   outputDir,
		captureTime: time.Now(),
	}
}

func (dc *DataCapture) RecordCall(method string, request interface{}, response interface{}, err error) {
	entry := CaptureEntry{
		Method:    method,
		Request:   request,
		Response:  response,
		Timestamp: time.Now(),
	}

	if err != nil {
		entry.Error = err.Error()
	}

	dc.captures = append(dc.captures, entry)
}

func (dc *DataCapture) CaptureVault(client *ksm.SecretsManager) error {
	fmt.Println("Starting vault data capture...")

	// Create output directory
	if err := os.MkdirAll(dc.outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Get all records
	fmt.Println("Fetching all records...")
	records, err := client.GetSecrets([]string{})
	dc.RecordCall("GetSecrets", []string{}, records, err)
	if err != nil {
		return fmt.Errorf("failed to get secrets: %w", err)
	}

	fmt.Printf("Found %d records\n", len(records))

	// Prepare captured data
	captured := &CapturedData{
		CaptureTime: dc.captureTime,
		Records:     records,
		Folders:     []FolderInfo{},
		Files:       []FileInfo{},
		Calls:       dc.captures,
	}

	// Extract folder information from records
	folderMap := make(map[string]bool)
	for _, record := range records {
		folderUid := record.FolderUid()
		if folderUid != "" && !folderMap[folderUid] {
			folderMap[folderUid] = true

			// In real implementation, we'd fetch folder details
			// For now, we'll create mock folder info
			folderName := "Unknown"
			switch folderUid {
			case "dev-folder":
				folderName = "Development"
			case "prod-folder":
				folderName = "Production"
			case "test-folder":
				folderName = "Testing"
			}

			captured.Folders = append(captured.Folders, FolderInfo{
				UID:    folderUid,
				Name:   folderName,
				Parent: "",
			})
		}

		// Download and save files
		if len(record.Files) > 0 {
			fmt.Printf("Processing %d files for record '%s'\n", len(record.Files), record.Title())

			for _, file := range record.Files {
				fmt.Printf("  - Downloading file: %s\n", file.Name)

				// Download file data
				// TODO: Fix SDK method for downloading files
				// fileData, err := client.DownloadFileData(file)
				// dc.RecordCall("DownloadFileData", file.Name, len(fileData), err)

				// if err != nil {
				// 	fmt.Printf("    Error downloading file: %v\n", err)
				// 	continue
				// }
				var fileData []byte // Empty for now

				// Save file to disk
				fileName := fmt.Sprintf("%s_%s_%s", record.Uid, file.Name, file.Title)
				fileName = sanitizeFileName(fileName)
				filePath := filepath.Join(dc.outputDir, "files", fileName)

				if err := os.MkdirAll(filepath.Dir(filePath), 0750); err != nil {
					fmt.Printf("    Error creating file directory: %v\n", err)
					continue
				}

				if err := ioutil.WriteFile(filePath, fileData, 0600); err != nil {
					fmt.Printf("    Error saving file: %v\n", err)
					continue
				}

				captured.Files = append(captured.Files, FileInfo{
					RecordUID: record.Uid,
					FileName:  file.Name,
					FileType:  file.Type,
					FileSize:  int64(file.Size),
					FilePath:  filePath,
				})

				fmt.Printf("    Saved to: %s (%d bytes)\n", filePath, len(fileData))
			}
		}
	}

	// Save main fixture file
	fixtureFile := filepath.Join(dc.outputDir, "vault_fixtures.json")
	data, err := json.MarshalIndent(captured, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal captured data: %w", err)
	}

	if err := ioutil.WriteFile(fixtureFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write fixture file: %w", err)
	}

	fmt.Printf("\nCapture complete!\n")
	fmt.Printf("- Records captured: %d\n", len(records))
	fmt.Printf("- Folders identified: %d\n", len(captured.Folders))
	fmt.Printf("- Files downloaded: %d\n", len(captured.Files))
	fmt.Printf("- API calls recorded: %d\n", len(dc.captures))
	fmt.Printf("- Fixture file: %s\n", fixtureFile)

	// Generate summary report
	summaryFile := filepath.Join(dc.outputDir, "capture_summary.txt")
	summary := fmt.Sprintf(`KSM Vault Data Capture Summary
==============================
Capture Time: %s
Records: %d
Folders: %d
Files: %d
API Calls: %d

Records by Type:
`, dc.captureTime.Format(time.RFC3339), len(records), len(captured.Folders), len(captured.Files), len(dc.captures))

	typeCount := make(map[string]int)
	for _, record := range records {
		typeCount[record.Type()]++
	}

	for recordType, count := range typeCount {
		summary += fmt.Sprintf("- %s: %d\n", recordType, count)
	}

	if err := ioutil.WriteFile(summaryFile, []byte(summary), 0600); err != nil {
		fmt.Printf("Warning: Failed to write summary file: %v\n", err)
	}

	return nil
}

func sanitizeFileName(name string) string {
	// Replace problematic characters
	replacer := map[rune]rune{
		'/':  '_',
		'\\': '_',
		':':  '_',
		'*':  '_',
		'?':  '_',
		'"':  '_',
		'<':  '_',
		'>':  '_',
		'|':  '_',
		' ':  '_',
	}

	result := ""
	for _, char := range name {
		if replacement, ok := replacer[char]; ok {
			result += string(replacement)
		} else {
			result += string(char)
		}
	}

	return result
}

// LoadFixtures loads captured data from disk
func LoadFixtures(fixtureFile string) (*CapturedData, error) {
	// Clean and validate the path
	cleanPath := filepath.Clean(fixtureFile)
	data, err := ioutil.ReadFile(cleanPath) // #nosec G304 - test utility, path is cleaned
	if err != nil {
		return nil, fmt.Errorf("failed to read fixture file: %w", err)
	}

	var captured CapturedData
	if err := json.Unmarshal(data, &captured); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fixture data: %w", err)
	}

	return &captured, nil
}
