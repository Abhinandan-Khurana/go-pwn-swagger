// This is the old version. It is not used in the final version of the project.
// This is based on the code pattern identification for swagger-ui.
// It is inefficient and does not provided any confidence on vulnerability detection.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Signatures holds the patterns and vulnerability data for Swagger UI versions
type Signatures struct {
	VersionPatterns map[string]VersionSignature
}

// VersionSignature contains signature information for a specific Swagger version
type VersionSignature struct {
	BasePatterns    []Pattern
	DomPatterns     []Pattern
	FilePatterns    []Pattern
	SpecificVersion map[string]SpecificVersionSig
}

// SpecificVersionSig contains signature for a specific version number
type SpecificVersionSig struct {
	Patterns        []Pattern
	Vulnerabilities []string
}

// Pattern represents a detection pattern
type Pattern struct {
	Pattern    string
	Confidence float64
	Type       string
}

// DetectionResult stores the results of Swagger UI version detection
type DetectionResult struct {
	URL             string   `json:"url"`
	MajorVersion    string   `json:"major_version"`
	SpecificVersion string   `json:"specific_version,omitempty"`
	Confidence      float64  `json:"confidence"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// Global signatures database
var signaturesDB Signatures

func init() {
	signaturesDB = Signatures{
		VersionPatterns: map[string]VersionSignature{
			"2.x": {
				BasePatterns: []Pattern{
					{Pattern: `window\.SwaggerUi=Backbone\.Router\.extend`, Confidence: 0.9, Type: "js"},
					{Pattern: `SwaggerUi\.Views\.OperationView`, Confidence: 0.8, Type: "js"},
					{Pattern: `SwaggerUi\.Collections`, Confidence: 0.8, Type: "js"},
					{Pattern: `SwaggerUi\.partials\.signature`, Confidence: 0.9, Type: "js"},
					{Pattern: `JSONEditor\.defaults\.iconlibs\.swagger`, Confidence: 0.7, Type: "js"},
				},
				DomPatterns: []Pattern{
					{Pattern: ".swagger-section", Confidence: 0.7, Type: "html"},
					{Pattern: "#swagger-ui-container", Confidence: 0.8, Type: "html"},
					{Pattern: ".swagger-ui-wrap", Confidence: 0.7, Type: "html"},
				},
				FilePatterns: []Pattern{
					{Pattern: "swagger-ui.min.js", Confidence: 0.6, Type: "file"},
					{Pattern: "swagger-ui.js", Confidence: 0.6, Type: "file"},
				},
				SpecificVersion: map[string]SpecificVersionSig{
					"2.0.24": {
						Patterns: []Pattern{
							{Pattern: `version:"2\.0\.24"`, Confidence: 1.0, Type: "js"},
							{Pattern: `SwaggerUi:version="2\.0\.24"`, Confidence: 1.0, Type: "js"},
						},
						Vulnerabilities: []string{"XSS CVE-2016-5204"},
					},
					"2.1.0-2.1.6": {
						Patterns: []Pattern{
							{Pattern: `version:"2\.1\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Critical XSS in JSON Editor"},
					},
					"2.2.0-2.2.2": {
						Patterns: []Pattern{
							{Pattern: `version:"2\.2\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"XSS in parameter fields (CVE-2018-7753)"},
					},
				},
			},
			"3.x": {
				BasePatterns: []Pattern{
					{Pattern: "swagger-ui-react", Confidence: 0.9, Type: "js"},
					{Pattern: "swagger-ui-standalone-preset", Confidence: 0.9, Type: "js"},
					{Pattern: "SwaggerUIBundle", Confidence: 0.95, Type: "js"},
					{Pattern: "SwaggerUIStandalonePreset", Confidence: 0.9, Type: "js"},
					{Pattern: `window\.ui=SwaggerUIBundle`, Confidence: 0.8, Type: "js"},
				},
				DomPatterns: []Pattern{
					{Pattern: "#swagger-ui", Confidence: 0.8, Type: "html"},
					{Pattern: ".swagger-ui", Confidence: 0.7, Type: "html"},
					{Pattern: ".opblock", Confidence: 0.8, Type: "html"},
					{Pattern: ".information-container", Confidence: 0.7, Type: "html"},
				},
				FilePatterns: []Pattern{
					{Pattern: "swagger-ui-bundle.js", Confidence: 0.8, Type: "file"},
					{Pattern: "swagger-ui.css", Confidence: 0.6, Type: "file"},
					{Pattern: "swagger-ui-standalone-preset.js", Confidence: 0.8, Type: "file"},
				},
				SpecificVersion: map[string]SpecificVersionSig{
					"3.0.0-3.0.12": {
						Patterns: []Pattern{
							{Pattern: `SwaggerUIBundle$\{version:"3\.0\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"XSS CVE-2018-3760"},
					},
					"3.4.0-3.4.1": {
						Patterns: []Pattern{
							{Pattern: `SwaggerUIBundle$\{version:"3\.4\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"XSS via Swagger JSON/YAML definitions"},
					},
					"3.18.0-3.20.8": {
						Patterns: []Pattern{
							{Pattern: `SwaggerUIBundle$\{version:"3\.18\.`, Confidence: 0.95, Type: "js"},
							{Pattern: `SwaggerUIBundle$\{version:"3\.19\.`, Confidence: 0.95, Type: "js"},
							{Pattern: `SwaggerUIBundle$\{version:"3\.20\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Reverse Tabnabbing", "XSS in older 3.20.x"},
					},
					"3.23.0-3.23.10": {
						Patterns: []Pattern{
							{Pattern: `SwaggerUIBundle$\{version:"3\.23\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Relative Path Overwrite (RPO)"},
					},
					"3.26.0": {
						Patterns: []Pattern{
							{Pattern: `SwaggerUIBundle$\{version:"3\.26\.0`, Confidence: 1.0, Type: "js"},
						},
						Vulnerabilities: []string{"Insecure Defaults"},
					},
					"3.38.0-4.1.2": {
						Patterns: []Pattern{
							{Pattern: `version:"3\.38\.`, Confidence: 0.95, Type: "js"},
							{Pattern: `version:"3\.4`, Confidence: 0.9, Type: "js"},
							{Pattern: `version:"4\.0\.`, Confidence: 0.95, Type: "js"},
							{Pattern: `version:"4\.1\.0`, Confidence: 1.0, Type: "js"},
							{Pattern: `version:"4\.1\.1`, Confidence: 1.0, Type: "js"},
							{Pattern: `version:"4\.1\.2`, Confidence: 1.0, Type: "js"},
						},
						Vulnerabilities: []string{"Server-side Request Forgery (SSRF)"},
					},
				},
			},
		},
	}
}

func fetchContent(url string) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("error fetching URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 status code: %d", resp.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	return string(bodyBytes), nil
}

// fetchJSFiles extracts and retrieves JavaScript files referenced in HTML
func fetchJSFiles(baseURL string, htmlContent string) (map[string]string, error) {
	jsFiles := make(map[string]string)

	// Find all JavaScript file references
	jsRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["'][^>]*>`)
	matches := jsRegex.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		jsURL := match[1]
		if !strings.HasPrefix(jsURL, "http") {
			if strings.HasPrefix(jsURL, "/") {
				baseURLParts := strings.Split(baseURL, "/")
				if len(baseURLParts) >= 3 {
					domain := strings.Join(baseURLParts[:3], "/")
					jsURL = domain + jsURL
				} else {
					jsURL = baseURL + jsURL
				}
			} else {
				baseDir := baseURL
				if !strings.HasSuffix(baseURL, "/") {
					lastSlash := strings.LastIndex(baseURL, "/")
					if lastSlash > 0 {
						baseDir = baseURL[:lastSlash+1]
					} else {
						baseDir = baseURL + "/"
					}
				}
				jsURL = baseDir + jsURL
			}
		}

		jsContent, err := fetchContent(jsURL)
		if err == nil {
			jsFiles[jsURL] = jsContent
		}
	}

	return jsFiles, nil
}

// detectSwaggerVersion detects the Swagger UI version from HTML and JS content
func detectSwaggerVersion(url, htmlContent string, jsFiles map[string]string) DetectionResult {
	result := DetectionResult{
		URL:        url,
		Confidence: 0.0,
	}

	// First, check for exact version patterns in JS files
	for _, jsContent := range jsFiles {
		// Check each major version
		for majorVersion, versionSig := range signaturesDB.VersionPatterns {
			// Check specific version patterns
			for specificVersion, specSig := range versionSig.SpecificVersion {
				for _, pattern := range specSig.Patterns {
					regex, err := regexp.Compile(pattern.Pattern)
					if err != nil {
						fmt.Printf("Warning: Invalid regex pattern: %s - %v\n", pattern.Pattern, err)
						continue
					}

					if regex.MatchString(jsContent) {
						if pattern.Confidence > result.Confidence {
							result.MajorVersion = majorVersion
							result.SpecificVersion = specificVersion
							result.Confidence = pattern.Confidence
							result.Vulnerabilities = specSig.Vulnerabilities
						}
					}
				}
			}

			// If no specific version found, check base patterns
			if result.MajorVersion == "" {
				for _, pattern := range versionSig.BasePatterns {
					if pattern.Type == "js" {
						regex, err := regexp.Compile(pattern.Pattern)
						if err != nil {
							fmt.Printf("Warning: Invalid regex pattern: %s - %v\n", pattern.Pattern, err)
							continue
						}

						if regex.MatchString(jsContent) {
							if pattern.Confidence > result.Confidence {
								result.MajorVersion = majorVersion
								result.Confidence = pattern.Confidence
							}
						}
					}
				}
			}
		}
	}

	// Check DOM patterns in HTML if no strong match found
	if result.Confidence < 0.8 {
		for majorVersion, versionSig := range signaturesDB.VersionPatterns {
			for _, pattern := range versionSig.DomPatterns {
				if pattern.Type == "html" {
					selector := pattern.Pattern
					if strings.HasPrefix(selector, ".") || strings.HasPrefix(selector, "#") {
						// Simple check for class or ID presence
						classOrID := selector[1:]
						patternText := fmt.Sprintf(`(class|id)=["']%s["']`, regexp.QuoteMeta(classOrID))
						if regexp.MustCompile(patternText).MatchString(htmlContent) {
							if pattern.Confidence > result.Confidence {
								result.MajorVersion = majorVersion
								result.Confidence = pattern.Confidence
							}
						}
					}
				}
			}
		}
	}

	// Check for file patterns if still uncertain
	if result.Confidence < 0.7 {
		for majorVersion, versionSig := range signaturesDB.VersionPatterns {
			for _, pattern := range versionSig.FilePatterns {
				if pattern.Type == "file" {
					for jsURL := range jsFiles {
						if strings.Contains(jsURL, pattern.Pattern) {
							if pattern.Confidence > result.Confidence {
								result.MajorVersion = majorVersion
								result.Confidence = pattern.Confidence
							}
						}
					}
				}
			}
		}
	}

	// If we've found a major version but no specific version, add generic vulnerabilities
	if result.MajorVersion != "" && result.SpecificVersion == "" && len(result.Vulnerabilities) == 0 {
		// Add generic vulnerabilities for the major version
		if result.MajorVersion == "2.x" {
			result.Vulnerabilities = []string{
				"Potentially vulnerable to XSS (common in 2.x series)",
				"May expose sensitive API information",
			}
		} else if result.MajorVersion == "3.x" {
			result.Vulnerabilities = []string{
				"Check for CORS misconfiguration",
				"Verify OAuth flow implementation",
			}
		}
	}

	return result
}

func analyzeSwaggerURL(url string) DetectionResult {
	result := DetectionResult{URL: url}

	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	htmlContent, err := fetchContent(url)
	if err != nil {
		result.Error = fmt.Sprintf("Error fetching URL: %v", err)
		return result
	}

	// Check if content looks like Swagger UI
	swaggerIndicators := []string{"swagger", "api-docs", "SwaggerUI", "swagger-ui"}
	containsSwagger := false
	for _, indicator := range swaggerIndicators {
		if strings.Contains(strings.ToLower(htmlContent), strings.ToLower(indicator)) {
			containsSwagger = true
			break
		}
	}

	if !containsSwagger {
		result.Error = "Page does not appear to contain Swagger UI"
		return result
	}

	jsFiles, err := fetchJSFiles(url, htmlContent)
	if err != nil {
		result.Error = fmt.Sprintf("Error fetching JS files: %v", err)
		return result
	}

	result = detectSwaggerVersion(url, htmlContent, jsFiles)
	return result
}

func printHelp() {
	fmt.Println("Swagger UI Version Detector")
	fmt.Println("==========================")
	fmt.Println("A tool to detect Swagger UI versions and associated vulnerabilities.")
	fmt.Println("\nUsage:")
	fmt.Println("  swagger-detector [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  -url string        Single Swagger UI URL to analyze")
	fmt.Println("  -file string       File containing Swagger UI URLs (one per line)")
	fmt.Println("  -json              Output results in JSON format")
	fmt.Println("  -concurrency int   Number of concurrent requests (default: 5)")
	fmt.Println("  -help              Display this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  swagger-detector -url https://example.com/api-docs")
	fmt.Println("  swagger-detector -file urls.txt -concurrency 10")
	fmt.Println("  cat urls.txt | swagger-detector -json")
}

func main() {
	urlFlag := flag.String("url", "", "Single Swagger UI URL to analyze")
	fileFlag := flag.String("file", "", "File containing Swagger UI URLs (one per line)")
	jsonOutputFlag := flag.Bool("json", false, "Output results in JSON format")
	concurrencyFlag := flag.Int("concurrency", 5, "Number of concurrent requests")
	helpFlag := flag.Bool("help", false, "Display help information")
	flag.Parse()

	if *helpFlag {
		printHelp()
		os.Exit(0)
	}

	var urls []string

	if *urlFlag != "" {
		urls = append(urls, *urlFlag)
	} else if *fileFlag != "" {
		file, err := os.Open(*fileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url != "" && !strings.HasPrefix(url, "#") {
				urls = append(urls, url)
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				url := strings.TrimSpace(scanner.Text())
				if url != "" && !strings.HasPrefix(url, "#") {
					urls = append(urls, url)
				}
			}
		} else {
			fmt.Println("Please provide URLs using -url, -file flag, or pipe input")
			fmt.Println("Use -help for more information")
			os.Exit(1)
		}
	}

	if len(urls) == 0 {
		fmt.Println("No URLs to process")
		fmt.Println("Use -help for more information")
		os.Exit(1)
	}

	results := make([]DetectionResult, len(urls))
	wg := sync.WaitGroup{}
	semaphore := make(chan struct{}, *concurrencyFlag)

	for i, url := range urls {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(i int, url string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			results[i] = analyzeSwaggerURL(url)
		}(i, url)
	}

	wg.Wait()

	if *jsonOutputFlag {
		jsonData, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		fmt.Println("========== Swagger UI Version Detection Results ==========")
		fmt.Println()

		for _, result := range results {
			fmt.Printf("URL: %s\n", result.URL)

			if result.Error != "" {
				fmt.Printf("Error: %s\n", result.Error)
			} else {
				fmt.Printf("Detected Version: %s", result.MajorVersion)
				if result.SpecificVersion != "" {
					fmt.Printf(" (%s)", result.SpecificVersion)
				}
				fmt.Printf("\nConfidence: %.1f%%\n", result.Confidence*100)

				if len(result.Vulnerabilities) > 0 {
					fmt.Println("Potential Vulnerabilities:")
					for _, vuln := range result.Vulnerabilities {
						fmt.Printf("  - %s\n", vuln)
					}
				} else {
					fmt.Println("No specific vulnerabilities identified")
				}
			}
			fmt.Println(strings.Repeat("-", 60))
		}
	}
}
