package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
	"github.com/fatih/color"
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
	DetectionMethod string   `json:"detection_method,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// ResourceData contains all fetched resources from a URL
type ResourceData struct {
	HTML    string
	JS      map[string]string
	Headers http.Header
}

// Global signatures database (This is only used when the Javascript signature fails, which is very unlikely. You can also find these code pattern signatures in the old code and since it produces redundant results this shall be deprecated soon.)
var signaturesDB Signatures

func init() {
	// Initialize signatures database programmatically
	signaturesDB = Signatures{
		VersionPatterns: map[string]VersionSignature{
			"1.x": {
				BasePatterns: []Pattern{
					{Pattern: `SwaggerApi`, Confidence: 0.7, Type: "js"},
					{Pattern: `SwaggerService`, Confidence: 0.7, Type: "js"},
					{Pattern: `swaggerUI`, Confidence: 0.8, Type: "js"},
				},
				DomPatterns: []Pattern{
					{Pattern: ".swagger-ui-wrap", Confidence: 0.7, Type: "html"},
					{Pattern: "#resources_container", Confidence: 0.7, Type: "html"},
					{Pattern: ".resource_list", Confidence: 0.6, Type: "html"},
				},
				FilePatterns: []Pattern{
					{Pattern: "swagger-ui.js", Confidence: 0.5, Type: "file"},
					{Pattern: "swagger.js", Confidence: 0.5, Type: "file"},
				},
				SpecificVersion: map[string]SpecificVersionSig{
					"1.0.0": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']1\.0\.0[\"\']`, Confidence: 1.0, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: XSS in parameter rendering", "Medium: Information disclosure"},
					},
					"1.1.0-1.2.5": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']1\.[1-2]\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: XSS in parameter rendering", "Medium: Information disclosure"},
					},
				},
			},
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
							{Pattern: `version:[\"\']2\.0\.24[\"\']`, Confidence: 1.0, Type: "js"},
							{Pattern: `SwaggerUi:version=[\"\']2\.0\.24[\"\']`, Confidence: 1.0, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: XSS CVE-2016-5204"},
					},
					"2.1.0-2.1.6": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']2\.1\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Critical: XSS in JSON Editor"},
					},
					"2.2.0-2.2.10": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']2\.2\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"High: XSS in parameter fields (CVE-2018-7753)"},
					},
				},
			},
			"3.x": {
				BasePatterns: []Pattern{
					{Pattern: `swagger-ui-react`, Confidence: 0.9, Type: "js"},
					{Pattern: `swagger-ui-standalone-preset`, Confidence: 0.9, Type: "js"},
					{Pattern: `SwaggerUIBundle`, Confidence: 0.95, Type: "js"},
					{Pattern: `SwaggerUIStandalonePreset`, Confidence: 0.9, Type: "js"},
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
					"3.0.0-3.0.21": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']3\.0\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: XSS CVE-2018-3760", "Medium: XSS in URL parsing"},
					},
					"3.1.0-3.3.2": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']3\.[1-3]\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: XSS in URL handling", "Medium: CORS misconfiguration vulnerability"},
					},
					"3.4.0-3.17.0": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']3\.[4-9]\.`, Confidence: 0.95, Type: "js"},
							{Pattern: `version:[\"\']3\.1[0-7]\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: XSS via Swagger JSON/YAML definitions", "Medium: CORS misconfiguration"},
					},
					"3.18.0-3.20.9": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']3\.1[8-9]\.`, Confidence: 0.95, Type: "js"},
							{Pattern: `version:[\"\']3\.20\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: XSS in older 3.20.x"},
					},
					"3.21.0-3.22.3": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']3\.2[1-2]\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: JSON parsing vulnerabilities"},
					},
					"3.23.0-3.38.0": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']3\.2[3-9]\.`, Confidence: 0.95, Type: "js"},
							{Pattern: `version:[\"\']3\.3[0-8]\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: SSRF in validator module"},
					},
					"3.39.0-3.52.1": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']3\.[3-5][9-9]\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: SSRF in validator module (pre-4.0)"},
					},
				},
			},
			"4.x": {
				BasePatterns: []Pattern{
					{Pattern: `swagger-ui/dist/swagger-ui.css`, Confidence: 0.8, Type: "js"},
					{Pattern: `swagger-ui-react/swagger-ui.css`, Confidence: 0.8, Type: "js"},
					{Pattern: `SwaggerUIBundle`, Confidence: 0.7, Type: "js"}, // Also in 3.x
					{Pattern: `SwaggerUI.plugins`, Confidence: 0.8, Type: "js"},
				},
				DomPatterns: []Pattern{
					{Pattern: "#swagger-ui", Confidence: 0.6, Type: "html"}, // Also in 3.x
					{Pattern: ".swagger-ui", Confidence: 0.6, Type: "html"}, // Also in 3.x
					{Pattern: ".opblock-summary-description", Confidence: 0.7, Type: "html"},
				},
				FilePatterns: []Pattern{
					{Pattern: "swagger-ui.v4", Confidence: 0.9, Type: "file"},
					{Pattern: "swagger-ui@4", Confidence: 0.9, Type: "file"},
					{Pattern: "swagger-ui/4.", Confidence: 0.9, Type: "file"},
				},
				SpecificVersion: map[string]SpecificVersionSig{
					"4.0.0-4.1.3": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']4\.[0-1]\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{"Medium: Server-side Request Forgery (SSRF)"},
					},
					"4.2.0-4.15.5": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']4\.[2-9]\.`, Confidence: 0.95, Type: "js"},
							{Pattern: `version:[\"\']4\.1[0-5]\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{},
					},
				},
			},
			"5.x": {
				BasePatterns: []Pattern{
					{Pattern: `swagger-ui-v5`, Confidence: 0.9, Type: "js"},
					{Pattern: `swagger-ui@5`, Confidence: 0.9, Type: "js"},
					{Pattern: `SwaggerUINext`, Confidence: 0.8, Type: "js"},
				},
				DomPatterns: []Pattern{
					{Pattern: ".swagger-ui-v5", Confidence: 0.8, Type: "html"},
					{Pattern: "[data-swagger-version='5']", Confidence: 0.9, Type: "html"},
				},
				FilePatterns: []Pattern{
					{Pattern: "swagger-ui.v5", Confidence: 0.9, Type: "file"},
					{Pattern: "swagger-ui@5", Confidence: 0.9, Type: "file"},
					{Pattern: "swagger-ui/5.", Confidence: 0.9, Type: "file"},
				},
				SpecificVersion: map[string]SpecificVersionSig{
					"5.0.0-latest": {
						Patterns: []Pattern{
							{Pattern: `version:[\"\']5\.`, Confidence: 0.95, Type: "js"},
						},
						Vulnerabilities: []string{},
					},
				},
			},
		},
	}
}

// fetchResources retrieves all necessary resources from a URL
func fetchResources(url string) (ResourceData, error) {
	var resources ResourceData
	resources.JS = make(map[string]string)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Fetch main HTML content
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return resources, err
	}

	// Add headers to mimic a browser
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return resources, fmt.Errorf("error fetching URL: %v", err)
	}
	defer resp.Body.Close()

	// Store headers for analysis
	resources.Headers = resp.Header

	if resp.StatusCode != http.StatusOK {
		return resources, fmt.Errorf("non-200 status code: %d", resp.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resources, fmt.Errorf("error reading response body: %v", err)
	}

	resources.HTML = string(bodyBytes)

	// Parse HTML to find JS file references
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(resources.HTML))
	if err != nil {
		return resources, fmt.Errorf("error parsing HTML: %v", err)
	}

	baseURL := getBaseURL(url)

	// Find and fetch all script files
	doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			jsURL := resolveURL(baseURL, src)

			// Skip external CDNs and third-party scripts that aren't likely Swagger-related
			if !strings.Contains(jsURL, "googleapis.com") &&
				!strings.Contains(jsURL, "jquery") &&
				!strings.Contains(jsURL, "analytics") {
				jsContent, err := fetchContent(jsURL, client)
				if err == nil {
					resources.JS[jsURL] = jsContent
				}
			}
		}
	})

	// Check for inline scripts that might be swagger-related
	doc.Find("script:not([src])").Each(func(_ int, s *goquery.Selection) {
		scriptContent := s.Text()
		if strings.Contains(scriptContent, "swagger") ||
			strings.Contains(scriptContent, "Swagger") ||
			strings.Contains(scriptContent, "SwaggerUI") {
			resources.JS["inline-script-"+fmt.Sprint(len(resources.JS))] = scriptContent
		}
	})

	return resources, nil
}

func getBaseURL(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], "/")
	}
	return url
}

// Helper function to resolve relative URLs
func resolveURL(baseURL, relPath string) string {
	if strings.HasPrefix(relPath, "http") {
		return relPath
	}

	if strings.HasPrefix(relPath, "//") {

		if strings.HasPrefix(baseURL, "https:") {
			return "https:" + relPath
		}
		return "http:" + relPath
	}

	if strings.HasPrefix(relPath, "/") {
		return getBaseURL(baseURL) + relPath
	}

	// Handle relative path
	baseDir := baseURL
	if !strings.HasSuffix(baseURL, "/") {
		lastSlash := strings.LastIndex(baseURL, "/")
		if lastSlash > 0 {
			baseDir = baseURL[:lastSlash+1]
		} else {
			baseDir = baseURL + "/"
		}
	}
	return baseDir + relPath
}

// fetchContent retrieves content from a URL
func fetchContent(url string, client *http.Client) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// Add headers to mimic a browser
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Referer", getBaseURL(url))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 status code: %d", resp.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(bodyBytes), nil
}

// determineVulnerabilities updates the result with accurate vulnerability information based on version
func determineVulnerabilities(result *DetectionResult) {
	// Clear existing vulnerabilities to avoid duplicates
	result.Vulnerabilities = []string{}

	// For 1.x versions
	if strings.HasPrefix(result.MajorVersion, "1.") || result.MajorVersion == "1.x" {
		result.Vulnerabilities = append(result.Vulnerabilities, "Medium: XSS in parameter rendering", "Medium: Information disclosure")
		return
	}

	// For 2.x versions
	if strings.HasPrefix(result.MajorVersion, "2.") || result.MajorVersion == "2.x" {
		if result.SpecificVersion != "" {
			version := strings.TrimPrefix(result.SpecificVersion, "2.")
			if version >= "0.3" && version < "0.24" {
				result.Vulnerabilities = append(result.Vulnerabilities, "Medium: Cross-site Scripting (XSS) CVE-2016-5204")
			}
			if version < "1.0" {
				result.Vulnerabilities = append(result.Vulnerabilities, "Critical: Cross-site Scripting (XSS)")
			}
			if version < "2.1" {
				result.Vulnerabilities = append(result.Vulnerabilities, "High: Cross-site Scripting (XSS)")
			}
			if version < "2.3" {
				result.Vulnerabilities = append(result.Vulnerabilities, "Medium: Cross-site Scripting (XSS)")
			}
		} else {
			// If we only know it's 2.x but don't have specific version
			result.Vulnerabilities = append(result.Vulnerabilities,
				"Potentially vulnerable to XSS (Critical/High/Medium severity depending on specific version)")
		}
		return
	}

	// For 3.x versions
	if strings.HasPrefix(result.MajorVersion, "3.") || result.MajorVersion == "3.x" {
		if result.SpecificVersion != "" {
			version := strings.TrimPrefix(result.SpecificVersion, "3.")
			parts := strings.Split(version, ".")
			if len(parts) > 0 {
				minorStr := parts[0]
				minorNum, err := strconv.Atoi(minorStr)
				if err == nil {
					if minorNum < 1 {
						if version < "0.13" {
							result.Vulnerabilities = append(result.Vulnerabilities, "Medium: Cross-site Scripting (XSS)")
						}
					}
					if minorNum < 5 {
						if version < "4.2" {
							result.Vulnerabilities = append(result.Vulnerabilities, "Medium: Cross-site Scripting (XSS)")
						}
					}
					if minorNum < 18 {
						result.Vulnerabilities = append(result.Vulnerabilities, "Medium: Reverse Tabnabbing")
					}
					if minorNum < 21 {
						if version < "20.9" {
							result.Vulnerabilities = append(result.Vulnerabilities, "Medium: Cross-site Scripting (XSS)")
						}
					}
					if minorNum < 24 {
						if version < "23.11" {
							result.Vulnerabilities = append(result.Vulnerabilities, "Medium: Relative Path Overwrite (RPO)")
						}
					}
					if minorNum < 27 {
						if version < "26.1" {
							result.Vulnerabilities = append(result.Vulnerabilities, "Medium: Insecure Defaults")
						}
					}
				}
			}
		} else {
			// If we only know it's 3.x
			result.Vulnerabilities = append(result.Vulnerabilities,
				"Potentially vulnerable to XSS, Reverse Tabnabbing, RPO, and Insecure Defaults (Medium severity)")
		}
		return
	}

	// For 4.x versions
	if strings.HasPrefix(result.MajorVersion, "4.") || result.MajorVersion == "4.x" {
		if result.SpecificVersion != "" {
			version := strings.TrimPrefix(result.SpecificVersion, "4.")
			if version < "1.3" {
				result.Vulnerabilities = append(result.Vulnerabilities, "Medium: Server-side Request Forgery (SSRF)")
			}
		} else {
			// If we only know it's 4.x
			result.Vulnerabilities = append(result.Vulnerabilities,
				"Potentially vulnerable to SSRF if version < 4.1.3 (Medium severity)")
		}
		return
	}

	// For 5.x versions - currently no known vulnerabilities
	if strings.HasPrefix(result.MajorVersion, "5.") || result.MajorVersion == "5.x" {
		result.Vulnerabilities = append(result.Vulnerabilities, "No known vulnerabilities for Swagger UI 5.x at this time")
		return
	}

	// If no vulnerabilities were found but we have version info
	if len(result.Vulnerabilities) == 0 && result.MajorVersion != "" {
		result.Vulnerabilities = append(result.Vulnerabilities, "No known vulnerabilities for this specific version")
	}
}

// detectSwaggerVersionComprehensive combines multiple detection methods
func detectSwaggerVersionComprehensive(url string) DetectionResult {
	result := DetectionResult{
		URL:        url,
		Confidence: 0.0,
	}

	// Ensure URL has proper scheme
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	// Fetch resources
	resources, err := fetchResources(url)
	if err != nil {
		result.Error = fmt.Sprintf("Error fetching resources: %v", err)
		return result
	}

	// Check if content looks like Swagger UI
	swaggerIndicators := []string{"swagger", "api-docs", "SwaggerUI", "swagger-ui", "openapi"}
	containsSwagger := false
	for _, indicator := range swaggerIndicators {
		if strings.Contains(strings.ToLower(resources.HTML), strings.ToLower(indicator)) {
			containsSwagger = true
			break
		}
	}

	if !containsSwagger {
		result.Error = "Page does not appear to contain Swagger UI"
		return result
	}

	// 1. Try HTTP headers (most reliable when available)
	headerResult := detectFromHeaders(resources.Headers)
	if headerResult.Confidence > 0 {
		headerResult.URL = url
		headerResult.DetectionMethod = "HTTP Headers"
		return headerResult
	}

	// 2. Try JavaScript execution via headless browser (high reliability)
	jsResult := detectFromJavaScriptExecution(url)
	if jsResult.Error == "" && jsResult.Confidence >= 0.9 {
		jsResult.URL = url
		jsResult.DetectionMethod = "JavaScript Execution"
		return jsResult
	}

	// 3. Try static pattern detection (good reliability)
	staticResult := detectFromStaticPatterns(resources)
	if staticResult.Confidence > 0 {
		staticResult.URL = url
		staticResult.DetectionMethod = "Static Pattern Analysis"

		// If JS execution gave some results but with lower confidence, combine them
		if jsResult.MajorVersion != "" && jsResult.SpecificVersion != "" && staticResult.SpecificVersion == "" {
			staticResult.SpecificVersion = jsResult.SpecificVersion
		}

		return staticResult
	}

	// 4. Try DOM analysis (moderate reliability)
	domResult := detectFromDOMStructure(resources.HTML)
	if domResult.Confidence > 0 {
		domResult.URL = url
		domResult.DetectionMethod = "DOM Structure Analysis"
		return domResult
	}

	// 5. Try asset filename analysis (less reliable)
	assetResult := detectFromAssetFilenames(resources.HTML)
	if assetResult.Confidence > 0 {
		assetResult.URL = url
		assetResult.DetectionMethod = "Asset Filename Analysis"
		return assetResult
	}

	// If all else failed but we know it's Swagger UI, provide a generic result
	if containsSwagger {
		result.MajorVersion = "Unknown"
		result.Confidence = 0.5
		result.DetectionMethod = "Basic Signature Detection"
		result.Vulnerabilities = []string{
			"Unknown version - manual inspection recommended",
			"Check for outdated dependencies and improper configurations",
		}
	}

	return result
}

// Detect version from HTTP response headers
func detectFromHeaders(headers http.Header) DetectionResult {
	result := DetectionResult{Confidence: 0.0}

	// Check common version headers
	versionHeaders := []string{
		"X-Swagger-UI-Version",
		"X-UI-Version",
		"X-Swagger-Version",
		"X-API-Version",
		"Swagger-Version",
	}

	for _, header := range versionHeaders {
		if version := headers.Get(header); version != "" {
			// Parse version string
			if strings.HasPrefix(version, "1.") {
				result.MajorVersion = "1.x"
				result.SpecificVersion = version
				result.Confidence = 1.0
			} else if strings.HasPrefix(version, "2.") {
				result.MajorVersion = "2.x"
				result.SpecificVersion = version
				result.Confidence = 1.0
			} else if strings.HasPrefix(version, "3.") {
				result.MajorVersion = "3.x"
				result.SpecificVersion = version
				result.Confidence = 1.0
			} else if strings.HasPrefix(version, "4.") {
				result.MajorVersion = "4.x"
				result.SpecificVersion = version
				result.Confidence = 1.0
			} else if strings.HasPrefix(version, "5.") {
				result.MajorVersion = "5.x"
				result.SpecificVersion = version
				result.Confidence = 1.0
			}

			if result.Confidence > 0 {
				// Determine vulnerabilities based on detected version
				determineVulnerabilities(&result)
				return result
			}
		}
	}

	return result
}

// detectFromJavaScriptExecution uses a headless browser to detect Swagger UI version
func detectFromJavaScriptExecution(url string) DetectionResult {
	result := DetectionResult{
		Confidence: 0.0,
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Create headless browser context
	browserCtx, cancel := chromedp.NewContext(ctx)
	defer cancel()

	// Define JavaScript to detect Swagger UI version
	versionDetectionScript := `
(function () {
  // Helper function to determine major version from a version string
  function getMajorVersion(versionString) {
    if (typeof versionString !== "string") {
      return "unknown";
    }
    if (versionString.startsWith("5")) return "5.x";
    if (versionString.startsWith("4")) return "4.x";
    if (versionString.startsWith("3")) return "3.x";
    // Add check for 2.x if version string might explicitly contain it
    if (versionString.startsWith("2")) return "2.x";
    return "unknown";
  }

  try {
    // Method 1: Try window.versions object (preferred, often contains explicit version)
    // Check safely for nested properties and ensure version is a string
    if (
      window.versions &&
      window.versions.swaggerUi &&
      typeof window.versions.swaggerUi.version === "string"
    ) {
      const v = window.versions.swaggerUi.version;
      const mj = getMajorVersion(v);
      // Only return if major version is determined, otherwise fallback might be better
      if (mj !== "unknown") {
        return JSON.stringify({
          method: "versions-object",
          version: v,
          major: mj,
        });
      }
    }

    // Method 2: Try SwaggerUIBundle.version (Common in 3.x, 4.x, 5.x standard bundles)
    if (
      window.SwaggerUIBundle &&
      typeof window.SwaggerUIBundle.version === "string"
    ) {
      const v = window.SwaggerUIBundle.version;
      const mj = getMajorVersion(v);
      if (mj !== "unknown") {
        return JSON.stringify({
          method: "swagger-ui-bundle",
          version: v,
          major: mj,
        });
      }
    }

    // Method 3: Try ui.getConfigs() (Available in 3.x+, but might not be initialized)
    // 'ui' is the common variable name for the Swagger UI instance
    if (window.ui && typeof window.ui.getConfigs === "function") {
      try {
        const config = window.ui.getConfigs();
        // Check if config and its version property exist and version is a string
        if (config && typeof config.version === "string") {
          const v = config.version;
          const mj = getMajorVersion(v);
          if (mj !== "unknown") {
            return JSON.stringify({
              method: "ui-configs",
              version: v,
              major: mj,
            });
          }
        }
      } catch (configError) {
        // Some versions throw errors if getConfigs is called too early or if 'ui' isn't fully ready.
        console.warn(
          "Could not get version from ui.getConfigs():",
          configError.message,
        );
      }
    }

    // Method 4: Look for global SwaggerUI object and infer based on properties
    // The 'SwaggerUI' constructor function exists in v3, v4, v5. Its *properties* differ.
    // 'SwaggerUI' also existed in v2, but often without SwaggerUIBundle.
    if (window.SwaggerUI) {
      // Check for 5.x-specific static properties (plugins/systems were prominent additions)
      if (window.SwaggerUI.plugins || window.SwaggerUI.systems) {
        // High confidence this is 5.x or related structure
        return JSON.stringify({
          method: "swagger-ui-5x-apis",
          version: "5.x inferred", // Cannot get exact version here easily
          major: "5.x",
        });
      }
      // If SwaggerUI exists but SwaggerUIBundle does NOT, it's likely 2.x
      // (Bundle was introduced later)
      else if (!window.SwaggerUIBundle) {
        return JSON.stringify({
          method: "swagger-ui-global-no-bundle",
          version: "2.x inferred",
          major: "2.x",
        });
      }
      // If SwaggerUI exists and SwaggerUIBundle exists, Method 2 should have caught it.
      // If it falls through here, it might be an unusual setup (e.g., v3/v4 without bundle version property)
      // We can make an educated guess based on the presence of SwaggerUI + Bundle
      else if (window.SwaggerUIBundle) {
        // Cannot reliably distinguish 3.x/4.x here without version property
        // Let DOM methods try to refine this
        console.warn(
          "Found SwaggerUI and SwaggerUIBundle, but Bundle had no version property.",
        );
      }
    }

    // Method 5: Check for SwaggerUINext (Potentially a 5.x specific global or future version indicator)
    if (window.SwaggerUINext) {
      // Try to get a version if available, otherwise default to 5.x
      const v =
        typeof window.SwaggerUINext.version === "string"
          ? window.SwaggerUINext.version
          : "5.x inferred";
      return JSON.stringify({
        method: "swagger-ui-next",
        version: v,
        major: "5.x", // Assuming SwaggerUINext implies 5.x
      });
    }

    // --- DOM Based Checks (Less reliable, used as fallback) ---

    // Method 6: Look for 5.x specific data attributes in the DOM
    // This relies on developers explicitly adding this attribute.
    try {
      const dataAttrs = document.querySelectorAll("[data-swagger-version]");
      for (let i = 0; i < dataAttrs.length; i++) {
        const versionAttr = dataAttrs[i].getAttribute("data-swagger-version");
        // Check if attribute value looks like a v5 version
        if (
          versionAttr &&
          typeof versionAttr === "string" &&
          versionAttr.trim().startsWith("5")
        ) {
          return JSON.stringify({
            method: "dom-data-attribute",
            version: versionAttr,
            major: "5.x",
          });
        }
      }
    } catch (domError) {
      console.warn("DOM query error (data-attr):", domError.message);
    }

    // Method 7: Check for indicative CSS classes (potentially version-specific or custom)
    try {
      const swaggerVersionClasses = [
        ".swagger-ui-v5", // Example specific class
        ".swagger-ui--v5", // Another pattern
        '.swagger-ui .swagger-ui-wrap[data-v="5"]', // Example attribute selector
        '[class*="swagger-ui-v5"]', // Wildcard check
        '[class*="swagger-ui-5"]', // Simpler wildcard
      ];
      for (const selector of swaggerVersionClasses) {
        if (document.querySelector(selector)) {
          return JSON.stringify({
            method: "dom-class-detection",
            version: "5.x inferred", // Class presence doesn't give specific version
            major: "5.x",
          });
        }
      }
      // Wil add similar checks for v4/v3 in future if reliable classes are known
      // Example for v4:
      // if (document.querySelector('.swagger-ui--v4')) { return ... "4.x" ... }
      // Example for v3:
      // if (document.querySelector('.swagger-ui--v3')) { return ... "3.x" ... }
    } catch (domError) {
      console.warn("DOM query error (class):", domError.message);
    }

    // Method 8: Check DOM element structure typical for different major versions
    // This is heuristic and can be broken by customization.
    try {
      const swaggerUiBaseElement = document.querySelector(".swagger-ui"); // Common base for v3+
      const swaggerV2Container = document.querySelector(
        "#swagger-ui-container",
      ); // Common ID for v2
      const swaggerV2Section = document.querySelector(".swagger-section"); // Another v2 indicator

      // V5 Heuristics: Often includes specific components like server dropdowns, new opblock structures
      const hasServersDropdown = !!document.querySelector(
        ".servers > .servers-title, .servers > label > select",
      );
      const hasNewOpblockPath = !!document.querySelector(
        ".opblock .opblock-summary-path",
      );
      const hasAuthorizeBtn = !!document.querySelector(
        ".auth-wrapper .authorize",
      );

      if (
        swaggerUiBaseElement &&
        hasServersDropdown &&
        hasNewOpblockPath &&
        hasAuthorizeBtn
      ) {
        // High likelihood of v5 due to combination of modern components within .swagger-ui
        return JSON.stringify({
          method: "dom-structure-v5",
          version: "5.x inferred",
          major: "5.x",
        });
      }

      // V3/V4 Heuristics: Has .swagger-ui base, lacks v2 containers.
      // Distinguishing v3/v4 via DOM alone is tricky. V4 introduced subtle changes.
      else if (swaggerUiBaseElement && !swaggerV2Container) {
        // Look for elements more common in v4+ (e.g., updated model rendering)
        const hasV4ModelElements = !!document.querySelector(
          ".model-box, .model-title .model-title__text, .models .model-container",
        );
        if (hasV4ModelElements) {
          return JSON.stringify({
            method: "dom-structure-v4",
            version: "4.x inferred",
            major: "4.x",
          });
        } else {
          // If it has .swagger-ui but lacks clear v4/v5 indicators, assume v3
          return JSON.stringify({
            method: "dom-structure-v3",
            version: "3.x inferred",
            major: "3.x",
          });
        }
      }
      // V2 Heuristics: Uses older container IDs/classes
      else if (swaggerV2Container || swaggerV2Section) {
        return JSON.stringify({
          method: "dom-structure-v2",
          version: "2.x inferred",
          major: "2.x",
        });
      }
    } catch (domError) {
      console.warn("DOM query error (structure):", domError.message);
    }

    // Method 9: Check script source URLs for version patterns (Last resort)
    // Relies on common CDN or file naming patterns.
    try {
      const scripts = document.querySelectorAll("script[src]");
      for (let i = 0; i < scripts.length; i++) {
        const src = scripts[i].getAttribute("src");
        if (src && typeof src === "string") {
          // Check from newest to oldest
          if (
            src.includes("swagger-ui@5") ||
            src.includes("swagger-ui/5.") ||
            src.includes("swagger-ui-bundle/5.")
          ) {
            return JSON.stringify({
              method: "script-src-detection",
              version: "5.x inferred",
              major: "5.x",
            });
          }
          if (
            src.includes("swagger-ui@4") ||
            src.includes("swagger-ui/4.") ||
            src.includes("swagger-ui-bundle/4.")
          ) {
            return JSON.stringify({
              method: "script-src-detection",
              version: "4.x inferred",
              major: "4.x",
            });
          }
          if (
            src.includes("swagger-ui@3") ||
            src.includes("swagger-ui/3.") ||
            src.includes("swagger-ui-bundle/3.")
          ) {
            return JSON.stringify({
              method: "script-src-detection",
              version: "3.x inferred",
              major: "3.x",
            });
          }
          // V2 often didn't use 'bundle' and might just be 'swagger-ui.js' or similar, less specific pattern.
          // Checking for '@2' or '/2.' might catch some cases.
          if (src.includes("swagger-ui@2") || src.includes("swagger-ui/2.")) {
            return JSON.stringify({
              method: "script-src-detection",
              version: "2.x inferred",
              major: "2.x",
            });
          }
        }
      }
    } catch (domError) {
      console.warn("DOM query error (script src):", domError.message);
    }

    // If none of the methods above worked, return detection failure
    return JSON.stringify({
      method: "detection-failed",
      error:
        "No definitive Swagger UI markers found via objects or DOM inspection.",
      major: "unknown", // Explicitly state unknown
    });
  } catch (e) {
    // Catch any unexpected errors during the detection process
    console.error("Swagger UI detection script failed:", e);
    return JSON.stringify({
      method: "detection-error",
      error: e.toString(),
      major: "error", // Indicate an error occurred
    });
  }
})(); // Immediately invoke the function

	`

	// Prepare variable to hold the result
	var versionInfo string

	// Execute browser navigation and script execution
	err := chromedp.Run(browserCtx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second), // Wait for scripts to load
		chromedp.EvaluateAsDevTools(versionDetectionScript, &versionInfo),
	)
	if err != nil {
		result.Error = fmt.Sprintf("Browser automation error: %v", err)
		return result
	}

	// Parse the JSON result
	var jsResult struct {
		Method  string `json:"method"`
		Version string `json:"version"`
		Major   string `json:"major"`
		Error   string `json:"error"`
	}

	err = json.Unmarshal([]byte(versionInfo), &jsResult)
	if err != nil {
		result.Error = fmt.Sprintf("Error parsing version info: %v", err)
		return result
	}

	if jsResult.Error != "" {
		result.Error = fmt.Sprintf("JavaScript error: %s", jsResult.Error)
		return result
	}

	// If detection worked
	if jsResult.Method != "detection-failed" && jsResult.Major != "" {
		result.MajorVersion = jsResult.Major
		result.SpecificVersion = jsResult.Version
		result.Confidence = 0.95

		// Determine vulnerabilities based on detected version
		determineVulnerabilities(&result)
	}

	return result
}

// detectFromStaticPatterns checks JS content for version patterns
func detectFromStaticPatterns(resources ResourceData) DetectionResult {
	result := DetectionResult{
		Confidence: 0.0,
	}

	// Combine all JS content for analysis
	allJS := ""
	for _, js := range resources.JS {
		allJS += js + "\n"
	}

	// First check for major version patterns
	bestConfidence := 0.0
	bestVersion := ""

	for version, sig := range signaturesDB.VersionPatterns {
		confidence := 0.0
		matches := 0

		// Check base patterns in JS
		for _, pattern := range sig.BasePatterns {
			if pattern.Type == "js" {
				re := regexp.MustCompile(pattern.Pattern)
				if re.MatchString(allJS) {
					confidence += pattern.Confidence
					matches++
				}
			}
		}

		// Need multiple matches to confirm
		if matches >= 2 && confidence > bestConfidence {
			bestConfidence = confidence
			bestVersion = version
		}
	}

	// If we have a major version, try to find specific version
	if bestVersion != "" {
		result.MajorVersion = bestVersion
		result.Confidence = math.Min(bestConfidence, 0.9) // Cap at 0.9 for static detection

		// Look for specific version patterns
		versionSig := signaturesDB.VersionPatterns[bestVersion]
		for specificVersion, sig := range versionSig.SpecificVersion {
			for _, pattern := range sig.Patterns {
				re := regexp.MustCompile(pattern.Pattern)
				if re.MatchString(allJS) {
					result.SpecificVersion = specificVersion
					result.Confidence = pattern.Confidence
					result.Vulnerabilities = sig.Vulnerabilities
					break
				}
			}
			if result.SpecificVersion != "" {
				break
			}
		}

		// If no specific version found but we have a major version
		if result.SpecificVersion == "" && result.MajorVersion != "" {
			// Determine vulnerabilities based on detected version
			determineVulnerabilities(&result)
		}
	}

	return result
}

// detectFromDOMStructure analyzes HTML DOM for version-specific patterns
func detectFromDOMStructure(html string) DetectionResult {
	result := DetectionResult{
		Confidence: 0.0,
	}

	// Reader for HTML parsing
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return result
	}

	// Track the best match
	bestConfidence := 0.0
	bestVersion := ""

	// Check DOM elements for version indicators
	for version, sig := range signaturesDB.VersionPatterns {
		confidence := 0.0
		matches := 0

		for _, pattern := range sig.DomPatterns {
			if pattern.Type == "html" {
				// Strip the leading "." or "#" for selector
				selector := pattern.Pattern
				if strings.HasPrefix(selector, ".") || strings.HasPrefix(selector, "#") {
					selector = pattern.Pattern
				}

				if doc.Find(selector).Length() > 0 {
					confidence += pattern.Confidence
					matches++
				}
			}
		}

		// Need multiple matches for confidence
		if matches >= 2 && confidence > bestConfidence {
			bestConfidence = confidence
			bestVersion = version
		}
	}

	if bestVersion != "" {
		result.MajorVersion = bestVersion
		result.Confidence = math.Min(bestConfidence, 0.8) // Cap confidence for DOM detection

		// Determine vulnerabilities based on detected version
		determineVulnerabilities(&result)
	}

	return result
}

// detectFromAssetFilenames looks for version info in asset filenames
func detectFromAssetFilenames(html string) DetectionResult {
	result := DetectionResult{
		Confidence: 0.0,
	}

	// Parse HTML document
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return result
	}

	// Patterns to check in filenames
	versionPatterns := map[string]struct {
		pattern    *regexp.Regexp
		version    string
		confidence float64
	}{
		"1.x": {
			pattern:    regexp.MustCompile(`swagger-ui-?v?1\.[0-9.]+`),
			version:    "1.x",
			confidence: 0.7,
		},
		"2.x": {
			pattern:    regexp.MustCompile(`swagger-ui-?v?2\.[0-9.]+`),
			version:    "2.x",
			confidence: 0.7,
		},
		"3.x": {
			pattern:    regexp.MustCompile(`swagger-ui-?v?3\.[0-9.]+`),
			version:    "3.x",
			confidence: 0.7,
		},
		"4.x": {
			pattern:    regexp.MustCompile(`swagger-ui-?v?4\.[0-9.]+`),
			version:    "4.x",
			confidence: 0.7,
		},
		"5.x": {
			pattern:    regexp.MustCompile(`swagger-ui-?v?5\.[0-9.]+`),
			version:    "5.x",
			confidence: 0.7,
		},
	}

	// Extract potential version from specific version pattern
	specificVersionPattern := regexp.MustCompile(`swagger-ui-?v?([0-9]+\.[0-9]+\.[0-9]+)`)

	// Check script tags
	doc.Find("script[src], link[href]").Each(func(i int, s *goquery.Selection) {
		var src string
		var exists bool

		if s.Is("script") {
			src, exists = s.Attr("src")
		} else if s.Is("link") {
			src, exists = s.Attr("href")
		}

		if exists {
			// Check for major version patterns
			for _, vInfo := range versionPatterns {
				if vInfo.pattern.MatchString(src) {
					if vInfo.confidence > result.Confidence {
						result.MajorVersion = vInfo.version
						result.Confidence = vInfo.confidence

						// Try to extract specific version
						matches := specificVersionPattern.FindStringSubmatch(src)
						if len(matches) > 1 {
							result.SpecificVersion = matches[1]
							result.Confidence += 0.1 // Slight confidence boost for specific version
						}

						// Determine vulnerabilities based on detected version
						determineVulnerabilities(&result)
					}
				}
			}
		}
	})

	return result
}

func main() {
	banner := `
Swagger UI Version Detector and Vulnerability Scanner                                                                                         
   ____ _____        ____ _      ______        ______      ______ _____ _____ ____  _____
  / __ -/ __ \______/ __ \ | /| / / __ \______/ ___/ | /| / / __ -/ __ -/ __ -/ _ \/ ___/
 / /_/ / /_/ /_____/ /_/ / |/ |/ / / / /_____(__  )| |/ |/ / /_/ / /_/ / /_/ /  __/ /    
 \__- /\____/     / -___/|__/|__/_/ /_/     /____/ |__/|__/\__-_/\__- /\__- /\___/_/     
/____/           /_/                                            /____//____/             
~ Made with ❤️ by Abhinandan-Khurana (@l0u51f3r007)				v1.0.1
`

	// Parse command-line flags
	urlFlag := flag.String("url", "", "URL to scan for Swagger UI")
	fileFlag := flag.String("file", "", "File containing URLs to scan, one per line")
	outputFlag := flag.String("output", "", "Output file for results (JSON format)")
	concurrencyFlag := flag.Int("concurrency", 5, "Number of concurrent scans")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	// Validate flags
	if *urlFlag == "" && *fileFlag == "" {
		color.New(color.FgCyan, color.Bold).Println(banner)
		color.New(color.FgRed).Println("Error: Either -url or -file must be specified")
		flag.Usage()
		os.Exit(1)
	}

	// Prepare URLs to scan
	var urls []string
	if *urlFlag != "" {
		urls = append(urls, *urlFlag)
	}

	if *fileFlag != "" {
		file, err := os.Open(*fileFlag)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
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
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}
	}

	color.New(color.FgCyan, color.Bold).Println(banner)
	color.New(color.FgYellow).Println("====================================================")
	color.New(color.FgGreen, color.Bold).Printf("Scanning %d URLs with concurrency level %d\n\n", len(urls), *concurrencyFlag)

	var wg sync.WaitGroup
	resultsChan := make(chan DetectionResult, len(urls))
	semaphore := make(chan struct{}, *concurrencyFlag)

	// Start scans
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if *verboseFlag {
				color.New(color.FgHiYellow).Printf("[i] Scanning %s...\n", url)
			}

			result := detectSwaggerVersionComprehensive(url)
			resultsChan <- result

			if *verboseFlag {
				if result.Error != "" {
					color.New(color.FgYellow).Printf("[i] Error scanning %s: %s\n", url, result.Error)
				} else {
					fmt.Printf("[i] Detected %s version %s (confidence: %.2f) for %s\n",
						result.MajorVersion, result.SpecificVersion, result.Confidence, url)
					if len(result.Vulnerabilities) > 0 {
						fmt.Println(" [i] Potential vulnerabilities:")
						for _, vuln := range result.Vulnerabilities {
							fmt.Printf("    - %s\n", vuln)
						}
					}
				}
			}
		}(url)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []DetectionResult
	for result := range resultsChan {
		results = append(results, result)
	}

	if *outputFlag != "" {
		resultJSON, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			color.New(color.FgRed, color.Bold).Printf("Error encoding results: %v\n", err)
			os.Exit(1)
		}

		err = ioutil.WriteFile(*outputFlag, resultJSON, 0644)
		if err != nil {
			color.New(color.FgRed, color.Bold).Printf("Error writing to output file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Results written to %s\n", *outputFlag)
	} else {
		// Print to stdout
		for _, result := range results {
			color.New(color.FgHiBlue, color.Bold).Printf("URL: %s\n", result.URL)
			if result.Error != "" {
				color.New(color.FgRed, color.Bold).Printf("  Error: %s\n", result.Error)
				continue
			}

			fmt.Printf("  Major Version: %s\n", result.MajorVersion)
			if result.SpecificVersion != "" {
				color.New(color.FgGreen).Printf("  Specific Version: %s\n", result.SpecificVersion)
			}
			color.New(color.FgYellow).Printf("  Confidence: %.2f\n", result.Confidence)
			color.New(color.FgBlue).Printf("  Detection Method: %s\n", result.DetectionMethod)

			if len(result.Vulnerabilities) > 0 {
				color.New(color.FgHiRed, color.Bold).Println("  Potential Vulnerabilities:")
				for _, vuln := range result.Vulnerabilities {
					fmt.Printf("    - %s\n", vuln)
				}
			}
			fmt.Println()
		}
	}

	fmt.Println("====================================================")
	color.New(color.FgHiGreen, color.Bold).Println("\nScan completed!")
	color.New(color.FgRed, color.Bold).Println("Remember to verify findings manually before making security decisions.")
	fmt.Println("Swagger UI version detection is based on heuristics and may not be 100% accurate.")
}
