package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Configurable timeouts
const (
	HttpTimeout       = 8 * time.Second
	ScannerTimeout    = 20 * time.Minute // increased to 20m
	DefaultUserAgent  = "Mozilla/5.0 (X11; Linux) CMS-Detector-Go/1.0"
	MaxBodySnippetLen = 20000
)

// Supported scanners list (order matters for output)
var supportedScanners = []string{
	"joomla", "wordpress", "drupal", "silverstripe", "typo3", "aem",
	"vbscan", "moodle", "oscommerce", "coldfusion", "jboss", "oracle_e_business",
	"phpbb", "php_nuke", "dotnetnuke", "umbraco", "prestashop", "opencart",
	"magento",
}

// fingerprint patterns to search in response body/headers
var techFingerprints = map[string][]string{
	"wordpress":         {"wp-content", "wp-includes", "wordpress", "/xmlrpc.php", "wp-login.php"},
	"joomla":            {"joomla!", "index.php?option=com_", "/components/com_", "/administrator/"},
	"drupal":            {"drupal.settings", "sites/all/", "drupal.js", "powered by drupal", "/user/login"},
	"silverstripe":      {"silverstripe", "data-silverstripe", "ss-assets"},
	"typo3":             {"typo3", "typo3temp", "index.php?id="},
	"aem":               {"cq-editor", "adobe experience manager", "/etc/clientlibs/"},
	"vbscan":            {"vbulletin", "vbseo", "/vb/"},
	"moodle":            {"moodle", "lib/javascript.php", "/login/index.php"},
	"oscommerce":        {"oscommerce", "catalog", "oscommerce"},
	"coldfusion":        {"cfide", "coldfusion", "cfusion"},
	"jboss":             {"jboss", "jmx-console", "jbossweb"},
	"oracle_e_business": {"oracle e-business", "apps/", "forms/frmservlet"},
	"phpbb":             {"phpbb", "/viewtopic.php", "/download/file.php"},
	"php_nuke":          {"php-nuke", "pnphpbb2"},
	"dotnetnuke":        {"dotnetnuke", "dnn_", "dnnservicestack"},
	"umbraco":           {"umbraco", "umbracoclient"},
	"prestashop":        {"prestashop", "/modules/", "product-page"},
	"opencart":          {"opencart", "index.php?route=product/"},
	"magento":           {"mage.cookies", "mage/", "/skin/frontend/"},
}

// common paths to HEAD-check for extra confidence
var commonPaths = map[string][]string{
	"wordpress": {"/wp-admin/", "/wp-login.php", "/wp-content/"},
	"joomla":    {"/administrator/", "/images/"},
	"drupal":    {"/user/login", "/sites/default/"},
	"magento":   {"/skin/", "/js/"},
}

// Command mapping for scanners (scanner -> command template)
// In command template, %s will be replaced only for tokens exactly equal to "%s".
var scannerCommands = map[string][]string{
	"joomla":    {"joomscan", "--url", "%s"},
	"wordpress": {"wpscan", "--url", "%s", "--disable-tls-checks", "--random-user-agent"},
	// droopescan handles drupal and silverstripe
	"drupal":       {"droopescan", "scan", "drupal", "-u", "%s"},
	"silverstripe": {"droopescan", "scan", "silverstripe", "-u", "%s"},
	// Magento using PHAR in current directory
	"magento": {"php", "magescan.phar", "scan:all", "%s"},
}

var (
	flagURL             = flag.String("u", "", "Single URL to scan")
	flagInput           = flag.String("i", "", "File containing URLs (one per line)")
	flagVerbose         = flag.Bool("v", false, "Verbose mode (print scanner output)")
	flagOutput          = flag.String("o", "text", "Output format: text or html (kept for compatibility)")
	flagNoVerifySSL     = flag.Bool("no-verify-ssl", false, "Do not verify SSL certificates for HTTP probes")
	flagConcurrency     = flag.Int("concurrency", 2, "Number of concurrent target scans")
	flagScanConcurrency = flag.Int("scan-concurrency", 2, "Number of concurrent scanner processes *per target*")
	// new: group/subfolder name
	flagGroup = flag.String("group", "default", "Group name (subfolder under outputs/) to store results, e.g. 'apple' or 'microsoft'")
)

func main() {
	flag.Parse()

	if *flagURL == "" && *flagInput == "" {
		fmt.Println("Either -u <url> or -i <file> must be provided.")
		flag.Usage()
		os.Exit(1)
	}

	urls := []string{}
	if *flagURL != "" {
		urls = append(urls, *flagURL)
	} else {
		f, err := os.Open(*flagInput)
		if err != nil {
			log.Fatalf("failed to open input file: %v", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				urls = append(urls, line)
			}
		}
		if scanner.Err() != nil {
			log.Fatalf("reading input file: %v", scanner.Err())
		}
	}

	// Create root outputs dir and group subdir
	rootOut := "outputs"
	groupOut := filepath.Join(rootOut, *flagGroup)
	if err := os.MkdirAll(groupOut, 0755); err != nil {
		log.Fatalf("failed to create outputs directory: %v", err)
	}

	// Prepare channel for results; we will collect per-url combined output
	type resultItem struct {
		URL    string
		Output string
	}
	resultsCh := make(chan resultItem, len(urls))

	// Worker pool for concurrency (targets)
	sem := make(chan struct{}, *flagConcurrency)
	var wg sync.WaitGroup

	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			combined := processTarget(target, *flagNoVerifySSL, *flagVerbose, *flagOutput, groupOut, *flagScanConcurrency)
			// send the combined output for summary writing
			resultsCh <- resultItem{URL: target, Output: combined}
		}(u)
	}

	wg.Wait()
	close(resultsCh)

	// Collect results into a map for ordered writing
	resultsMap := make(map[string]string, len(urls))
	for r := range resultsCh {
		resultsMap[r.URL] = r.Output
	}

	// Write single summary.txt in group folder with numbered entries in original order
	summaryPath := filepath.Join(groupOut, "summary.txt")
	sf, err := os.Create(summaryPath)
	if err != nil {
		log.Fatalf("failed to create summary file: %v", err)
	}
	defer sf.Close()

	for idx, u := range urls {
		fmt.Fprintf(sf, "%d. %s\n\n", idx+1, u)
		combined, ok := resultsMap[u]
		if ok && combined != "" {
			// write the combined output
			sf.WriteString(combined)
			// ensure trailing newline
			if !strings.HasSuffix(combined, "\n") {
				sf.WriteString("\n")
			}
		} else {
			sf.WriteString("[no output captured]\n")
		}
		sf.WriteString("\n")
	}

	fmt.Printf("\nSummary written: %s\n", summaryPath)
	fmt.Println("\n✅ Done.")
}

// processTarget: detect technologies and run scanners for detected ones
// now runs per-site scanners in parallel (bounded by scanConcurrency)
func processTarget(url string, noVerify bool, verbose bool, outFormat string, groupOut string, scanConcurrency int) string {
	var combinedAll bytes.Buffer
	var mu sync.Mutex // protects combinedAll

	fmt.Printf("\n=== Target: %s ===\n", url)
	combinedAll.WriteString(fmt.Sprintf("=== Target: %s ===\n", url))

	techs := detectTechnologiesHTTPOnly(url, noVerify)
	if len(techs) == 0 {
		msg := fmt.Sprintf("No CMS/tech confidently detected via HTTP probes for %s. Skipping.\n", url)
		fmt.Print(msg)
		combinedAll.WriteString(msg + "\n")
		return combinedAll.String()
	}
	detectedLine := fmt.Sprintf("Technologies detected: %s\n", strings.Join(techs, ", "))
	fmt.Print(detectedLine)
	combinedAll.WriteString(detectedLine + "\n")

	safe := safeNameFromURL(url)

	// Per-target semaphore to limit concurrent scanners for this site
	if scanConcurrency < 1 {
		scanConcurrency = 1
	}
	siteSem := make(chan struct{}, scanConcurrency)
	var wg sync.WaitGroup

	for _, tech := range techs {
		wg.Add(1)
		siteSem <- struct{}{}
		// capture vars for goroutine
		t := tech
		outTxt := filepath.Join(groupOut, fmt.Sprintf("scan_output_%s_%s.txt", safe, t))

		go func(techName, outPath string) {
			defer wg.Done()
			defer func() { <-siteSem }()

			header := fmt.Sprintf("\n--- Running %s scanner on %s ---\n", techName, url)
			fmt.Print(header)
			// add header to combinedAll
			mu.Lock()
			combinedAll.WriteString(header)
			mu.Unlock()

			formatted := runScanner(url, techName, outPath, noVerify, verbose)

			if formatted == "" {
				msg := fmt.Sprintf("%s scanner returned no output (skipped or failed).\n", techName)
				fmt.Print(msg)
				mu.Lock()
				combinedAll.WriteString(msg + "\n")
				mu.Unlock()
				_ = os.WriteFile(outPath, []byte(msg), 0644)
				return
			}

			// Build the block to append
			var block bytes.Buffer
			sep := fmt.Sprintf("----- %s output for %s -----\n", strings.ToUpper(techName), url)
			block.WriteString(sep)
			block.WriteString(formatted)
			if !strings.HasSuffix(formatted, "\n") {
				block.WriteString("\n")
			}
			block.WriteString(strings.Repeat("-", 60) + "\n\n")

			// append to combinedAll
			mu.Lock()
			combinedAll.Write(block.Bytes())
			mu.Unlock()

			// Optionally write HTML
			if outFormat == "html" {
				htmlPath := filepath.Join(groupOut, fmt.Sprintf("scan_output_%s_%s.html", safe, techName))
				if err := writeHTMLReport(htmlPath, url, techName, formatted); err != nil {
					log.Printf("failed to write html report: %v", err)
				} else {
					fmt.Printf("HTML report saved: %s\n", htmlPath)
				}
			} else {
				fmt.Printf("Results saved: %s\n", outPath)
			}
		}(t, outTxt)
	}

	// wait for all per-site scanners to finish
	wg.Wait()

	return combinedAll.String()
}

// safeNameFromURL creates a filesystem-safe name
func safeNameFromURL(url string) string {
	// remove scheme then replace non-alnum with _
	re := regexp.MustCompile(`^https?://`)
	s := re.ReplaceAllString(url, "")
	s = strings.TrimSuffix(s, "/")
	s = regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(s, "_")
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// detectTechnologiesHTTPOnly uses HTTP probes to detect possible CMS/tech
func detectTechnologiesHTTPOnly(url string, noVerify bool) []string {
	detected := map[string]bool{}

	// 1) quick GET fetch
	client := &http.Client{
		Timeout: HttpTimeout,
	}
	if noVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
		client.Transport = tr
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", DefaultUserAgent)
	resp, err := client.Do(req)
	var bodySnippet string
	var headersJoined string
	if err == nil {
		defer resp.Body.Close()
		headersJoined = headersToString(resp.Header)
		// read a limited amount of body
		buf := new(bytes.Buffer)
		n, _ := io.CopyN(buf, resp.Body, MaxBodySnippetLen)
		if n > 0 {
			bodySnippet = buf.String()
		}
	} else {
		// If GET failed, still try to probe with HEAD for common paths
		log.Printf("HTTP GET failed for %s: %v", url, err)
	}

	combined := strings.ToLower(headersJoined + "\n" + bodySnippet)

	// 2) match fingerprints
	for tech, pats := range techFingerprints {
		for _, p := range pats {
			if strings.Contains(combined, strings.ToLower(p)) {
				detected[tech] = true
				break
			}
		}
	}

	// 3) HEAD probe common paths when not detected yet
	for tech, paths := range commonPaths {
		if detected[tech] {
			continue
		}
		for _, p := range paths {
			headURL := strings.TrimRight(url, "/") + p
			ok := headProbe(headURL, client)
			if ok {
				detected[tech] = true
				break
			}
		}
	}

	// preserve supportedScanners order
	out := []string{}
	for _, s := range supportedScanners {
		if detected[s] {
			out = append(out, s)
		}
	}
	return out
}

func headersToString(h http.Header) string {
	var b strings.Builder
	for k, vals := range h {
		for _, v := range vals {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func headProbe(url string, client *http.Client) bool {
	req, _ := http.NewRequest("HEAD", url, nil)
	req.Header.Set("User-Agent", DefaultUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 403 {
		return true
	}
	return false
}

// runScanner executes the external scanner command (if configured) and returns combined stdout+stderr
func runScanner(url, cms, outFile string, noVerify, verbose bool) string {
	// map cms to command template
	cmdT, ok := scannerCommands[cms]
	if !ok {
		note := fmt.Sprintf("No dedicated scanner implemented for %s; skipping.\n", cms)
		log.Print(note)
		_ = os.WriteFile(outFile, []byte(note), 0644)
		return ""
	}

	// substitute URL only in placeholders (not in executable name)
	cmd := make([]string, len(cmdT))
	for i, s := range cmdT {
		if s == "%s" {
			cmd[i] = url
		} else {
			cmd[i] = s
		}
	}

	// verify exe exists
	exe := cmd[0]
	args := []string{}
	if len(cmd) > 1 {
		args = cmd[1:]
	}

	log.Printf("Attempting to execute scanner for %s: %s %v", cms, exe, args)

	if _, err := exec.LookPath(exe); err != nil {
		note := fmt.Sprintf("scanner executable not found in PATH: %s (skipping).\n", exe)
		log.Print(note)
		_ = os.WriteFile(outFile, []byte(note), 0644)
		return ""
	}

	// prepare command with context timeout
	ctx, cancel := context.WithTimeout(context.Background(), ScannerTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, exe, args...)
	c.Env = os.Environ()

	// capture stdout+stderr
	var combined bytes.Buffer
	stdoutPipe, err := c.StdoutPipe()
	if err != nil {
		errMsg := fmt.Sprintf("failed to get stdout pipe: %v\n", err)
		log.Print(errMsg)
		_ = os.WriteFile(outFile, []byte(errMsg), 0644)
		return ""
	}
	c.Stderr = c.Stdout

	// start
	if err := c.Start(); err != nil {
		errMsg := fmt.Sprintf("failed to start scanner %s: %v\n", exe, err)
		log.Print(errMsg)
		_ = os.WriteFile(outFile, []byte(errMsg), 0644)
		return ""
	}

	// stream and capture
	multi := io.MultiWriter(&combined)
	if verbose {
		multi = io.MultiWriter(&combined, os.Stdout)
	}
	_, copyErr := io.Copy(multi, stdoutPipe)
	if copyErr != nil && copyErr != io.EOF {
		log.Printf("error while reading scanner output: %v", copyErr)
	}

	// wait
	waitErr := c.Wait()

	// write whatever we captured
	finalOut := combined.String()
	footer := ""
	if waitErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			footer = fmt.Sprintf("\n--- scanner timed out after %v ---\n", ScannerTimeout)
			log.Printf("scanner timed out for %s", url)
		} else {
			footer = fmt.Sprintf("\n--- scanner finished with error: %v ---\n", waitErr)
			log.Printf("scanner finished with error: %v", waitErr)
		}
		finalOut = finalOut + footer
	}

	if err := os.WriteFile(outFile, []byte(finalOut), 0644); err != nil {
		log.Printf("failed to write scanner output to %s: %v", outFile, err)
	} else {
		log.Printf("scanner output written to %s (bytes: %d)", outFile, len(finalOut))
	}

	return finalOut
}

func writeHTMLReport(path, url, cms, results string) error {
	type R struct {
		URL     string
		CMS     string
		Date    string
		Results template.HTML
	}
	tmpl := `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Scan Report for {{.URL}}</title></head>
<body>
  <h1>Scan Results for {{.URL}} ({{.CMS}})</h1>
  <p><em>Scan date: {{.Date}}</em></p>
  <h2>Results</h2>
  <pre style="white-space:pre-wrap;word-wrap:break-word;">{{.Results}}</pre>
</body>
</html>`
	data := R{URL: url, CMS: cms, Date: time.Now().Format(time.RFC3339), Results: template.HTML(template.HTMLEscapeString(results))}
	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, data)
}
