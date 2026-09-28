// Command client reads a local JSON file of raw banners, posts them to the
// recognition server, and prints the identified results.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/example/banner/internal/models"
)

func main() {
	input := flag.String("input", "testdata/input.json", "path to a JSON file of raw banners")
	serverURL := flag.String("server", "http://localhost:8080", "base URL of the recognition server")
	out := flag.String("out", "", "optional path to write the JSON results")
	flag.Parse()

	records, err := loadInput(*input)
	if err != nil {
		log.Fatalf("load input %q: %v", *input, err)
	}
	fmt.Printf("loaded %d records from %s\n", len(records), *input)

	results, err := postRecords(*serverURL, records)
	if err != nil {
		log.Fatalf("post records: %v", err)
	}

	printTable(results)

	if *out != "" {
		if err := writeJSON(*out, results); err != nil {
			log.Fatalf("write out %q: %v", *out, err)
		}
		fmt.Printf("results written to %s\n", *out)
	}
}

// loadInput decodes a JSON array (or a {records:[...]} object) into RawBanner.
func loadInput(path string) ([]models.RawBanner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Try a bare array first (the documented input shape).
	var records []models.RawBanner
	if err := json.Unmarshal(data, &records); err == nil {
		return records, nil
	}
	// Fall back to a request-shaped object.
	var req models.FingerprintRequest
	if err := json.Unmarshal(data, &req); err == nil {
		return req.Records, nil
	}
	// Last resort: re-attempt the array error so the user sees a useful message.
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	return records, nil
}

func postRecords(baseURL string, records []models.RawBanner) ([]models.FingerprintResult, error) {
	body, err := json.Marshal(models.FingerprintRequest{Records: records})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := baseURL + "/fingerprint"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(raw))
	}

	var fr models.FingerprintResponse
	if err := json.Unmarshal(raw, &fr); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return fr.Results, nil
}

func printTable(results []models.FingerprintResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	fmt.Fprintln(w, "--\t----\t--------\t-------\t-------\t-------\t---------")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OSHint, r.Confidence)
	}
	w.Flush()
	fmt.Printf("\nrecognized %d records\n", len(results))
}

func writeJSON(path string, results []models.FingerprintResult) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
