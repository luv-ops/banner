// Package models defines the data structures exchanged between client and server.
package models

// RawBanner is the raw scan record submitted by the client.
type RawBanner struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// FingerprintResult is the recognition output for a single raw banner.
type FingerprintResult struct {
	IP        string  `json:"ip"`
	Port      int     `json:"port"`
	Protocol  string  `json:"protocol"`
	Product   string  `json:"product"`
	Version   string  `json:"version"`
	OSHint    string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// FingerprintRequest is the body of POST /fingerprint.
type FingerprintRequest struct {
	Records []RawBanner `json:"records"`
}

// FingerprintResponse is what POST /fingerprint returns.
type FingerprintResponse struct {
	Results []FingerprintResult `json:"results"`
	Total   int                 `json:"total"`
}
