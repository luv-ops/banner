// Package fingerprint implements the banner recognition engine.
//
// The engine inspects a raw banner string (optionally aided by a port hint)
// and produces a FingerprintResult. It never panics: any unrecognized banner
// is reported as protocol "unknown" with a low confidence rather than an error.
package fingerprint

import (
	"regexp"
	"strings"

	"github.com/example/banner/internal/models"
)

// Engine performs banner recognition.
// It is stateless and safe for concurrent use.
type Engine struct{}

// New returns an Engine instance.
func New() *Engine { return &Engine{} }

// Recognize inspects a single raw banner record.
func (e *Engine) Recognize(r models.RawBanner) models.FingerprintResult {
	banner := strings.TrimSpace(r.Banner)
	if banner == "" {
		return unknownResult(r, 0)
	}

	// Order matters: the most specific signatures are checked first.
	switch {
	case isSSH(banner):
		return e.recognSSH(r, banner)
	case isHTTP(banner):
		return e.recognHTTP(r, banner)
	case isFTP(banner, r.Port):
		return e.recognFTP(r, banner)
	case isRedis(banner, r.Port):
		return e.recognRedis(r, banner)
	case isMySQL(banner, r.Port):
		return e.recognMySQL(r, banner)
	default:
		return unknownResult(r, 0.2)
	}
}

// RecognizeBatch recognizes a slice of records.
func (e *Engine) RecognizeBatch(records []models.RawBanner) []models.FingerprintResult {
	results := make([]models.FingerprintResult, 0, len(records))
	for _, r := range records {
		results = append(results, e.Recognize(r))
	}
	return results
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

var sshRe = regexp.MustCompile(`^SSH-(?P<protoVer>\d+\.\d+)-(?P<product>[^_\s]+)(?:_(?P<version>\S+))?(?:\s+(?P<os>.+))?$`)

func isSSH(banner string) bool { return strings.HasPrefix(banner, "SSH-") }

func (e *Engine) recognSSH(r models.RawBanner, banner string) models.FingerprintResult {
	out := models.FingerprintResult{IP: r.IP, Port: r.Port, Protocol: "SSH", Confidence: 0.95}
	m := sshRe.FindStringSubmatch(banner)
	if m == nil {
		out.Product = "SSH"
		out.Confidence = 0.6
		return out
	}
	out.Product = m[2]
	out.Version = m[3]
	if m[4] != "" {
		out.OSHint = parseSSHOS(m[4])
	}
	return out
}

// parseSSHOS extracts an OS hint from an SSH banner tail like "Ubuntu-3".
func parseSSHOS(tail string) string {
	// e.g. "Ubuntu-3" -> "Ubuntu"; "FreeBSD-20220614" -> "FreeBSD"
	if idx := strings.Index(tail, "-"); idx > 0 {
		return tail[:idx]
	}
	return tail
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

var (
	httpServerRe = regexp.MustCompile(`(?im)^[ \t]*Server:[ \t]*(?P<value>.+?)\r?$`)
	httpStatusRe = regexp.MustCompile(`^HTTP/(?P<ver>\d(?:\.\d)?)\s+\d{3}`)
	serverVerRe  = regexp.MustCompile(`^(?P<product>[^/\s()]+)(?:/(?P<version>[^\s)]+))?`)
	jettyRe      = regexp.MustCompile(`(?i)^Jetty(?:\((?P<version>[^)]+)\))?`)
)

func isHTTP(banner string) bool {
	// Treat the banner as HTTP if it carries an HTTP status line or a Server header.
	return httpStatusRe.MatchString(banner) || strings.Contains(strings.ToLower(banner), "server:")
}

func (e *Engine) recognHTTP(r models.RawBanner, banner string) models.FingerprintResult {
	out := models.FingerprintResult{IP: r.IP, Port: r.Port, Protocol: "HTTP", Confidence: 0.9}
	value := extractServerHeader(banner)
	if value == "" {
		// HTTP response without a Server header: we can still tell it's HTTP.
		out.Product = ""
		out.Confidence = 0.6
		return out
	}

	// Jetty uses the "Jetty(<version>)" convention.
	if j := jettyRe.FindStringSubmatch(value); j != nil {
		out.Product = "Jetty"
		out.Version = j[1]
		out.OSHint = httpOSHint(value)
		return out
	}

	if sv := serverVerRe.FindStringSubmatch(value); sv != nil {
		out.Product = normalizeHTTPProduct(sv[1])
		out.Version = stripTrailing(sv[2])
		out.OSHint = httpOSHint(value)
	}
	return out
}

func extractServerHeader(banner string) string {
	m := httpServerRe.FindStringSubmatch(banner)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func normalizeHTTPProduct(p string) string {
	switch strings.ToLower(p) {
	case "nginx":
		return "nginx"
	case "apache", "apachecoyote":
		return "Apache"
	default:
		// Preserve original casing (e.g. "Apache" vs "nginx").
		if strings.EqualFold(p, "nginx") {
			return "nginx"
		}
		return p
	}
}

// httpOSHint inspects the Server header for platform tokens (Win32, Unix, Debian...).
func httpOSHint(serverValue string) string {
	lower := strings.ToLower(serverValue)
	switch {
	case strings.Contains(lower, "win32") || strings.Contains(lower, "windows"):
		return "Windows"
	case strings.Contains(lower, "unix"):
		return "Unix"
	case strings.Contains(lower, "debian"):
		return "Debian"
	case strings.Contains(lower, "ubuntu"):
		return "Ubuntu"
	}
	return ""
}

func stripTrailing(s string) string {
	s = strings.TrimSpace(s)
	// Drop trailing junk after a space/paren, e.g. "2.4.57 (Win32)" -> "2.4.57"
	for _, sep := range []string{" ", "(", ";"} {
		if i := strings.Index(s, sep); i > 0 {
			s = s[:i]
		}
	}
	return s
}

// ---------------------------------------------------------------------------
// FTP
// ---------------------------------------------------------------------------

var (
	ftpCodeRe   = regexp.MustCompile(`^(?P<code>\d{3})([-\s])`)
	ftpProftpdRe = regexp.MustCompile(`(?i)ProFTPD[/\s]*(?P<ver>[\d.]+)?`)
	ftpVsftpdRe  = regexp.MustCompile(`(?i)vsFTPd[/\s]*(?P<ver>[\d.]+)?`)
	ftpFilezillaRe = regexp.MustCompile(`(?i)FileZilla(?:\s+Server)?[/\s]*(?P<ver>[\d.]+)?`)
	ftpPureftpdRe = regexp.MustCompile(`(?i)Pure-?FTPd[/\s]*(?P<ver>[\d.]+)?`)
)

func isFTP(banner string, port int) bool {
	if !ftpCodeRe.MatchString(banner) {
		return false
	}
	// 220 is the FTP "service ready" greeting; 21x codes are also FTP-only.
	code := banner[:3]
	if code == "220" || code == "212" || code == "213" || code == "214" {
		// Strong signal already; also accept when port==21 even with other 2xx.
		return true
	}
	if port == 21 && strings.HasPrefix(code, "2") {
		return true
	}
	return false
}

func (e *Engine) recognFTP(r models.RawBanner, banner string) models.FingerprintResult {
	out := models.FingerprintResult{IP: r.IP, Port: r.Port, Protocol: "FTP", Confidence: 0.9}
	if m := ftpProftpdRe.FindStringSubmatch(banner); m != nil {
		out.Product = "ProFTPD"
		out.Version = m[1]
	} else if m := ftpVsftpdRe.FindStringSubmatch(banner); m != nil {
		out.Product = "vsftpd"
		out.Version = m[1]
	} else if m := ftpFilezillaRe.FindStringSubmatch(banner); m != nil {
		out.Product = "FileZilla Server"
		out.Version = m[1]
	} else if m := ftpPureftpdRe.FindStringSubmatch(banner); m != nil {
		out.Product = "Pure-FTPd"
		out.Version = m[1]
	} else {
		out.Product = "FTP"
		out.Confidence = 0.6
	}
	return out
}

// ---------------------------------------------------------------------------
// MySQL
// ---------------------------------------------------------------------------

var (
	mysqlVerRe   = regexp.MustCompile(`^(?P<version>\d+\.\d+\.\d+)(?P<rest>[^\s]*)`)
	mysqlAuthRe  = regexp.MustCompile(`(?i)mysql`)
)

func isMySQL(banner string, port int) bool {
	if port == 3306 && mysqlVerRe.MatchString(banner) {
		return true
	}
	if mysqlAuthRe.MatchString(banner) {
		return true
	}
	return false
}

func (e *Engine) recognMySQL(r models.RawBanner, banner string) models.FingerprintResult {
	out := models.FingerprintResult{IP: r.IP, Port: r.Port, Protocol: "MySQL", Product: "MySQL", Confidence: 0.9}
	if m := mysqlVerRe.FindStringSubmatch(banner); m != nil {
		out.Version = m[1]
		out.OSHint = mysqlOSHint(m[2])
	}
	// Without a parseable version we are less sure.
	if out.Version == "" {
		out.Confidence = 0.7
	}
	return out
}

// mysqlOSHint inspects the suffix after the version for distribution tokens,
// e.g. "8.0.32-0ubuntu0.20.04.2" -> "Ubuntu".
func mysqlOSHint(suffix string) string {
	lower := strings.ToLower(suffix)
	switch {
	case strings.Contains(lower, "ubuntu"):
		return "Ubuntu"
	case strings.Contains(lower, "debian"):
		return "Debian"
	case strings.Contains(lower, "rhel") || strings.Contains(lower, "el"):
		return "RHEL"
	case strings.Contains(lower, "win"):
		return "Windows"
	case strings.Contains(lower, "freebsd"):
		return "FreeBSD"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Redis
// ---------------------------------------------------------------------------

func isRedis(banner string, port int) bool {
	// Redis replies start with one of: + - : * $ (inline/status/error/int/multi/bulk).
	if port == 6379 && (strings.HasPrefix(banner, "-") || strings.HasPrefix(banner, "+") ||
		strings.HasPrefix(banner, "*") || strings.HasPrefix(banner, "$") || strings.HasPrefix(banner, ":")) {
		return true
	}
	if strings.Contains(strings.ToLower(banner), "redis") {
		return true
	}
	return false
}

var redisVerRe = regexp.MustCompile(`(?i)redis[\s/v]*(?P<ver>\d+\.\d+(?:\.\d+)?)`)

func (e *Engine) recognRedis(r models.RawBanner, banner string) models.FingerprintResult {
	out := models.FingerprintResult{IP: r.IP, Port: r.Port, Protocol: "Redis", Product: "Redis", Confidence: 0.7}
	if m := redisVerRe.FindStringSubmatch(banner); m != nil {
		out.Version = m[1]
		out.Confidence = 0.9
	}
	return out
}

// ---------------------------------------------------------------------------

func unknownResult(r models.RawBanner, confidence float64) models.FingerprintResult {
	return models.FingerprintResult{
		IP:         r.IP,
		Port:       r.Port,
		Protocol:   "unknown",
		Confidence: confidence,
	}
}


