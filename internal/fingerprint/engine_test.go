package fingerprint

import (
	"testing"

	"github.com/example/banner/internal/models"
)

func TestRecognize(t *testing.T) {
	cases := []struct {
		name   string
		in     models.RawBanner
		want   models.FingerprintResult
	}{
		{
			name: "ssh_openssh_ubuntu",
			in:   models.RawBanner{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
			want: models.FingerprintResult{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
		},
		{
			name: "http_nginx",
			in:   models.RawBanner{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"},
			want: models.FingerprintResult{IP: "1.2.3.5", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		},
		{
			name: "http_apache",
			in:   models.RawBanner{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"},
			want: models.FingerprintResult{IP: "1.2.3.6", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.57", Confidence: 0.9},
		},
		{
			name: "mysql_8",
			in:   models.RawBanner{IP: "1.2.3.7", Port: 3306, Banner: "8.0.32-0ubuntu0.20.04.2"},
			want: models.FingerprintResult{IP: "1.2.3.7", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", OSHint: "Ubuntu", Confidence: 0.9},
		},
		{
			name: "redis_err",
			in:   models.RawBanner{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments"},
			want: models.FingerprintResult{IP: "1.2.3.8", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		},
		{
			name: "ftp_proftpd",
			in:   models.RawBanner{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"},
			want: models.FingerprintResult{IP: "1.2.3.9", Port: 21, Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", Confidence: 0.9},
		},
		{
			name: "http_jetty",
			in:   models.RawBanner{IP: "1.2.3.10", Port: 8443, Banner: "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.44.v20210927)"},
			want: models.FingerprintResult{IP: "1.2.3.10", Port: 8443, Protocol: "HTTP", Product: "Jetty", Version: "9.4.44.v20210927", Confidence: 0.9},
		},
		{
			name: "ftp_vsftpd",
			in:   models.RawBanner{IP: "1.2.3.11", Port: 21, Banner: "220 vsFTPd 3.0.3"},
			want: models.FingerprintResult{IP: "1.2.3.11", Port: 21, Protocol: "FTP", Product: "vsftpd", Version: "3.0.3", Confidence: 0.9},
		},
		{
			name: "unknown_garbage",
			in:   models.RawBanner{IP: "1.2.3.12", Port: 9999, Banner: "totally unknown garbage banner"},
			want: models.FingerprintResult{IP: "1.2.3.12", Port: 9999, Protocol: "unknown", Confidence: 0.2},
		},
		{
			name: "empty_banner",
			in:   models.RawBanner{IP: "1.2.3.13", Port: 22, Banner: ""},
			want: models.FingerprintResult{IP: "1.2.3.13", Port: 22, Protocol: "unknown", Confidence: 0},
		},
	}

	e := New()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := e.Recognize(c.in)
			if !resultEqual(got, c.want) {
				t.Errorf("\n  got  %+v\n  want %+v", got, c.want)
			}
		})
	}
}

func resultEqual(a, b models.FingerprintResult) bool {
	return a.IP == b.IP && a.Port == b.Port && a.Protocol == b.Protocol &&
		a.Product == b.Product && a.Version == b.Version && a.OSHint == b.OSHint &&
		a.Confidence == b.Confidence
}
