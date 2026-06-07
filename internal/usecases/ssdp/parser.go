package ssdp

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

// ParseSSDPRequest extracts the relevant headers from an M-SEARCH request.
//
// SSDP is intentionally permissive: real attackers send malformed variants
// frequently (per Griffioen et al. §5.4, only 67% of attack requests are
// canonical). We accept anything starting with "M-SEARCH" and try to extract
// headers; missing headers are returned as empty strings.
func ParseSSDPRequest(data []byte) (*models.SSDPQuery, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("ssdp packet empty")
	}

	text := string(data)
	if !strings.HasPrefix(text, "M-SEARCH ") {
		return nil, fmt.Errorf("not an M-SEARCH request")
	}

	q := &models.SSDPQuery{
		Method:  "M-SEARCH",
		RawSize: len(data),
	}

	scanner := bufio.NewScanner(strings.NewReader(text))
	first := true
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if first {
			first = false
			continue // skip request line
		}
		if line == "" {
			break // end of headers
		}
		colon := strings.Index(line, ":")
		if colon == -1 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		val = strings.Trim(val, `"`)

		switch key {
		case "HOST":
			q.Host = val
		case "MAN":
			q.MAN = val
		case "MX":
			q.MX = val
		case "ST":
			q.ST = val
		}
	}

	return q, nil
}

// IsAmplificationProbe returns true if this looks like a discovery probe
// rather than miscellaneous UPnP traffic. We use this to filter out noise.
func IsAmplificationProbe(q *models.SSDPQuery) bool {
	return strings.Contains(strings.ToLower(q.MAN), "ssdp:discover")
}
