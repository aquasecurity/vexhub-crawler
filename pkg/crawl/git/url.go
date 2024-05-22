package git

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeURL adjusts the given URL to a normalized form for hashicorp/go-getter.
func NormalizeURL(rawurl string) (*url.URL, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// Force the git protocol
	u.Scheme = "git::https"

	// Add .git suffix
	if !strings.HasSuffix(u.Path, ".git") {
		u.Path += ".git"
	}

	// Add depth=1 query parameter
	q := u.Query()
	q.Add("depth", "1")
	u.RawQuery = q.Encode()

	return u, nil
}
