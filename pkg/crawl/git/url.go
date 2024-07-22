package git

import (
	"net/url"
	"path"
	"strings"

	"github.com/samber/oops"
)

// NormalizeURL adjusts the given URL to a normalized form for hashicorp/go-getter.
func NormalizeURL(rawurl string) (*url.URL, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, oops.Code("normalize_url_error").In("git").With("url", rawurl).Wrapf(err, "failed to parse URL")
	}

	// Force the git protocol
	u.Scheme = "git::https"

	// GitHub specific
	if u.Host == "github.com" {
		normalizeGitHubURL(u)
	}

	// TODO: GitLab specific
	if u.Host == "gitlab.com" {
	}

	// Add .git suffix
	if !strings.HasSuffix(u.Path, ".git") && !strings.Contains(u.Path, "//") {
		u.Path += ".git"
	}

	// Add depth=1 query parameter
	q := u.Query()
	q.Add("depth", "1")
	u.RawQuery = q.Encode()

	return u, nil
}

func normalizeGitHubURL(u *url.URL) {
	// Split the path
	parts := strings.Split(u.Path, "/")

	// e.g. /<owner>/<repo>/tree/<ref>/<subpath1>/<subpath2>
	if len(parts) < 5 {
		return
	}

	if parts[3] == "tree" {
		ref := parts[4]

		// Add ref
		q := u.Query()
		q.Add("ref", ref)
		u.RawQuery = q.Encode()
	}

	if len(parts) < 6 {
		return
	}

	// Add subdirectories
	// cf. https://github.com/hashicorp/go-getter?tab=readme-ov-file#subdirectories
	u.Path = path.Join(parts[1], parts[2]) + ".git//" + path.Join(parts[5:]...)
}
