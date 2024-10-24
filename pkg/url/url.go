package url

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/samber/oops"
)

type URL struct {
	*url.URL
	depth   int
	ref     string
	subdirs string
}

// Parse parses rawurl into a URL structure.
func Parse(rawurl string) (*URL, error) {
	errBuilder := oops.Code("url_parse_error").In("url").With("url", rawurl)

	parsed, err := url.Parse(rawurl)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to parse URL")
	}
	u := &URL{
		URL:   parsed,
		depth: 1,
	}

	// GitHub specific
	if u.Host == "github.com" {
		parseGitHubURL(u)
	}

	// TODO: GitLab specific
	if u.Host == "gitlab.com" {
	}

	// Parse subdirectories: go-getter specific
	if before, after, found := strings.Cut(u.Path, "//"); found {
		u.Path = before
		u.subdirs = after
	}

	return u, nil
}

func parseGitHubURL(u *URL) {
	// Split the path
	parts := strings.Split(u.Path, "/")

	// e.g. /<owner>/<repo>/tree/<ref>/<subpath1>/<subpath2>
	if len(parts) < 5 {
		return
	}

	if parts[3] == "tree" {
		// Add ref
		u.ref = parts[4]
	}

	if len(parts) < 6 {
		return
	}

	// Add subdirectories
	// cf. https://github.com/hashicorp/go-getter?tab=readme-ov-file#subdirectories
	u.subdirs = path.Join(parts[5:]...)

	// Set organization/repository
	u.Path = path.Join(parts[1], parts[2])
}

func (u *URL) SetSubdirs(s string) {
	u.subdirs = s
}

func (u *URL) Subdirs() string {
	return u.subdirs
}

func (u *URL) String() string {
	return u.URL.String()
}

// GetterString returns URL string for hashicorp/go-getter.
// To keep Git information, do not specify subdirectories.
// cf. https://github.com/hashicorp/go-getter?tab=readme-ov-file#subdirectories
func (u *URL) GetterString() string {
	uu := *u.URL

	// Force the git protocol
	if !strings.HasPrefix(uu.Scheme, "git::") {
		uu.Scheme = "git::" + uu.Scheme
	}

	// Add .git suffix
	if !strings.HasSuffix(uu.Path, ".git") && !strings.Contains(uu.Path, "//") {
		uu.Path += ".git"
	}

	// Add depth=1 query parameter
	q := uu.Query()
	q.Add("depth", fmt.Sprint(u.depth))
	if u.ref != "" {
		q.Add("ref", u.ref)
	}
	uu.RawQuery = q.Encode()

	return uu.String()
}
