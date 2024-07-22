package manifest

import (
	"encoding/json"
	"os"

	"github.com/samber/oops"
)

const FileName = "manifest.json"

type Manifest struct {
	ID      string // Must be PURL at the moment
	Sources []Source
}

type Source struct {
	Path string
	URL  string
}

func Write(filePath string, m Manifest) error {
	errBuilder := oops.Code("write_manifest_error").In("manifest").With("filePath", filePath)
	f, err := os.Create(filePath)
	if err != nil {
		return errBuilder.Wrapf(err, "failed to create sources file")
	}
	defer f.Close()

	e := json.NewEncoder(f)
	e.SetIndent("", "    ")
	if err = e.Encode(m); err != nil {
		return errBuilder.Wrapf(err, "JSON encode error")
	}
	return nil
}

func Read(filePath string) (Manifest, error) {
	errBuilder := oops.Code("read_manifest_error").In("manifest").With("filePath", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		return Manifest{}, errBuilder.Wrapf(err, "failed to open the file")
	}
	defer f.Close()

	var m Manifest
	if err = json.NewDecoder(f).Decode(&m); err != nil {
		return Manifest{}, errBuilder.Wrapf(err, "failed to decode the file")
	}
	return m, nil
}
