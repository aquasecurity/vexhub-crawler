package manifest

import (
	"encoding/json"
	"fmt"
	"os"
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
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create sources file: %w", err)
	}
	defer f.Close()

	e := json.NewEncoder(f)
	e.SetIndent("", "    ")
	if err = e.Encode(m); err != nil {
		return fmt.Errorf("JSON encode error: %w", err)
	}
	return nil
}

func Read(filePath string) (Manifest, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return Manifest{}, fmt.Errorf("failed to open the file: %w", err)
	}
	defer f.Close()

	var m Manifest
	if err = json.NewDecoder(f).Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("failed to decode the file: %w", err)
	}
	return m, nil
}
