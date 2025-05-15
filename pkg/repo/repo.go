package repo

import "time"

type Index struct {
	UpdatedAt time.Time `json:"updated_at"`
	Packages  []Package `json:"packages"`
}

type Package struct {
	ID       string `json:"id"`       // Must be PURL at the moment
	Location string `json:"location"` // File path to the VEX document
}
