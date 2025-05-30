package repo

type Index struct {
	UpdatedAt string    `json:"updated_at"`
	Packages  []Package `json:"packages"`
}

type Package struct {
	ID       string `json:"id"`       // Must be PURL at the moment
	Location string `json:"location"` // File path to the VEX document
}
