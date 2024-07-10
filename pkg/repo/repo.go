package repo

type Index struct {
	Version  int       `json:"version"`
	Packages []Package `json:"packages"`
}

type Package struct {
	ID       string // Must be PURL at the moment
	Location string // File path to the VEX document
}
