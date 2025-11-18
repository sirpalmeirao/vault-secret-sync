package driver

import "fmt"

var (
	ErrPathRequired = fmt.Errorf("path is required")

	DriverNames = []DriverName{
		DriverNameGcp,
		DriverNameVault,
	}
)

type DriverName string

const (
	DriverNameGcp   DriverName = "gcp"
	DriverNameVault DriverName = "vault"
)

func DriverIsSupported(driver DriverName) bool {
	for _, d := range DriverNames {
		if d == driver {
			return true
		}
	}
	return false
}
