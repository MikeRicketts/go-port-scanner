package main

import (
	"errors"
	"fmt"
	"net"
	"regexp"
)

// ValidateScanRequest validates the scanning parameters
func ValidateScanRequest(req ScanRequest) error {
	if req.Host == "" {
		return errors.New("host required")
	}
	if net.ParseIP(req.Host) == nil {
		hostnameRegex := `^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$`
		matched, err := regexp.MatchString(hostnameRegex, req.Host)
		if err != nil || !matched {
			return errors.New("invalid hostname or IP address")
		}
		_, err = net.LookupHost(req.Host)
		if err != nil {
			return fmt.Errorf("failed to resolve hostname: %v", err)
		}
	}

	if req.StartPort < 1 || req.StartPort > 65535 {
		return errors.New("start port must be between 1 and 65535")
	}
	if req.EndPort < 1 || req.EndPort > 65535 {
		return errors.New("end port must be between 1 and 65535")
	}
	if req.StartPort > req.EndPort {
		return errors.New("start port cannot be greater than end port")
	}

	return nil
}
