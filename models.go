package main

import (
	"time"
)

// ScanRequest represents scanning parameters
type ScanRequest struct {
	Host          string `json:"host"`
	StartPort     int    `json:"start_port"`
	EndPort       int    `json:"end_port"`
	MaxConcurrent int    `json:"max_concurrent,omitempty"`
	TimeoutMs     int    `json:"timeout_ms,omitempty"`
}

// PortInfo contains information about a scanned port
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	State   string `json:"state"`
}

// ScanResponse contains scan results
type ScanResponse struct {
	Target          string     `json:"target"`
	StartPort       int        `json:"start_port"`
	EndPort         int        `json:"end_port"`
	OpenPorts       []PortInfo `json:"open_ports"`
	ClosedPorts     int        `json:"closed_ports"`
	TotalPorts      int        `json:"total_ports"`
	DurationSeconds float64    `json:"duration_seconds"`
	Timestamp       time.Time  `json:"timestamp"`
	Error           string     `json:"error,omitempty"`
}

// Common well-known ports and services
var CommonPorts = map[int]string{
	20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
	25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
	143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
}
