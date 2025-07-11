package main

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ScanPorts performs port scanning with concurrency control
func ScanPorts(hostname string, startPort, endPort, maxConcurrent int, timeout time.Duration, verbose bool) ([]PortInfo, time.Duration) {
	start := time.Now()
	totalPorts := endPort - startPort + 1
	results := make(chan PortInfo, totalPorts)
	semaphore := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	// For simple progress updates in verbose mode
	scanProgress := 0
	var progressMutex sync.Mutex

	if verbose {
		fmt.Printf("Starting scan of %d ports on %s...\n", totalPorts, hostname)
	}

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore
		go func(p int) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore

			address := net.JoinHostPort(hostname, strconv.Itoa(p))
			conn, err := net.DialTimeout("tcp", address, timeout)

			// Update progress counter if in verbose mode
			if verbose {
				progressMutex.Lock()
				scanProgress++
				if scanProgress%100 == 0 || scanProgress == totalPorts {
					fmt.Printf("\rScanning... %d/%d ports completed (%d%%)",
						scanProgress, totalPorts, scanProgress*100/totalPorts)
				}
				progressMutex.Unlock()
			}

			if err == nil {
				service, exists := CommonPorts[p]
				if !exists {
					service = "unknown"
				}
				results <- PortInfo{Port: p, Service: service, State: "open"}
				conn.Close()
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(results)
		if verbose {
			fmt.Println("\nScan complete!")
		}
	}()

	var openPorts []PortInfo
	for portInfo := range results {
		openPorts = append(openPorts, portInfo)
	}

	// Sort the results by port number
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	return openPorts, time.Since(start)
}

// RunScan executes a port scan with the given parameters
func RunScan(req ScanRequest, verbose bool) ScanResponse {
	maxConcurrent := req.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 100
	}

	timeoutMs := req.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 500
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	openPortsInfo, duration := ScanPorts(req.Host, req.StartPort, req.EndPort, maxConcurrent, timeout, verbose)

	totalPorts := req.EndPort - req.StartPort + 1
	closedPorts := totalPorts - len(openPortsInfo)

	return ScanResponse{
		Target:          req.Host,
		StartPort:       req.StartPort,
		EndPort:         req.EndPort,
		OpenPorts:       openPortsInfo,
		ClosedPorts:     closedPorts,
		TotalPorts:      totalPorts,
		DurationSeconds: duration.Seconds(),
		Timestamp:       time.Now(),
	}
}
