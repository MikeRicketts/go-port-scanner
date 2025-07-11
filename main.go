package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	// Command line flags
	webMode := flag.Bool("web", false, "Run in web interface mode")
	host := flag.String("host", "", "Target host to scan")
	startPort := flag.Int("start", 1, "Starting port")
	endPort := flag.Int("end", 1024, "Ending port")
	maxConcurrent := flag.Int("concurrent", 100, "Maximum concurrent connections")
	timeoutMs := flag.Int("timeout", 500, "Connection timeout in milliseconds")
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	quiet := flag.Bool("quiet", false, "Suppress progress output")
	flag.Parse()

	// Web mode
	if *webMode {
		AddWebInterface()
		return
	}

	// CLI mode
	if *host == "" && len(flag.Args()) > 0 {
		*host = flag.Arg(0)
	}

	if *host == "" {
		fmt.Println("Usage:")
		fmt.Println("  port-scanner -web                        # Start web interface")
		fmt.Println("  port-scanner -host example.com -start 1 -end 1000  # CLI mode")
		fmt.Println("  port-scanner example.com                 # Quick scan")
		flag.PrintDefaults()
		os.Exit(1)
	}

	req := ScanRequest{
		Host:          *host,
		StartPort:     *startPort,
		EndPort:       *endPort,
		MaxConcurrent: *maxConcurrent,
		TimeoutMs:     *timeoutMs,
	}

	if err := ValidateScanRequest(req); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		os.Exit(1)
	}

	// Show progress unless JSON output or quiet mode is enabled
	verbose := !*jsonOutput && !*quiet
	response := RunScan(req, verbose)

	// Display results
	if *jsonOutput {
		jsonResponse, _ := json.MarshalIndent(response, "", "  ")
		fmt.Println(string(jsonResponse))
	} else {
		fmt.Printf("\nScan Results for %s:\n", response.Target)
		fmt.Printf("Scanned ports %d-%d in %.2f seconds\n",
			response.StartPort, response.EndPort, response.DurationSeconds)
		fmt.Printf("Found %d open ports out of %d total ports\n\n",
			len(response.OpenPorts), response.TotalPorts)

		if len(response.OpenPorts) > 0 {
			fmt.Println("Open ports:")
			fmt.Println("PORT     SERVICE")
			for _, port := range response.OpenPorts {
				fmt.Printf("%-8d %s\n", port.Port, port.Service)
			}
		} else {
			fmt.Println("No open ports found.")
		}
	}
}
