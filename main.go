package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"syscall"
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
var commonPorts = map[int]string{
	20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
	25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
	143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
}

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
				service, exists := commonPorts[p]
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

func runScan(req ScanRequest, verbose bool) ScanResponse {
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

func addWebInterface() {
	// Create a server with a timeout
	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Set up handlers
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `<!DOCTYPE html>
        <html>
        <head>
            <title>Port Scanner</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                :root {
                    --primary: #4361ee;
                    --success: #38b000;
                    --dark: #212529;
                    --gray-light: #f8f9fa;
                    --border-color: #dee2e6;
                    --danger: #dc3545;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    max-width: 900px;
                    margin: 0 auto;
                    padding: 20px;
                    color: var(--dark);
                    line-height: 1.5;
                    background-color: #f9fafb;
                }
                h1, h2 {
                    margin-top: 0;
                    font-weight: 600;
                    color: var(--primary);
                }
                h1 { font-size: 28px; margin-bottom: 24px; }
                h2 { font-size: 22px; margin-top: 32px; margin-bottom: 16px; }
                .card {
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
                    padding: 24px;
                    margin-bottom: 24px;
                }
                .form-group { margin-bottom: 20px; }
                label {
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 500;
                    font-size: 14px;
                }
                input {
                    padding: 10px 12px;
                    width: 100%;
                    box-sizing: border-box;
                    border: 1px solid var(--border-color);
                    border-radius: 4px;
                    font-size: 16px;
                }
                input:focus {
                    outline: none;
                    border-color: var(--primary);
                    box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.15);
                }
                button {
                    padding: 12px 20px;
                    background: var(--primary);
                    color: white;
                    border: none;
                    border-radius: 4px;
                    font-size: 16px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: background-color 0.2s;
                }
                button:hover {
                    background: #324cdd;
                }
                pre {
                    background: var(--gray-light);
                    padding: 16px;
                    overflow: auto;
                    border-radius: 4px;
                    font-size: 14px;
                }
                .spinner {
                    border: 4px solid rgba(67, 97, 238, 0.15);
                    border-top: 4px solid var(--primary);
                    border-radius: 50%;
                    width: 30px;
                    height: 30px;
                    animation: spin 1s linear infinite;
                    display: none;
                    margin: 10px 0;
                }
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }

                .results-container {
                    margin-top: 32px;
                    display: none;
                }
                #scanSummary {
                    margin-bottom: 16px;
                    padding: 12px;
                    background-color: var(--gray-light);
                    border-radius: 4px;
                    font-weight: 500;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 16px;
                    margin-bottom: 16px;
                    border: 1px solid var(--border-color);
                    border-radius: 4px;
                    overflow: hidden;
                }
                th, td {
                    padding: 12px 16px;
                    text-align: left;
                    border-bottom: 1px solid var(--border-color);
                }
                th {
                    background-color: var(--gray-light);
                    font-weight: 600;
                    color: var(--dark);
                }
                tr:nth-child(even) {
                    background-color: #fcfcfd;
                }
                .port-open {
                    color: var(--success);
                    font-weight: 600;
                }
                .tab-container {
                    margin-bottom: 16px;
                }
                .tab-buttons {
                    display: flex;
                    margin-bottom: 16px;
                    border-bottom: 1px solid var(--border-color);
                }
                .tab-button {
                    padding: 12px 16px;
                    border: none;
                    background: none;
                    cursor: pointer;
                    font-size: 15px;
                    font-weight: 500;
                    color: #555;
                    border-bottom: 2px solid transparent;
                }
                .tab-button.active {
                    border-bottom: 2px solid var(--primary);
                    color: var(--primary);
                }
                .tab-content {
                    display: none;
                }
                .tab-content.active {
                    display: block;
                }
                footer {
                    margin-top: 48px;
                    text-align: center;
                    font-size: 14px;
                    color: #6c757d;
                }
                /* Shutdown button styles */
                .shutdown-button {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background-color: var(--danger);
                    color: white;
                    padding: 8px 16px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-weight: 500;
                    border: none;
                    font-size: 14px;
                }
                .shutdown-button:hover {
                    background-color: #c82333;
                }
                .modal {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background-color: rgba(0,0,0,0.5);
                    z-index: 100;
                    align-items: center;
                    justify-content: center;
                }
                .modal-content {
                    background-color: white;
                    padding: 24px;
                    border-radius: 8px;
                    max-width: 400px;
                    text-align: center;
                }
                .modal-buttons {
                    display: flex;
                    gap: 12px;
                    margin-top: 16px;
                    justify-content: center;
                }
                .btn-cancel {
                    background-color: #6c757d;
                }
                .btn-cancel:hover {
                    background-color: #5a6268;
                }
            </style>
        </head>
        <body>
            <h1>Port Scanner</h1>

            <!-- Shutdown button -->
            <button id="shutdownButton" class="shutdown-button">Shutdown Server</button>

            <!-- Shutdown confirmation modal -->
            <div id="shutdownModal" class="modal">
                <div class="modal-content">
                    <h2>Confirm Shutdown</h2>
                    <p>Are you sure you want to shutdown the server?</p>
                    <div class="modal-buttons">
                        <button id="cancelShutdown" class="btn-cancel">Cancel</button>
                        <button id="confirmShutdown" style="background: var(--danger);">Shutdown</button>
                    </div>
                </div>
            </div>

            <div class="card">
                <form id="scanForm">
                    <div class="form-group">
                        <label for="host">Host (IP or Domain):</label>
                        <input type="text" id="host" name="host" required placeholder="example.com or 192.168.1.1">
                    </div>
                    <div class="form-group" style="display: flex; gap: 16px;">
                        <div style="flex: 1;">
                            <label for="startPort">Start Port:</label>
                            <input type="number" id="startPort" name="startPort" min="1" max="65535" value="1" required>
                        </div>
                        <div style="flex: 1;">
                            <label for="endPort">End Port:</label>
                            <input type="number" id="endPort" name="endPort" min="1" max="65535" value="1024" required>
                        </div>
                    </div>
                    <div class="form-group" style="display: flex; gap: 16px;">
                        <div style="flex: 1;">
                            <label for="maxConcurrent">Max Concurrent Connections:</label>
                            <input type="number" id="maxConcurrent" name="maxConcurrent" min="1" max="500" value="100">
                        </div>
                        <div style="flex: 1;">
                            <label for="timeoutMs">Connection Timeout (ms):</label>
                            <input type="number" id="timeoutMs" name="timeoutMs" min="100" max="5000" value="500">
                        </div>
                    </div>
                    <button type="submit">Start Scan</button>
                </form>
            </div>

            <div id="results" class="results-container">
                <h2>Scan Results</h2>
                <div class="spinner" id="spinner"></div>
                <div id="scanSummary"></div>

                <div class="tab-container">
                    <div class="tab-buttons">
                        <button id="tableTabButton" class="tab-button active">Table View</button>
                        <button id="jsonTabButton" class="tab-button">JSON View</button>
                    </div>

                    <div id="tableTab" class="tab-content active">
                        <table id="portsTable">
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>Service</th>
                                    <th>State</th>
                                </tr>
                            </thead>
                            <tbody id="portsTableBody"></tbody>
                        </table>
                        <div id="noPortsMessage" style="display:none; text-align:center; padding:16px;">
                            No open ports found.
                        </div>
                    </div>

                    <div id="jsonTab" class="tab-content">
                        <pre id="resultsJson"></pre>
                    </div>
                </div>
            </div>

            <footer>
                Port Scanner © 2025 | A Go Web Application
            </footer>

            <script>
                document.getElementById('scanForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const host = document.getElementById('host').value;
                    const startPort = parseInt(document.getElementById('startPort').value);
                    const endPort = parseInt(document.getElementById('endPort').value);
                    const maxConcurrent = parseInt(document.getElementById('maxConcurrent').value);
                    const timeoutMs = parseInt(document.getElementById('timeoutMs').value);

                    document.getElementById('spinner').style.display = 'block';
                    document.getElementById('scanSummary').textContent = 'Scanning...';
                    document.getElementById('results').style.display = 'block';
                    document.getElementById('tableTab').style.display = 'none';
                    document.getElementById('jsonTab').style.display = 'none';

                    try {
                        const response = await fetch('/scan', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                host,
                                start_port: startPort,
                                end_port: endPort,
                                max_concurrent: maxConcurrent,
                                timeout_ms: timeoutMs
                            })
                        });
                        const data = await response.json();

                        // Display summary
                        const summary = 'Scanned ' + data.total_ports + ' ports on ' + data.target + ' in ' +
                                        data.duration_seconds.toFixed(2) + ' seconds. Found ' +
                                        data.open_ports.length + ' open ports.';
                        document.getElementById('scanSummary').textContent = summary;

                        // Display JSON
                        document.getElementById('resultsJson').textContent = JSON.stringify(data, null, 2);

                        // Display table of open ports
                        const tableBody = document.getElementById('portsTableBody');
                        tableBody.innerHTML = '';

                        if (data.open_ports.length > 0) {
                            data.open_ports.forEach(port => {
                                const row = tableBody.insertRow();
                                row.insertCell(0).textContent = port.port;
                                row.insertCell(1).textContent = port.service || 'unknown';
                                const stateCell = row.insertCell(2);
                                stateCell.textContent = port.state;
                                stateCell.className = 'port-open';
                            });
                            document.getElementById('portsTable').style.display = 'table';
                            document.getElementById('noPortsMessage').style.display = 'none';
                        } else {
                            document.getElementById('portsTable').style.display = 'none';
                            document.getElementById('noPortsMessage').style.display = 'block';
                        }

                        document.getElementById('tableTab').style.display = 'block';
                        document.getElementById('jsonTab').style.display = 'none';
                    } catch (error) {
                        document.getElementById('scanSummary').textContent = 'Error: ' + error.message;
                    } finally {
                        document.getElementById('spinner').style.display = 'none';
                    }
                });

                // Tab switching functionality
                document.getElementById('tableTabButton').addEventListener('click', function() {
                    document.getElementById('tableTab').style.display = 'block';
                    document.getElementById('jsonTab').style.display = 'none';
                    document.getElementById('tableTabButton').classList.add('active');
                    document.getElementById('jsonTabButton').classList.remove('active');
                });

                document.getElementById('jsonTabButton').addEventListener('click', function() {
                    document.getElementById('tableTab').style.display = 'none';
                    document.getElementById('jsonTab').style.display = 'block';
                    document.getElementById('tableTabButton').classList.remove('active');
                    document.getElementById('jsonTabButton').classList.add('active');
                });

                // Shutdown functionality
                document.getElementById('shutdownButton').addEventListener('click', function() {
                    document.getElementById('shutdownModal').style.display = 'flex';
                });

                document.getElementById('cancelShutdown').addEventListener('click', function() {
                    document.getElementById('shutdownModal').style.display = 'none';
                });

                document.getElementById('confirmShutdown').addEventListener('click', async function() {
                    try {
                        const response = await fetch('/shutdown', {
                            method: 'POST'
                        });

                        document.body.innerHTML = 
                            '<div style="text-align: center; padding-top: 100px;">' +
                            '<h1>Server Shutdown</h1>' +
                            '<p>The server has been shut down successfully.</p>' +
                            '<p>You can close this window now.</p>' +
                            '</div>';
                    } catch (error) {
                        // If we get here, the server probably shut down before the response was sent
                        document.body.innerHTML = 
                            '<div style="text-align: center; padding-top: 100px;">' +
                            '<h1>Server Shutdown</h1>' +
                            '<p>The server has been shut down.</p>' +
                            '<p>You can close this window now.</p>' +
                            '</div>';
                    }
                });
            </script>
        </body>
        </html>`
		fmt.Fprintf(w, html)
	})

	// Add scan endpoint
	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if err := ValidateScanRequest(req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			response := ScanResponse{
				Error:     err.Error(),
				Timestamp: time.Now(),
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Run the scan without verbose output for web interface
		response := runScan(req, false)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Add shutdown endpoint
	http.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Send a response before shutting down
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "shutting_down"}`))

		// Trigger server shutdown in a goroutine
		go func() {
			// Wait a moment to allow the response to be sent
			time.Sleep(100 * time.Millisecond)

			// Shutdown the server
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			fmt.Println("\nShutting down server...")
			if err := server.Shutdown(ctx); err != nil {
				fmt.Printf("Server forced to shutdown: %v\n", err)
			}

			fmt.Println("Server has been shut down")
			os.Exit(0)
		}()
	})

	// Set up a channel to listen for interrupt signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start the server in a goroutine
	go func() {
		fmt.Println("Server running at http://localhost:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Error starting server: %v\n", err)
		}
	}()

	// Wait for interrupt signal or shutdown request
	<-stop

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	fmt.Println("\nShutting down server...")
	if err := server.Shutdown(ctx); err != nil {
		fmt.Printf("Server forced to shutdown: %v\n", err)
	}

	fmt.Println("Server has been shut down")
}

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
		addWebInterface()
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
	response := runScan(req, verbose)

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
