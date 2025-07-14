# Port Scanner

A fast, concurrent port scanner written in Go with both CLI and web interface support.

## Features

- **Fast concurrent scanning** with configurable concurrency limits
- **CLI interface** for quick command-line scanning
- **Web interface** with modern UI for interactive scanning
- **Service detection** for common well-known ports
- **JSON output** support for programmatic use
- **Progress tracking** with real-time updates
- **Graceful shutdown** handling

## Project Structure

The code has been logically separated into the following files:

- **`main.go`** - Entry point and CLI logic
- **`models.go`** - Data structures and types (ScanRequest, PortInfo, ScanResponse, CommonPorts)
- **`validation.go`** - Input validation functions
- **`scanner.go`** - Core port scanning logic
- **`web.go`** - Web interface and HTTP handlers

## Usage

### CLI Mode

```bash
# Quick scan
./scanner example.com

# Detailed scan with custom parameters
./scanner -host 192.168.1.1 -start 1 -end 1000 -concurrent 200 -timeout 1000

# JSON output
./scanner -host 127.0.0.1 -start 80 -end 90 -json

# Quiet mode (no progress output)
./scanner -host 127.0.0.1 -start 80 -end 90 -quiet
```

### Web Interface

```bash
# Start web server
./scanner -web
```

Then open http://localhost:8080 in your browser.

## Command Line Options

- `-web` - Run in web interface mode
- `-host` - Target host to scan (IP or domain)
- `-start` - Starting port (default: 1)
- `-end` - Ending port (default: 1024)
- `-concurrent` - Maximum concurrent connections (default: 100)
- `-timeout` - Connection timeout in milliseconds (default: 500)
- `-json` - Output in JSON format
- `-quiet` - Suppress progress output

## Examples

```bash
# Scan common ports on localhost
./scanner 127.0.0.1

# Scan a specific range with high concurrency
./scanner -host 192.168.1.1 -start 1 -end 65535 -concurrent 500

# Quick web interface
./scanner -web
```

## Building

```bash
go build -o scanner
```

## Dependencies

- Go 1.23 or later
- Standard library only (no external dependencies)

## License
