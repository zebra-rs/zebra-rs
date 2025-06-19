# zmcp-server

Model Context Protocol (MCP) server for Zebra routing daemon.

## Overview

`zmcp-server` provides an MCP-compliant interface to zebra-rs, allowing AI assistants and other MCP clients to interact with network routing data. It exposes network topology information through structured tools that can be used for network analysis, troubleshooting, and visualization.

## Features

- **MCP Protocol Compliance**: Implements the Model Context Protocol 2024-11-05 specification
- **ISIS Topology Tools**: Get IS-IS graph data for network visualization
- **JSON Output**: Structured data output for programmatic consumption
- **Real-time Data**: Direct connection to zebra-rs daemon via gRPC
- **Configurable Connection**: Support for different zebra-rs server addresses

## Available Tools

### get-isis-graph

Retrieves IS-IS topology graph data for network visualization and analysis.

**Parameters:**
- `level` (optional): IS-IS level to retrieve
  - `"L1"`: Level-1 topology only
  - `"L2"`: Level-2 topology only  
  - `"both"`: Both levels (default)

**Returns:**
JSON-formatted graph data containing nodes, links, and topology information.

## Usage

### Basic Usage

```bash
# Run MCP server connecting to local zebra-rs
./zmcp-server

# Connect to zebra-rs on different host/port
./zmcp-server --base http://192.168.1.1 --port 2650

# Enable debug logging
./zmcp-server --debug
```

### Command Line Options

- `--base <URL>`: Base URL of zebra-rs server (default: http://127.0.0.1)
- `--port <PORT>`: Show server port (default: 2650)
- `--debug`: Enable debug logging

### MCP Client Integration

The server communicates via stdin/stdout using the MCP protocol. Example client interaction:

```json
// Initialize
{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

// List available tools
{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

// Call get-isis-graph tool
{
  "jsonrpc": "2.0", 
  "id": 3, 
  "method": "tools/call", 
  "params": {
    "name": "get-isis-graph",
    "arguments": {"level": "both"}
  }
}
```

## Prerequisites

- zebra-rs daemon running and accessible
- Network capabilities for gRPC communication

## Building

```bash
cargo build --bin zmcp-server
```

## Architecture

```
┌─────────────┐    MCP Protocol     ┌─────────────┐    gRPC      ┌─────────────┐
│ MCP Client  │ ◄─── stdin/stdout ──► │ zmcp-server │ ◄─────────── │  zebra-rs   │
└─────────────┘                     └─────────────┘              └─────────────┘
```

The server acts as a bridge between MCP clients and the zebra-rs daemon:
1. Receives MCP requests via stdin
2. Translates to zebra-rs gRPC calls
3. Returns structured JSON responses via stdout

## Error Handling

The server provides detailed error information for:
- Connection failures to zebra-rs
- Invalid tool parameters
- Network topology retrieval errors
- JSON parsing errors

## Logging

Uses structured logging with configurable levels:
- `warn` (default): Warnings and errors only - safe for MCP client communication
- `debug`: Detailed request/response information (use --debug flag)
- `error`: Error conditions and failures

The default `warn` level ensures that log output doesn't interfere with MCP protocol 
communication over stdin/stdout. Use `--debug` flag for detailed logging during development.

Set `RUST_LOG` environment variable for custom log filtering.