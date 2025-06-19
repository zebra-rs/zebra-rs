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
# Run MCP server connecting to local zebra-rs (silent operation)
./zmcp-server

# Connect to zebra-rs on different host/port
./zmcp-server --base http://192.168.1.1 --port 2650

# Enable debug logging for development
./zmcp-server --debug

# Enable specific log level via environment
RUST_LOG=warn ./zmcp-server
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

**Default Behavior**: All logging is disabled to ensure clean MCP protocol communication over stdin/stdout.

**Enable Logging**:
- `--debug`: Enable debug-level logging for development
- `RUST_LOG=<level>`: Set custom log level via environment variable

**Available Levels**:
- `debug`: Detailed request/response information
- `warn`: Warnings and errors only
- `error`: Error conditions and failures only

The default silent operation ensures that log output never interferes with MCP JSON-RPC 
communication. Enable logging only when needed for development or troubleshooting.