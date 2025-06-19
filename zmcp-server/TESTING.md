# zmcp-server Testing Guide

This document describes the comprehensive test suite for the zmcp-server MCP (Model Context Protocol) implementation.

## Test Overview

The test suite includes **35 total tests** covering all aspects of the MCP server:

- **Unit Tests (25)**: Core functionality, protocol compliance, error handling
- **Integration Tests (10)**: Real server communication, end-to-end workflows

## Test Categories

### 1. Unit Tests (`src/lib.rs`, `src/client.rs`, `src/tools/isis.rs`)

#### MCP Server Core Tests (14 tests)
- JSON-RPC protocol compliance
- MCP initialization and capability negotiation  
- Tool listing and schema validation
- Tool execution with parameter validation
- Error handling for unknown methods/tools
- Request/response structure validation

#### gRPC Client Tests (5 tests)
- Client creation and configuration
- Connection handling and error scenarios
- Command formatting and execution

#### ISIS Tools Tests (8 tests)
- Graph data filtering by ISIS level (L1, L2, both)
- Parameter validation and error handling
- Mock data processing and structure validation

### 2. Integration Tests (`tests/integration_tests.rs`)

#### Real Server Connection Tests (2 tests)
- **`test_real_zebra_connection_and_isis_graph`**: Full MCP workflow with live zebra-rs
- **`test_direct_zebra_client_isis_command`**: Direct gRPC client testing

#### Protocol Validation Tests (6 tests)
- JSON-RPC message format compliance
- Tool schema structure validation
- Error response format verification
- Concurrent request handling
- Mock client workflow simulation

#### Data Processing Tests (2 tests)
- ISIS graph filtering with realistic topology data
- Sample MCP response structure validation

## Running Tests

### All Tests
```bash
cargo test
```

### Unit Tests Only
```bash
cargo test --lib
```

### Integration Tests Only
```bash
cargo test --test integration_tests
```

### Real Server Tests (requires zebra-rs running)
```bash
# Start zebra-rs first
make run

# In another terminal
cargo test test_real_zebra -- --nocapture
cargo test test_direct_zebra -- --nocapture
```

### Specific Test Categories
```bash
# MCP protocol tests
cargo test test_handle_ 

# ISIS functionality tests  
cargo test isis

# Client tests
cargo test client

# Mock data tests
cargo test mock
```

## Test Requirements

### Basic Tests (No External Dependencies)
- Rust toolchain
- Standard dependencies (tokio, serde_json, etc.)

### Real Server Tests (Optional)
- zebra-rs daemon running at `localhost:2650`
- gRPC server enabled on zebra-rs
- Network connectivity

## Test Scenarios Covered

### MCP Protocol Compliance
✅ **Initialize handshake** - Protocol version negotiation  
✅ **Capability advertising** - Tool availability and schemas  
✅ **Tool execution** - Parameter validation and result formatting  
✅ **Error handling** - Standard JSON-RPC error responses  

### ISIS Graph Functionality  
✅ **Level filtering** - L1, L2, and both level support  
✅ **Empty data handling** - Graceful handling when ISIS not configured  
✅ **JSON parsing** - Robust parsing of zebra-rs responses  
✅ **Data validation** - Structure verification for graph data  

### Real-World Integration
✅ **Live server communication** - Full gRPC client functionality  
✅ **Command execution** - `show isis graph` and related commands  
✅ **Error scenarios** - Connection failures, invalid parameters  
✅ **Performance** - Concurrent request handling  

## Expected Test Outcomes

### With zebra-rs Running
- **Connection successful** ✅
- **Commands execute** ✅  
- **Empty data handled gracefully** ✅ (when ISIS not configured)
- **Level filtering works** ✅
- **Error validation works** ✅

### Without zebra-rs Running  
- **Connection tests skip gracefully** ✅
- **Mock tests still run** ✅
- **All unit tests pass** ✅
- **Protocol validation complete** ✅

## Test Output Examples

### Successful Real Server Test
```
✓ Connected to zebra-rs at localhost:2650
  Testing: Test getting ISIS graph for both levels
  ✓ Received ISIS graph data (2 bytes)
  ✓ ISIS graph data is valid JSON
  ✓ Found 0 graph object(s)
  Testing error handling with real server
  ✓ Invalid level parameter correctly rejected
```

### Mock Data Test
```
✓ ISIS graph filtering tests passed with realistic topology data
  L1 graph: 2 nodes, 1 edges
  L2 graph: 2 nodes, 1 edges
```

## Troubleshooting

### Test Failures
1. **Connection errors**: Ensure zebra-rs is running on port 2650
2. **Permission errors**: Check network capabilities for raw sockets
3. **Protocol errors**: Verify gRPC service is enabled in zebra-rs

### Common Issues
- **Empty ISIS data**: Normal when ISIS protocol not configured
- **Connection timeouts**: Check firewall and network configuration  
- **Build errors**: Ensure all dependencies are available

## Adding New Tests

### For New MCP Tools
1. Add unit tests in `src/tools/[protocol]/mod.rs`
2. Add integration tests in `tests/integration_tests.rs`  
3. Include both mock data and real server scenarios

### For Protocol Extensions
1. Update schema validation tests
2. Add new JSON-RPC method tests
3. Verify MCP specification compliance

## Continuous Integration

The test suite is designed to work in CI environments:
- **No external dependencies required** for core tests
- **Graceful skipping** of server-dependent tests
- **Clear pass/fail indicators** for automated systems
- **Comprehensive coverage** of all code paths