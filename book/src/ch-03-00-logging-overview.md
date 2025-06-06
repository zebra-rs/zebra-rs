# Logging Configuration

Zebra-rs provides flexible logging capabilities with multiple output destinations and formats to support various deployment scenarios, from development and debugging to production monitoring and log analysis.

## Key Features

- **Multiple Output Destinations**: stdout, syslog, file
- **Multiple Formats**: terminal (human-readable), JSON, Elasticsearch-compatible
- **Protocol-Aware Logging**: Automatic protocol field inclusion (ISIS, BGP, OSPF)
- **Structured Logging**: Rich metadata for filtering and analysis
- **Fallback Mechanisms**: Automatic fallback when preferred output is unavailable

## Quick Start

For most users, the default configuration works well:

```bash
# Development - human-readable console output
zebra-rs

# Production - JSON to syslog
zebra-rs --daemon --log-output=syslog --log-format=json

# Container - JSON to stdout
zebra-rs --log-output=stdout --log-format=json
```

## Configuration Overview

Logging is configured through command-line options:

| Option | Purpose | Default |
|--------|---------|---------|
| `--log-output` | Where to send logs | `stdout` |
| `--log-format` | Log message format | `terminal` |
| `--log-file` | File path (when using file output) | `zebra-rs.log` |

## Common Use Cases

### Development and Debugging

```bash
# Verbose terminal output
RUST_LOG=debug zebra-rs --log-output=stdout --log-format=terminal
```

### Production Deployment

```bash
# Structured logging to syslog
zebra-rs --daemon --log-output=syslog --log-format=json
```

### Container Orchestration

```bash
# JSON to stdout for log collectors
zebra-rs --log-output=stdout --log-format=json
```

### Log Analytics

```bash
# Elasticsearch-ready format
zebra-rs --log-output=file --log-format=elasticsearch --log-file=/var/log/zebra-rs.log
```