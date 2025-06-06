# Zebra-RS Logging Configuration Guide

This document provides comprehensive information about configuring logging in zebra-rs, including all available options, formats, and use cases.

## Table of Contents

- [Overview](#overview)
- [Command Line Options](#command-line-options)
- [Log Output Destinations](#log-output-destinations)
- [Log Formats](#log-formats)
- [File Logging Configuration](#file-logging-configuration)
- [Configuration Examples](#configuration-examples)
- [Protocol-Specific Logging](#protocol-specific-logging)
- [Integration Examples](#integration-examples)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Overview

Zebra-rs provides flexible logging capabilities with multiple output destinations and formats to support various deployment scenarios, from development and debugging to production monitoring and log analysis.

### Key Features

- **Multiple Output Destinations**: stdout, syslog, file
- **Multiple Formats**: terminal (human-readable), JSON, Elasticsearch-compatible
- **Protocol-Aware Logging**: Automatic protocol field inclusion (ISIS, BGP, OSPF)
- **Structured Logging**: Rich metadata for filtering and analysis
- **Fallback Mechanisms**: Automatic fallback when preferred output is unavailable

## Command Line Options

### --log-output

Controls where log messages are sent.

```bash
--log-output <OUTPUT>
```

**Values:**
- `stdout` (default) - Output to standard output
- `syslog` - Send to system syslog daemon
- `file` - Write to log file

### --log-format

Controls the format of log messages.

```bash
--log-format <FORMAT>
```

**Values:**
- `terminal` (default) - Human-readable format for console output
- `json` - Standard JSON format for structured logging
- `elasticsearch` - Elasticsearch-optimized JSON format

### --log-file

Specifies the log file path when using `--log-output=file`.

```bash
--log-file <PATH>
```

**Optional**: If not specified, defaults to `zebra-rs.log` in the current directory.

## Log Output Destinations

### stdout

Sends log messages to standard output. Ideal for:
- Development and debugging
- Container deployments with log collection
- Interactive sessions

```bash
zebra-rs --log-output=stdout
```

**Output Example (terminal format):**
```
2025-06-06T06:52:31.157Z  INFO zebra_rs: zebra-rs started
2025-06-06T06:52:31.158Z  INFO zebra_rs::isis::ifsm: Hello originate L1 on eth0
```

### syslog

Sends log messages to the system syslog daemon. Ideal for:
- System integration
- Centralized logging infrastructure
- Production deployments

```bash
zebra-rs --log-output=syslog
```

**Syslog Configuration:**
- **Facility**: `LOG_DAEMON`
- **Process**: `zebra-rs`
- **PID**: Included automatically

**Syslog Example:**
```
Jun 6 06:52:31 router zebra-rs[12345]: zebra-rs started
Jun 6 06:52:31 router zebra-rs[12345]: Hello originate L1 on eth0
```

### file

Writes log messages to a specified file. Ideal for:
- Long-term log retention
- Offline analysis
- High-volume logging scenarios

```bash
zebra-rs --log-output=file --log-file=/var/log/zebra-rs.log
```

**File Path Resolution:**
1. If absolute path: Use as-is (with directory creation if needed)
2. If relative path: Try in order:
   - Current directory: `./filename`
   - User home: `~/.zebra-rs/filename`
   - System logs: `/var/log/filename`

## Log Formats

### terminal

Human-readable format optimized for console viewing.

```bash
zebra-rs --log-format=terminal
```

**Features:**
- Timestamp in ISO 8601 format
- Color coding (when supported)
- Compact, readable layout
- Module path information

**Example:**
```
2025-06-06T06:52:31.157Z  INFO zebra_rs::isis::ifsm: Hello originate L1 on eth0
2025-06-06T06:52:31.158Z  WARN zebra_rs::isis::link: DIS flapping detected, applying dampening for 30 seconds
```

### json

Standard JSON format for structured logging and parsing.

```bash
zebra-rs --log-format=json
```

**Features:**
- Structured field access
- Machine-readable format
- Consistent schema
- Easy parsing with standard tools

**Example:**
```json
{
  "timestamp": "2025-06-06T06:52:31.157888414Z",
  "level": "INFO",
  "target": "zebra_rs::isis::ifsm",
  "fields": {
    "message": "Hello originate L1 on eth0",
    "proto": "isis"
  }
}
```

### elasticsearch

Elasticsearch-optimized JSON format with enhanced metadata.

```bash
zebra-rs --log-format=elasticsearch
```

**Features:**
- `@timestamp` field for time-based queries
- Service metadata for multi-daemon environments
- Host and process information
- Daily index patterns
- Protocol field extraction

**Example:**
```json
{
  "@timestamp": "2025-06-06T06:52:31.157888414+00:00",
  "level": "info",
  "message": "Hello originate L1 on eth0",
  "protocol": "isis",
  "service": {
    "name": "zebra-rs",
    "type": "routing-daemon",
    "version": "0.6.9",
    "protocol": "isis"
  },
  "host": {
    "hostname": "router-1"
  },
  "process": {
    "pid": 12345
  },
  "@metadata": {
    "index": "zebra-rs-2025.06.06",
    "type": "_doc"
  }
}
```

## File Logging Configuration

### Path Specification

#### Absolute Paths
```bash
zebra-rs --log-output=file --log-file=/var/log/zebra-rs.log
zebra-rs --log-output=file --log-file=/home/user/logs/routing.log
```

#### Relative Paths
```bash
zebra-rs --log-output=file --log-file=zebra-rs.log          # Current directory
zebra-rs --log-output=file --log-file=logs/routing.log     # Subdirectory
```

### Directory Creation

Zebra-rs automatically creates directories as needed:

```bash
zebra-rs --log-output=file --log-file=/var/log/zebra/router.log
# Creates /var/log/zebra/ if it doesn't exist
```

### Permission Handling

If the specified path is not writable, zebra-rs tries fallback locations:

1. **Current directory**: `./filename`
2. **User home**: `~/.zebra-rs/filename`
3. **System logs**: `/var/log/filename`

### File Rotation

Currently, zebra-rs writes to a single log file without automatic rotation. For production use, consider:

- External log rotation tools (logrotate)
- Log aggregation systems
- Container-based log collection

## Configuration Examples

### Development Setup
```bash
# Human-readable output to console
zebra-rs --log-output=stdout --log-format=terminal
```

### Production Daemon
```bash
# Structured logging to syslog
zebra-rs --daemon --log-output=syslog --log-format=json
```

### Container Deployment
```bash
# JSON output to stdout for log collection
zebra-rs --log-output=stdout --log-format=json
```

### Elasticsearch Integration
```bash
# Elasticsearch-compatible format to file
zebra-rs --log-output=file --log-format=elasticsearch --log-file=/var/log/zebra-rs-es.log
```

### Debug Session
```bash
# Verbose terminal output with protocol details
RUST_LOG=debug zebra-rs --log-output=stdout --log-format=terminal
```

### Multi-Instance Setup
```bash
# Instance-specific log files
zebra-rs --log-output=file --log-file=/var/log/zebra-rs-instance1.log
zebra-rs --log-output=file --log-file=/var/log/zebra-rs-instance2.log
```

## Protocol-Specific Logging

Zebra-rs includes protocol-aware logging that automatically tags log messages with protocol information.

### ISIS Logging

ISIS-related logs include `proto="isis"` field:

```json
{
  "message": "Hello originate L1 on eth0",
  "protocol": "isis",
  "fields": {
    "proto": "isis"
  }
}
```

**Common ISIS Log Messages:**
- Hello packet origination and reception
- DIS (Designated Intermediate System) selection
- LSP (Link State PDU) processing
- Adjacency state changes

### BGP Logging

BGP-related logs include `proto="bgp"` field:

```json
{
  "message": "BGP session established with 192.168.1.1",
  "protocol": "bgp",
  "fields": {
    "proto": "bgp"
  }
}
```

### OSPF Logging

OSPF-related logs include `proto="ospf"` field:

```json
{
  "message": "OSPF area 0.0.0.0 DR election completed",
  "protocol": "ospf",
  "fields": {
    "proto": "ospf"
  }
}
```

## Integration Examples

### Elasticsearch Stack

#### 1. Logstash Configuration
```ruby
input {
  file {
    path => "/var/log/zebra-rs-es.log"
    codec => "json"
  }
}

filter {
  # Extract index from @metadata
  if [@metadata][index] {
    mutate {
      add_field => { "[@metadata][target_index]" => "%{[@metadata][index]}" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "%{[@metadata][target_index]}"
  }
}
```

#### 2. Filebeat Configuration
```yaml
filebeat.inputs:
- type: log
  paths:
    - /var/log/zebra-rs-es.log
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "zebra-rs-%{+yyyy.MM.dd}"
```

### Syslog Integration

#### 1. rsyslog Configuration
```
# /etc/rsyslog.d/zebra-rs.conf
if $programname == 'zebra-rs' then /var/log/zebra-rs.log
& stop
```

#### 2. syslog-ng Configuration
```
filter f_zebra_rs { program("zebra-rs"); };
destination d_zebra_rs { file("/var/log/zebra-rs.log"); };
log { source(s_src); filter(f_zebra_rs); destination(d_zebra_rs); };
```

### Monitoring Integration

#### 1. Prometheus with mtail
```
# /etc/mtail/zebra-rs.mtail
counter isis_hello_total by protocol, interface
counter bgp_sessions_total by state
counter errors_total by level, protocol

/Hello originate (?P<level>L[12]) on (?P<interface>\w+)/ {
  isis_hello_total["isis"][$interface]++
}

/BGP session (?P<state>\w+)/ {
  bgp_sessions_total[$state]++
}

/level":"(?P<level>error|warn)".*"protocol":"(?P<protocol>\w+)"/ {
  errors_total[$level][$protocol]++
}
```

#### 2. Fluentd Configuration
```yaml
<source>
  @type tail
  path /var/log/zebra-rs-es.log
  pos_file /var/log/fluentd/zebra-rs.log.pos
  tag zebra.routing
  format json
</source>

<filter zebra.routing>
  @type record_transformer
  <record>
    hostname "#{Socket.gethostname}"
    service_type routing
  </record>
</filter>

<match zebra.routing>
  @type elasticsearch
  host localhost
  port 9200
  index_name zebra-rs
  type_name _doc
</match>
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied
**Problem**: Cannot write to log file
```
Failed to setup File("/var/log/zebra-rs.log") logging: Cannot write to log directory: /var/log
```

**Solutions:**
- Use a writable directory: `--log-file=./zebra-rs.log`
- Create directory with proper permissions: `sudo mkdir -p /var/log && sudo chown $USER /var/log`
- Run with appropriate privileges: `sudo zebra-rs --log-file=/var/log/zebra-rs.log`

#### 2. Syslog Connection Failed
**Problem**: Cannot connect to syslog
```
Failed to setup Syslog logging: Failed to connect to syslog: Connection refused
```

**Solutions:**
- Verify syslog daemon is running: `systemctl status rsyslog`
- Check syslog socket: `ls -la /dev/log`
- Use alternative output: `--log-output=file`

#### 3. Disk Space Issues
**Problem**: Log file grows too large

**Solutions:**
- Implement log rotation:
```bash
# /etc/logrotate.d/zebra-rs
/var/log/zebra-rs.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload zebra-rs || true
    endscript
}
```

- Use centralized logging to reduce local storage
- Monitor disk usage with system tools

#### 4. Log Level Configuration
**Problem**: Too verbose or not enough logging

**Solutions:**
- Set environment variable: `RUST_LOG=debug` (verbose) or `RUST_LOG=warn` (minimal)
- Available levels: `trace`, `debug`, `info`, `warn`, `error`
- Protocol-specific: `RUST_LOG=zebra_rs::isis=debug`

### Diagnostic Commands

#### Check Log Output
```bash
# Follow log output in real-time
tail -f /var/log/zebra-rs.log

# Search for specific protocols
grep '"protocol":"isis"' /var/log/zebra-rs-es.log

# Check for errors
grep -i error /var/log/zebra-rs.log
```

#### Validate JSON Format
```bash
# Check JSON validity
jq . /var/log/zebra-rs-es.log

# Extract specific fields
jq '.message' /var/log/zebra-rs-es.log
jq 'select(.protocol == "isis")' /var/log/zebra-rs-es.log
```

#### Test Connectivity
```bash
# Test syslog connectivity
logger -t zebra-rs "Test message"

# Check file permissions
touch /var/log/test-write && rm /var/log/test-write
```

## Best Practices

### Production Deployments

1. **Use Structured Logging**
   ```bash
   zebra-rs --log-format=json --log-output=syslog
   ```

2. **Implement Log Rotation**
   - Configure logrotate for file-based logging
   - Use centralized log management systems
   - Monitor disk usage

3. **Set Appropriate Log Levels**
   ```bash
   RUST_LOG=info zebra-rs  # Default for production
   RUST_LOG=debug zebra-rs # For troubleshooting
   ```

4. **Use Protocol Filtering**
   ```bash
   # Monitor specific protocols
   jq 'select(.protocol == "bgp")' /var/log/zebra-rs.log
   ```

### Development

1. **Use Terminal Format**
   ```bash
   zebra-rs --log-format=terminal --log-output=stdout
   ```

2. **Enable Debug Logging**
   ```bash
   RUST_LOG=debug zebra-rs
   ```

3. **Module-Specific Debugging**
   ```bash
   RUST_LOG=zebra_rs::isis::ifsm=trace zebra-rs
   ```

### Container Deployments

1. **Log to stdout**
   ```bash
   zebra-rs --log-output=stdout --log-format=json
   ```

2. **Use Init Systems**
   - Ensure proper signal handling
   - Configure restart policies
   - Set resource limits

### Monitoring and Alerting

1. **Key Metrics to Monitor**
   - Error rates by protocol
   - Adjacency state changes
   - DIS selection events
   - Resource utilization

2. **Alert Conditions**
   - High error rates
   - Protocol adjacency failures
   - Unexpected restarts
   - Log volume anomalies

3. **Dashboard Queries**
   ```
   # Elasticsearch queries
   level:error AND @timestamp:[now-1h TO now]
   protocol:isis AND message:*DIS*
   service.name:zebra-rs AND level:(error OR warn)
   ```

### Security Considerations

1. **Log File Permissions**
   - Restrict read access to authorized users
   - Use appropriate file system permissions
   - Consider log encryption for sensitive data

2. **Network Logging**
   - Secure log transmission channels
   - Authenticate log collection systems
   - Monitor for log injection attacks

3. **Data Retention**
   - Implement appropriate retention policies
   - Comply with regulatory requirements
   - Balance storage costs with operational needs

---

## Summary

Zebra-rs provides comprehensive logging capabilities suitable for various deployment scenarios. By combining the appropriate output destination, format, and configuration options, you can create a logging solution that meets your operational requirements while providing the visibility needed for monitoring, troubleshooting, and analysis.

For additional information, refer to the main project documentation or raise issues on the project repository.