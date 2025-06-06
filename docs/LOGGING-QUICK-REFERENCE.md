# Zebra-RS Logging Quick Reference

## Command Line Options

### Basic Usage
```bash
zebra-rs [--log-output OUTPUT] [--log-format FORMAT] [--log-file PATH]
```

### Options Summary

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `--log-output` | `stdout`, `syslog`, `file` | `stdout` | Where to send logs |
| `--log-format` | `terminal`, `json`, `elasticsearch` | `terminal` | Log message format |
| `--log-file` | `<path>` | `zebra-rs.log` | Log file path (when using `file` output) |

## Quick Examples

### Development
```bash
# Human-readable console output
zebra-rs --log-output=stdout --log-format=terminal

# Debug mode
RUST_LOG=debug zebra-rs
```

### Production
```bash
# Daemon with syslog
zebra-rs --daemon --log-output=syslog --log-format=json

# File logging with rotation-friendly format
zebra-rs --log-output=file --log-format=json --log-file=/var/log/zebra-rs.log
```

### Containers
```bash
# JSON to stdout for log collection
zebra-rs --log-output=stdout --log-format=json
```

### Elasticsearch
```bash
# Elasticsearch-optimized output
zebra-rs --log-output=file --log-format=elasticsearch --log-file=/var/log/zebra-rs-es.log
```

## Output Formats

### Terminal Format
```
2025-06-06T06:52:31.157Z  INFO zebra_rs::isis::ifsm: Hello originate L1 on eth0
```

### JSON Format
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

### Elasticsearch Format
```json
{
  "@timestamp": "2025-06-06T06:52:31.157888414+00:00",
  "level": "info",
  "message": "Hello originate L1 on eth0",
  "protocol": "isis",
  "service": {
    "name": "zebra-rs",
    "type": "routing-daemon",
    "version": "0.6.9"
  },
  "host": {"hostname": "router-1"},
  "process": {"pid": 12345},
  "@metadata": {
    "index": "zebra-rs-2025.06.06",
    "type": "_doc"
  }
}
```

## Environment Variables

| Variable | Values | Description |
|----------|--------|-------------|
| `RUST_LOG` | `error`, `warn`, `info`, `debug`, `trace` | Global log level |
| `RUST_LOG` | `zebra_rs::isis=debug` | Module-specific log level |

## File Path Resolution

### Absolute Paths
- Used as-is with directory creation if needed
- Example: `/var/log/zebra-rs.log`

### Relative Paths (tried in order)
1. Current directory: `./filename`
2. User home: `~/.zebra-rs/filename`  
3. System logs: `/var/log/filename`

## Protocol Fields

All protocol-specific logs include a `proto` field:

| Protocol | Field Value |
|----------|-------------|
| ISIS | `proto="isis"` |
| BGP | `proto="bgp"` |
| OSPF | `proto="ospf"` |

## Common Log Queries

### grep Examples
```bash
# ISIS logs only
grep '"proto":"isis"' /var/log/zebra-rs.log

# Error logs
grep '"level":"error"' /var/log/zebra-rs.log

# Last hour (requires timestamp parsing)
grep "$(date -d '1 hour ago' '+%Y-%m-%d')" /var/log/zebra-rs.log
```

### jq Examples
```bash
# Extract messages only
jq -r '.message' /var/log/zebra-rs.log

# ISIS logs only
jq 'select(.protocol == "isis")' /var/log/zebra-rs.log

# Error logs with timestamp
jq 'select(.level == "error") | {timestamp: ."@timestamp", message}' /var/log/zebra-rs.log
```

### Elasticsearch Queries
```
# Recent errors
level:error AND @timestamp:[now-1h TO now]

# ISIS protocol logs
protocol:isis

# DIS selection events
protocol:isis AND message:*DIS*

# Service logs from specific host
service.name:zebra-rs AND host.hostname:router-1
```

## Troubleshooting

### Permission Issues
```bash
# Check file permissions
ls -la /var/log/zebra-rs.log

# Test write access
touch /var/log/test && rm /var/log/test

# Use alternative path
zebra-rs --log-file=./zebra-rs.log
```

### Syslog Issues
```bash
# Check syslog daemon
systemctl status rsyslog

# Test syslog
logger -t zebra-rs "Test message"

# Check syslog socket
ls -la /dev/log
```

### JSON Validation
```bash
# Validate JSON format
jq . /var/log/zebra-rs.log

# Check for parsing errors
jq empty /var/log/zebra-rs.log
```

## Integration

### Logrotate
```bash
# /etc/logrotate.d/zebra-rs
/var/log/zebra-rs.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
```

### systemd Service
```ini
[Unit]
Description=Zebra-RS Routing Daemon
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/zebra-rs --daemon --log-output=syslog --log-format=json
Restart=always

[Install]
WantedBy=multi-user.target
```

### Docker
```dockerfile
# Dockerfile
CMD ["zebra-rs", "--log-output=stdout", "--log-format=json"]
```

```yaml
# docker-compose.yml
version: '3'
services:
  zebra-rs:
    image: zebra-rs:latest
    command: ["--log-output=stdout", "--log-format=json"]
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```