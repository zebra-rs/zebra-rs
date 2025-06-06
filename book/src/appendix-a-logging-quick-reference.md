# Appendix A: Logging Quick Reference

## Command Line Options

```bash
zebra-rs [--log-output OUTPUT] [--log-format FORMAT] [--log-file PATH]
```

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `--log-output` | `stdout`, `syslog`, `file` | `stdout` | Where to send logs |
| `--log-format` | `terminal`, `json`, `elasticsearch` | `terminal` | Log message format |
| `--log-file` | `<path>` | `zebra-rs.log` | Log file path (when using `file` output) |

## Common Examples

```bash
# Development
zebra-rs --log-output=stdout --log-format=terminal

# Production daemon
zebra-rs --daemon --log-output=syslog --log-format=json

# Container deployment
zebra-rs --log-output=stdout --log-format=json

# Elasticsearch integration
zebra-rs --log-output=file --log-format=elasticsearch --log-file=/var/log/zebra-rs.log
```

## Environment Variables

```bash
# Set global log level
RUST_LOG=debug zebra-rs

# Set module-specific level
RUST_LOG=zebra_rs::isis=debug zebra-rs

# Multiple module levels
RUST_LOG=info,zebra_rs::isis=debug,zebra_rs::bgp=trace zebra-rs
```

## Log Levels

- `trace` - Very detailed information
- `debug` - Debugging information
- `info` - General information (default)
- `warn` - Warning conditions
- `error` - Error conditions

## Output Format Examples

### Terminal
```
2025-06-06T06:52:31.157Z  INFO zebra_rs::isis::ifsm: Hello originate L1 on eth0
```

### JSON
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

### Elasticsearch
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
  }
}
```

## Quick Troubleshooting

### Permission Issues
```bash
# Use current directory
zebra-rs --log-file=./zebra-rs.log

# Check permissions
ls -la /var/log/
```

### Syslog Issues
```bash
# Check syslog service
systemctl status rsyslog

# Test syslog
logger -t test "Test message"
```

### View Logs
```bash
# Follow log file
tail -f /var/log/zebra-rs.log

# Filter by protocol
grep '"proto":"isis"' /var/log/zebra-rs.log

# Parse JSON
jq '.message' /var/log/zebra-rs.log
```

## Integration Snippets

### Logrotate
```bash
# /etc/logrotate.d/zebra-rs
/var/log/zebra-rs.log {
    daily
    rotate 7
    compress
    missingok
}
```

### systemd
```ini
[Service]
ExecStart=/usr/local/bin/zebra-rs --daemon --log-output=syslog --log-format=json
```

### Docker
```dockerfile
CMD ["zebra-rs", "--log-output=stdout", "--log-format=json"]
```

### Filebeat
```yaml
filebeat.inputs:
- type: log
  paths: ["/var/log/zebra-rs.log"]
  json.keys_under_root: true
```