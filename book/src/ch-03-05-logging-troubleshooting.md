# Logging Troubleshooting

This chapter covers common issues with logging configuration and their solutions.

## Common Issues

### Permission Denied

**Problem**: Cannot write to log file
```
Failed to setup File("/var/log/zebra-rs.log") logging: Cannot write to log directory: /var/log
```

**Solutions:**

1. **Use a writable directory**:
   ```bash
   zebra-rs --log-output=file --log-file=./zebra-rs.log
   ```

2. **Create directory with proper permissions**:
   ```bash
   sudo mkdir -p /var/log/zebra-rs
   sudo chown $USER:$USER /var/log/zebra-rs
   zebra-rs --log-output=file --log-file=/var/log/zebra-rs/router.log
   ```

3. **Run with appropriate privileges**:
   ```bash
   sudo zebra-rs --log-output=file --log-file=/var/log/zebra-rs.log
   ```

### Syslog Connection Failed

**Problem**: Cannot connect to syslog
```
Failed to setup Syslog logging: Failed to connect to syslog: Connection refused
```

**Solutions:**

1. **Verify syslog daemon is running**:
   ```bash
   # For systemd systems
   systemctl status rsyslog
   systemctl start rsyslog
   
   # For other init systems
   service rsyslog status
   service rsyslog start
   ```

2. **Check syslog socket exists**:
   ```bash
   ls -la /dev/log
   # Should show a socket file
   ```

3. **Use alternative output**:
   ```bash
   zebra-rs --log-output=file --log-file=./zebra-rs.log
   ```

### Log File Growing Too Large

**Problem**: Log file consumes too much disk space

**Solutions:**

1. **Implement log rotation**:
   ```bash
   # /etc/logrotate.d/zebra-rs
   /var/log/zebra-rs.log {
       daily
       rotate 7
       compress
       delaycompress
       missingok
       notifempty
       create 0644 zebra zebra
       postrotate
           # Signal zebra-rs to reopen log files if needed
           systemctl reload zebra-rs 2>/dev/null || true
       endscript
   }
   ```

2. **Use syslog with built-in rotation**:
   ```bash
   zebra-rs --log-output=syslog --log-format=json
   ```

3. **Monitor disk usage**:
   ```bash
   # Add monitoring
   df -h /var/log
   du -sh /var/log/zebra-rs.log
   ```

### No Logs Appearing

**Problem**: Zebra-rs is running but no logs are visible

**Diagnostic Steps:**

1. **Check log level**:
   ```bash
   # Default is INFO, set to DEBUG for more output
   RUST_LOG=debug zebra-rs
   ```

2. **Verify output destination**:
   ```bash
   # Check current configuration
   ps aux | grep zebra-rs
   ```

3. **Test with stdout first**:
   ```bash
   zebra-rs --log-output=stdout --log-format=terminal
   ```

4. **Check file permissions**:
   ```bash
   ls -la /var/log/zebra-rs.log
   # Ensure the process user can write
   ```

### JSON Parsing Errors

**Problem**: Log collectors cannot parse JSON output

**Solutions:**

1. **Validate JSON format**:
   ```bash
   # Check if logs are valid JSON
   tail -1 /var/log/zebra-rs.log | jq .
   ```

2. **Check for mixed formats**:
   ```bash
   # Look for non-JSON lines
   grep -v "^{" /var/log/zebra-rs.log
   ```

3. **Ensure consistent format**:
   ```bash
   # Always specify format explicitly
   zebra-rs --log-format=json
   ```

### High CPU from Logging

**Problem**: Excessive CPU usage due to logging

**Solutions:**

1. **Reduce log verbosity**:
   ```bash
   # Use WARN or ERROR level for production
   RUST_LOG=warn zebra-rs
   ```

2. **Filter specific modules**:
   ```bash
   # Disable debug logs from chatty modules
   RUST_LOG=info,zebra_rs::isis::packet=warn zebra-rs
   ```

3. **Use efficient output**:
   ```bash
   # File output is generally more efficient than syslog
   zebra-rs --log-output=file --log-format=json
   ```

## Diagnostic Commands

### Check Log Configuration

```bash
# View running process arguments
ps aux | grep zebra-rs | grep -v grep

# Check environment variables
tr '\0' '\n' < /proc/$(pgrep zebra-rs)/environ | grep RUST_LOG
```

### Test Log Output

```bash
# Test file write permissions
touch /var/log/test-zebra-rs.log && rm /var/log/test-zebra-rs.log

# Test syslog connectivity
logger -t zebra-rs-test "Test message"
tail /var/log/syslog | grep zebra-rs-test
```

### Analyze Log Patterns

```bash
# Count log entries by level
jq -r .level /var/log/zebra-rs.log | sort | uniq -c

# Find most common messages
jq -r .message /var/log/zebra-rs.log | sort | uniq -c | sort -rn | head

# Check log rate
tail -f /var/log/zebra-rs.log | pv -l -i 10 > /dev/null
```

### Debug Logging Issues

```bash
# Run with maximum verbosity
RUST_LOG=trace zebra-rs --log-output=stdout --log-format=terminal

# Trace system calls
strace -e trace=write,open,connect zebra-rs 2>&1 | grep -E "(log|syslog)"

# Check file descriptors
ls -la /proc/$(pgrep zebra-rs)/fd/
```

## Performance Optimization

### Reduce Log Volume

1. **Adjust log levels by module**:
   ```bash
   RUST_LOG=zebra_rs=info,zebra_rs::isis::packet=warn,zebra_rs::bgp::update=warn
   ```

2. **Use sampling for high-frequency logs**:
   ```rust
   // In code: log every Nth occurrence
   if counter % 100 == 0 {
       log::info!("Processed {} packets", counter);
   }
   ```

### Optimize Output

1. **Batch writes**: Use buffered output
2. **Async logging**: File output with async I/O
3. **Local caching**: Use local syslog with forwarding

### Monitor Impact

```bash
# CPU usage by zebra-rs
top -p $(pgrep zebra-rs)

# I/O statistics
iotop -p $(pgrep zebra-rs)

# Log write rate
watch -n 1 'ls -la /var/log/zebra-rs.log | awk "{print \$5}"'
```

## Recovery Procedures

### When Logging Fails

1. **Automatic fallback**: Zebra-rs tries alternative outputs
2. **Manual recovery**:
   ```bash
   # Restart with different output
   systemctl stop zebra-rs
   zebra-rs --log-output=stdout --log-format=terminal
   ```

### Clearing Log Backlogs

```bash
# Safely truncate large log file
cp /var/log/zebra-rs.log /var/log/zebra-rs.log.backup
> /var/log/zebra-rs.log

# Or use logrotate manually
logrotate -f /etc/logrotate.d/zebra-rs
```

### Emergency Logging

When all else fails:
```bash
# Minimal logging to stdout
zebra-rs 2>&1 | tee emergency.log

# Or completely disable logging
RUST_LOG=off zebra-rs
```

## Monitoring Checklist

- [ ] Log files are being created
- [ ] Log rotation is working
- [ ] Disk space is adequate
- [ ] Log format is consistent
- [ ] Timestamps are accurate
- [ ] No permission errors
- [ ] Log collectors are receiving data
- [ ] Indices are created (Elasticsearch)
- [ ] Retention policies are applied
- [ ] Alerts are configured for errors