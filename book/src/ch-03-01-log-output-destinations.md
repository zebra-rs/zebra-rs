# Log Output Destinations

Zebra-rs supports three output destinations for logs, each suited for different deployment scenarios.

## stdout

Sends log messages to standard output. This is the default destination.

```bash
zebra-rs --log-output=stdout
```

**Best for:**
- Development and debugging
- Container deployments with log collection
- Interactive sessions
- Testing and troubleshooting

**Example Output (terminal format):**
```
2025-06-06T06:52:31.157Z  INFO zebra_rs: zebra-rs started
2025-06-06T06:52:31.158Z  INFO zebra_rs::isis::ifsm: Hello originate L1 on eth0
```

## syslog

Sends log messages to the system syslog daemon.

```bash
zebra-rs --log-output=syslog
```

**Best for:**
- System integration
- Centralized logging infrastructure
- Production deployments
- Traditional Unix/Linux environments

**Configuration Details:**
- **Facility**: `LOG_DAEMON`
- **Process Name**: `zebra-rs`
- **Process ID**: Included automatically

**Syslog Example:**
```
Jun 6 06:52:31 router zebra-rs[12345]: zebra-rs started
Jun 6 06:52:31 router zebra-rs[12345]: Hello originate L1 on eth0
```

**Integration with rsyslog:**
```bash
# /etc/rsyslog.d/zebra-rs.conf
if $programname == 'zebra-rs' then /var/log/zebra-rs.log
& stop
```

## file

Writes log messages to a specified file.

```bash
zebra-rs --log-output=file --log-file=/var/log/zebra-rs.log
```

**Best for:**
- Long-term log retention
- Offline analysis
- High-volume logging scenarios
- Environments without syslog

### File Path Resolution

Zebra-rs intelligently handles file paths:

#### Absolute Paths
```bash
zebra-rs --log-output=file --log-file=/var/log/zebra-rs.log
```
- Used exactly as specified
- Directory created if it doesn't exist
- Permission check performed

#### Relative Paths
```bash
zebra-rs --log-output=file --log-file=zebra-rs.log
```

Fallback order:
1. **Current directory**: `./zebra-rs.log`
2. **User home**: `~/.zebra-rs/zebra-rs.log`
3. **System logs**: `/var/log/zebra-rs.log`

### Permission Handling

If the specified path is not writable, zebra-rs automatically tries alternative locations:

```bash
# Attempt 1: Specified path
/var/log/zebra-rs.log

# Attempt 2: User home directory
~/.zebra-rs/zebra-rs.log

# Attempt 3: Current directory
./zebra-rs.log
```

### Log Rotation

For production use with file output, configure log rotation:

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

## Fallback Behavior

When the specified output destination fails, zebra-rs attempts fallbacks:

### Daemon Mode Fallbacks
1. Requested output (e.g., syslog)
2. File output to `zebra-rs.log`
3. Discard logs (if all else fails)

### Interactive Mode Fallbacks
1. Requested output
2. Standard output with basic formatting

This ensures zebra-rs can always start, even in restricted environments.