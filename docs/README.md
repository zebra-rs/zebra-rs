# Zebra-RS Documentation

This directory contains documentation for zebra-rs configuration and operation.

## Available Documentation

### [LOGGING.md](LOGGING.md)
Comprehensive guide to logging configuration in zebra-rs including:
- Command-line options (`--log-output`, `--log-format`, `--log-file`)
- Output destinations (stdout, syslog, file)
- Format types (terminal, JSON, Elasticsearch)
- Protocol-specific logging
- Integration examples
- Troubleshooting and best practices

### [LOGGING-QUICK-REFERENCE.md](LOGGING-QUICK-REFERENCE.md)
Quick reference for logging options including:
- Command syntax summary
- Common use case examples
- Output format samples
- Query patterns and integration snippets

## Getting Started

For most users, start with the [Logging Quick Reference](LOGGING-QUICK-REFERENCE.md) to find the configuration that matches your use case, then refer to the [comprehensive logging guide](LOGGING.md) for detailed information.

### Common Configurations

**Development:**
```bash
zebra-rs --log-output=stdout --log-format=terminal
```

**Production:**
```bash
zebra-rs --daemon --log-output=syslog --log-format=json
```

**Container:**
```bash
zebra-rs --log-output=stdout --log-format=json
```

**Elasticsearch:**
```bash
zebra-rs --log-output=file --log-format=elasticsearch --log-file=/var/log/zebra-rs-es.log
```

## Contributing

When adding new documentation:
1. Follow the existing structure and formatting
2. Include practical examples
3. Update this README with links to new documents
4. Test all command examples before committing