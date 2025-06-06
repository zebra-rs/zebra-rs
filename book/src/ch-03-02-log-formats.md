# Log Formats

Zebra-rs supports three log formats, each optimized for different use cases.

## terminal

Human-readable format optimized for console viewing. This is the default format.

```bash
zebra-rs --log-format=terminal
```

**Features:**
- Timestamp in ISO 8601 format
- Color coding (when terminal supports it)
- Compact, readable layout
- Module path information for debugging

**Example:**
```
2025-06-06T06:52:31.157Z  INFO zebra_rs: zebra-rs started
2025-06-06T06:52:31.158Z  INFO zebra_rs::isis::ifsm: Hello originate L1 on eth0
2025-06-06T06:52:31.159Z  WARN zebra_rs::isis::link: DIS flapping detected, applying dampening for 30 seconds
2025-06-06T06:52:31.160Z ERROR zebra_rs::bgp::peer: Connection refused: 192.168.1.1:179
```

**Log Level Indicators:**
- `TRACE` - Detailed trace information
- `DEBUG` - Debug information
- `INFO` - Informational messages
- `WARN` - Warning conditions
- `ERROR` - Error conditions

## json

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

**Field Description:**
- `timestamp`: ISO 8601 timestamp
- `level`: Log level (TRACE, DEBUG, INFO, WARN, ERROR)
- `target`: Module path where log originated
- `fields`: Structured data including message and custom fields

**Protocol Fields:**

ISIS logs include protocol information:
```json
{
  "fields": {
    "message": "DIS selection: self on eth0 (priority: 64, neighbors: 2)",
    "proto": "isis"
  }
}
```

## elasticsearch

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
- ECS (Elastic Common Schema) compatible fields

**Example:**
```json
{
  "@timestamp": "2025-06-06T06:52:31.157888414+00:00",
  "level": "info",
  "target": "zebra_rs::isis::ifsm",
  "message": "Hello originate L1 on eth0",
  "protocol": "isis",
  "service": {
    "name": "zebra-rs",
    "type": "routing-daemon",
    "version": "0.6.9",
    "protocol": "isis"
  },
  "log": {
    "level": "info",
    "logger": "zebra_rs::isis::ifsm"
  },
  "host": {
    "hostname": "router-1"
  },
  "process": {
    "pid": 12345
  },
  "fields": {
    "proto": "isis"
  },
  "@metadata": {
    "index": "zebra-rs-2025.06.06",
    "type": "_doc"
  }
}
```

**Elasticsearch Benefits:**
- Direct ingestion without transformation
- Daily index rotation support
- Rich metadata for filtering
- Service discovery and correlation
- Compatible with Kibana visualizations

### Index Pattern

The `@metadata.index` field suggests daily indices:
- Pattern: `zebra-rs-YYYY.MM.DD`
- Example: `zebra-rs-2025.06.06`

This enables:
- Automatic index lifecycle management
- Time-based retention policies
- Efficient time-range queries

### Integration Example

```yaml
# Filebeat configuration
filebeat.inputs:
- type: log
  paths:
    - /var/log/zebra-rs.log
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "%{[@metadata][index]}"
```

## Choosing a Format

| Use Case | Recommended Format | Reason |
|----------|-------------------|---------|
| Development | `terminal` | Human-readable, easy debugging |
| System Logs | `json` | Structured, parseable |
| Log Analytics | `elasticsearch` | Rich metadata, direct ingestion |
| Containers | `json` or `elasticsearch` | Structured for collectors |
| Debugging | `terminal` | Quick visual scanning |

## Format Comparison

| Feature | terminal | json | elasticsearch |
|---------|----------|------|---------------|
| Human Readable | ✓ | ✗ | ✗ |
| Machine Parseable | ✗ | ✓ | ✓ |
| Colored Output | ✓ | ✗ | ✗ |
| Structured Data | ✗ | ✓ | ✓ |
| Service Metadata | ✗ | ✗ | ✓ |
| Daily Indices | ✗ | ✗ | ✓ |
| ECS Compatible | ✗ | ✗ | ✓ |