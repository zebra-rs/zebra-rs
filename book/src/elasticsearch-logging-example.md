# Elasticsearch-Compatible Logging Example

## Command Usage

```bash
# Output to stdout with Elasticsearch format
./zebra-rs --log-format=elasticsearch --log-output=stdout

# Output to file with Elasticsearch format  
./zebra-rs --log-format=elasticsearch --log-output=file --log-file=zebra-rs-es.log

# Output to syslog with Elasticsearch format
./zebra-rs --log-format=elasticsearch --log-output=syslog
```

## Example Output

### Standard Log Entry
```json
{
  "@timestamp": "2025-06-06T06:52:31.157888414+00:00",
  "level": "info",
  "target": "zebra_rs",
  "message": "zebra-rs started",
  "service": {
    "name": "zebra-rs",
    "type": "routing-daemon",
    "version": "0.6.9"
  },
  "log": {
    "level": "info",
    "logger": "zebra_rs"
  },
  "host": {
    "hostname": "ubuntu"
  },
  "process": {
    "pid": 491697
  },
  "@metadata": {
    "index": "zebra-rs-2025.06.06",
    "type": "_doc"
  }
}
```

### Protocol-Specific Log Entry (ISIS)
```json
{
  "@timestamp": "2025-06-06T06:52:31.158123456+00:00",
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
    "hostname": "ubuntu"
  },
  "process": {
    "pid": 491697
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

## Elasticsearch Integration

### Index Template
```json
{
  "index_patterns": ["zebra-rs-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "level": {"type": "keyword"},
        "message": {"type": "text"},
        "protocol": {"type": "keyword"},
        "service": {
          "properties": {
            "name": {"type": "keyword"},
            "type": {"type": "keyword"},
            "version": {"type": "keyword"},
            "protocol": {"type": "keyword"}
          }
        },
        "host": {
          "properties": {
            "hostname": {"type": "keyword"}
          }
        },
        "process": {
          "properties": {
            "pid": {"type": "long"}
          }
        }
      }
    },
    "settings": {
      "index": {
        "lifecycle": {
          "name": "zebra-rs-policy",
          "rollover_alias": "zebra-rs"
        }
      }
    }
  }
}
```

### Example Kibana Queries

```
# All ISIS protocol logs
protocol:isis

# Error logs from the last hour
level:error AND @timestamp:[now-1h TO now]

# Logs from specific host
host.hostname:router-1

# Service-specific logs
service.name:zebra-rs AND service.type:routing-daemon

# BGP protocol errors
protocol:bgp AND level:error
```

## Benefits

1. **Time-based Analysis**: RFC3339 timestamps enable precise time filtering
2. **Service Discovery**: Structured service metadata for multi-daemon environments  
3. **Protocol Filtering**: Easy filtering by routing protocol (ISIS, BGP, OSPF)
4. **Index Management**: Daily indices enable automated retention policies
5. **Performance**: Optimized field structure for Elasticsearch queries
6. **Correlation**: Process and host fields enable cross-service analysis