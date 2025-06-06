# Logging Integration

This chapter covers how to integrate zebra-rs logging with popular log management and monitoring systems.

## Elasticsearch Stack

### Direct Ingestion with Filebeat

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/zebra-rs.log
  json.keys_under_root: true
  json.add_error_key: true
  
  # Use elasticsearch format
  processors:
    - decode_json_fields:
        fields: ["message"]
        target: ""

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "%{[@metadata][index]}"
  
setup.template.enabled: false
setup.ilm.enabled: false
```

### Logstash Pipeline

```ruby
# zebra-rs.conf
input {
  file {
    path => "/var/log/zebra-rs.log"
    codec => "json"
    type => "zebra-rs"
  }
}

filter {
  # Add environment information
  mutate {
    add_field => {
      "environment" => "${ENVIRONMENT:production}"
      "datacenter" => "${DATACENTER:us-east-1}"
    }
  }
  
  # Extract protocol to top level if exists
  if [fields][proto] {
    mutate {
      add_field => { "protocol" => "%{[fields][proto]}" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["${ELASTICSEARCH_HOSTS:localhost:9200}"]
    index => "%{[@metadata][index]}"
    document_type => "%{[@metadata][type]}"
  }
}
```

### Kibana Dashboards

Create visualizations for routing protocols:

```json
{
  "version": "7.17.0",
  "objects": [
    {
      "attributes": {
        "title": "Zebra-RS Protocol Distribution",
        "visState": {
          "type": "pie",
          "aggs": [
            {
              "id": "1",
              "type": "count",
              "schema": "metric"
            },
            {
              "id": "2",
              "type": "terms",
              "schema": "segment",
              "params": {
                "field": "protocol",
                "size": 10
              }
            }
          ]
        }
      }
    }
  ]
}
```

## Syslog Integration

### rsyslog Configuration

```bash
# /etc/rsyslog.d/50-zebra-rs.conf

# Create template for JSON logs
template(name="ZebraJSON" type="string"
  string="%msg:2:$%\n")

# Filter zebra-rs messages
if $programname == 'zebra-rs' then {
  # Write to separate file
  action(type="omfile" 
         file="/var/log/zebra-rs.log"
         template="ZebraJSON")
  
  # Forward to central syslog
  action(type="omfwd"
         target="syslog.example.com"
         port="514"
         protocol="tcp"
         template="ZebraJSON")
         
  # Stop processing
  stop
}
```

### syslog-ng Configuration

```
# /etc/syslog-ng/conf.d/zebra-rs.conf

source s_zebra {
    system();
};

filter f_zebra {
    program("zebra-rs");
};

parser p_json {
    json-parser(prefix(".json."));
};

destination d_zebra_file {
    file("/var/log/zebra-rs.log"
         template("${MESSAGE}\n"));
};

destination d_elastic {
    elasticsearch-http(
        url("http://localhost:9200/_bulk")
        index("zebra-rs-${YEAR}.${MONTH}.${DAY}")
        type("_doc")
        template("$(format-json --scope rfc5424 --scope dot-nv-pairs)")
    );
};

log {
    source(s_zebra);
    filter(f_zebra);
    parser(p_json);
    destination(d_zebra_file);
    destination(d_elastic);
};
```

## Container Platforms

### Docker

```dockerfile
# Dockerfile
FROM debian:bullseye-slim
COPY zebra-rs /usr/local/bin/
CMD ["zebra-rs", "--log-output=stdout", "--log-format=json"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  zebra-rs:
    image: zebra-rs:latest
    command: 
      - "--log-output=stdout"
      - "--log-format=elasticsearch"
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "service=routing,protocol=multi"
    
  # Log collector sidecar
  filebeat:
    image: elastic/filebeat:7.17.0
    volumes:
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
```

### Kubernetes

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zebra-rs
spec:
  template:
    spec:
      containers:
      - name: zebra-rs
        image: zebra-rs:latest
        args:
          - "--log-output=stdout"
          - "--log-format=elasticsearch"
        env:
        - name: RUST_LOG
          value: "info"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
```

```yaml
# fluent-bit-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
data:
  fluent-bit.conf: |
    [SERVICE]
        Parsers_File parsers.conf
        
    [INPUT]
        Name tail
        Path /var/log/containers/zebra-rs*.log
        Parser docker
        Tag zebra.routing
        
    [FILTER]
        Name parser
        Match zebra.*
        Key_Name log
        Parser json
        
    [OUTPUT]
        Name es
        Match zebra.*
        Host elasticsearch
        Port 9200
        Index zebra-rs
        Type _doc
```

## Monitoring Integration

### Prometheus with mtail

```python
# /etc/mtail/zebra-rs.mtail
# Count protocol events
counter protocol_events_total by protocol, level

# Track adjacency changes
counter adjacency_changes_total by protocol, state

# Monitor errors
counter errors_total by protocol, module

# Extract metrics from JSON logs
/^\{.*"proto":"(?P<protocol>\w+)".*"level":"(?P<level>\w+)"/ {
  protocol_events_total[$protocol][$level]++
  
  /"message":".*State Transition.*(?P<from>\w+) -> (?P<to>\w+)"/ {
    adjacency_changes_total[$protocol][$to]++
  }
  
  $level == "error" {
    /"target":"(?P<module>[^"]+)"/ {
      errors_total[$protocol][$module]++
    }
  }
}
```

### Grafana Loki

```yaml
# promtail-config.yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: zebra-rs
    static_configs:
      - targets:
          - localhost
        labels:
          job: zebra-rs
          __path__: /var/log/zebra-rs*.log
    
    pipeline_stages:
      - json:
          expressions:
            level: level
            protocol: protocol
            message: message
            timestamp: '"@timestamp"'
            
      - labels:
          level:
          protocol:
          
      - timestamp:
          source: timestamp
          format: RFC3339Nano
```

## Log Aggregation Patterns

### Multi-Instance Deployment

```bash
# Instance 1 - BGP focused
zebra-rs --log-file=/var/log/zebra-rs-bgp.log \
         --log-format=elasticsearch

# Instance 2 - ISIS focused  
zebra-rs --log-file=/var/log/zebra-rs-isis.log \
         --log-format=elasticsearch

# Aggregation with Filebeat
filebeat.inputs:
- type: log
  paths:
    - /var/log/zebra-rs-*.log
  fields:
    service: zebra-rs
  fields_under_root: true
```

### Centralized Logging Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Router 1   │     │  Router 2   │     │  Router 3   │
│  zebra-rs   │     │  zebra-rs   │     │  zebra-rs   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │ syslog            │ syslog            │ syslog
       └───────────────────┴───────────────────┘
                           │
                    ┌──────▼──────┐
                    │   rsyslog   │
                    │   server    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Logstash   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │Elasticsearch│
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Kibana    │
                    └─────────────┘
```

## Best Practices

1. **Use Structured Formats**: JSON or Elasticsearch format for automated processing
2. **Include Metadata**: Leverage protocol fields and service information
3. **Time Synchronization**: Ensure NTP is configured for accurate timestamps
4. **Index Management**: Implement retention policies for log indices
5. **Security**: Use TLS for log transmission and authentication for access
6. **Monitoring**: Alert on log volume anomalies and error rates
7. **Buffering**: Configure appropriate buffers in log collectors
8. **Compression**: Enable compression for long-term storage