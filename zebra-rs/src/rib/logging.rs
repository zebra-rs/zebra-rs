use std::collections::HashMap;
use std::io;

use chrono::Utc;
use clap::ValueEnum;
use serde_json::json;
use tracing::{Event, Level, Subscriber};
use tracing_appender::rolling;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::registry::LookupSpan;

#[derive(Debug, Clone)]
pub enum LogFormat {
    Json,
    Terminal,
    Elasticsearch,
}

#[derive(Debug, Clone)]
pub enum LoggingOutput {
    Stdout,
    Syslog,
    File(String),
}

#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub output: LoggingOutput,
    pub format: LogFormat,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum LogOutputType {
    Stdout,
    Syslog,
    File,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum LogFormatType {
    Json,
    Terminal,
    Elasticsearch,
}

pub fn logging_config_from_args(
    log_output: &LogOutputType,
    log_file: &Option<String>,
    log_format: &LogFormatType,
) -> LoggingConfig {
    let output = match log_output {
        LogOutputType::Stdout => LoggingOutput::Stdout,
        LogOutputType::Syslog => LoggingOutput::Syslog,
        LogOutputType::File => {
            let path = log_file
                .as_ref()
                .unwrap_or(&"zebra-rs.log".to_string())
                .clone();
            LoggingOutput::File(path)
        }
    };

    let format = match log_format {
        LogFormatType::Json => LogFormat::Json,
        LogFormatType::Terminal => LogFormat::Terminal,
        LogFormatType::Elasticsearch => LogFormat::Elasticsearch,
    };

    LoggingConfig { output, format }
}

/// Custom Elasticsearch-compatible JSON formatter
#[derive(Default)]
pub struct ElasticsearchFormatter;

impl<S, N> FormatEvent<S, N> for ElasticsearchFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let metadata = event.metadata();
        let now = Utc::now();

        // Create base Elasticsearch document
        let mut doc = json!({
            "@timestamp": now.to_rfc3339(),
            "level": metadata.level().to_string().to_lowercase(),
            "target": metadata.target(),
            "message": "",
            "service": {
                "name": "zebra-rs",
                "type": "routing-daemon",
                "version": env!("CARGO_PKG_VERSION")
            },
            "log": {
                "level": metadata.level().to_string().to_lowercase(),
                "logger": metadata.target()
            },
            "host": {
                "hostname": hostname::get().unwrap_or_default().to_string_lossy().into_owned()
            },
            "process": {
                "pid": std::process::id()
            }
        });

        // Extract fields from the event
        let mut visitor = JsonVisitor::new();
        event.record(&mut visitor);

        // Add message
        if let Some(message) = visitor.message {
            doc["message"] = json!(message);
        }

        // Add protocol field if present
        if let Some(proto) = visitor.fields.get("proto") {
            doc["protocol"] = json!(proto);
            doc["service"]["protocol"] = json!(proto);
        }

        // Add all other fields to a fields object
        if !visitor.fields.is_empty() {
            doc["fields"] = json!(visitor.fields);
        }

        // Add metadata for Elasticsearch indexing
        doc["@metadata"] = json!({
            "index": format!("zebra-rs-{}", now.format("%Y.%m.%d")),
            "type": "_doc"
        });

        // Write the JSON document
        writeln!(writer, "{}", doc)?;
        Ok(())
    }
}

/// Visitor to extract fields and message from tracing events
struct JsonVisitor {
    message: Option<String>,
    fields: HashMap<String, serde_json::Value>,
}

impl JsonVisitor {
    fn new() -> Self {
        Self {
            message: None,
            fields: HashMap::new(),
        }
    }
}

impl tracing::field::Visit for JsonVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        if name == "message" {
            self.message = Some(format!("{:?}", value));
        } else {
            self.fields
                .insert(name.to_string(), json!(format!("{:?}", value)));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let name = field.name();
        if name == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.insert(name.to_string(), json!(value));
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
}

pub fn tracing_set(daemon_mode: bool, log_config: Option<LoggingConfig>) {
    // Enable console_subscriber for tokio-console debugging if TOKIO_CONSOLE env var is set
    if std::env::var("TOKIO_CONSOLE").is_ok() {
        console_subscriber::init();
        return;
    }

    let config = if let Some(config) = log_config {
        // Use CLI-specified logging configuration
        config
    } else if daemon_mode {
        // Default daemon mode: use syslog with terminal format
        LoggingConfig {
            output: LoggingOutput::Syslog,
            format: LogFormat::Terminal,
        }
    } else {
        // Default interactive mode: use stdout with terminal format
        LoggingConfig {
            output: LoggingOutput::Stdout,
            format: LogFormat::Terminal,
        }
    };

    // Try to setup the requested logging output with fallbacks
    setup_tracing_with_format(config.output.clone(), config.format.clone()).unwrap_or_else(|e| {
        eprintln!("Failed to setup {:?} logging: {}", config.output, e);

        // Try fallback options
        if daemon_mode {
            // In daemon mode, try file then discard
            setup_tracing_with_format(
                LoggingOutput::File("zebra-rs.log".to_string()),
                LogFormat::Terminal,
            )
            .unwrap_or_else(|e| {
                eprintln!("Failed to setup file logging: {}, discarding logs", e);
                tracing_subscriber::fmt()
                    .with_max_level(Level::INFO)
                    .with_writer(std::io::sink)
                    .init();
            });
        } else {
            // In interactive mode, fallback to basic stdout
            tracing_subscriber::fmt().with_max_level(Level::INFO).init();
        }
    });
}

pub fn setup_tracing_with_format(output: LoggingOutput, format: LogFormat) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    match (output, format) {
        (LoggingOutput::Stdout, LogFormat::Json) => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .init();
        }
        (LoggingOutput::Stdout, LogFormat::Elasticsearch) => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .event_format(ElasticsearchFormatter::default())
                .init();
        }
        (LoggingOutput::Stdout, LogFormat::Terminal) => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .init();
        }
        (LoggingOutput::Syslog, LogFormat::Elasticsearch) => {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::sync::Mutex;
                use syslog::{Facility, Formatter3164};

                // Create a writer that wraps syslog
                struct SyslogWriter {
                    logger: Mutex<syslog::Logger<syslog::LoggerBackend, Formatter3164>>,
                }

                impl SyslogWriter {
                    fn new() -> anyhow::Result<Self> {
                        let formatter = Formatter3164 {
                            facility: Facility::LOG_DAEMON,
                            hostname: None,
                            process: "zebra-rs".to_string(),
                            pid: std::process::id(),
                        };
                        let logger = syslog::unix(formatter)
                            .map_err(|e| anyhow::anyhow!("Failed to connect to syslog: {}", e))?;
                        Ok(SyslogWriter {
                            logger: Mutex::new(logger),
                        })
                    }
                }

                impl Write for SyslogWriter {
                    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                        if let Ok(mut logger) = self.logger.lock() {
                            let msg_cow = String::from_utf8_lossy(buf);
                            let msg = msg_cow.trim();
                            let _ = logger.info(msg);
                        }
                        Ok(buf.len())
                    }

                    fn flush(&mut self) -> io::Result<()> {
                        Ok(())
                    }
                }

                let syslog_writer = SyslogWriter::new()?;
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .event_format(ElasticsearchFormatter::default())
                    .with_writer(Mutex::new(syslog_writer))
                    .init();
            }
            #[cfg(not(unix))]
            {
                return Err(anyhow::anyhow!("Syslog is only supported on Unix systems"));
            }
        }
        (LoggingOutput::Syslog, LogFormat::Json) => {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::sync::Mutex;
                use syslog::{Facility, Formatter3164};

                // Create a writer that wraps syslog
                struct SyslogWriter {
                    logger: Mutex<syslog::Logger<syslog::LoggerBackend, Formatter3164>>,
                }

                impl SyslogWriter {
                    fn new() -> anyhow::Result<Self> {
                        let formatter = Formatter3164 {
                            facility: Facility::LOG_DAEMON,
                            hostname: None,
                            process: "zebra-rs".to_string(),
                            pid: std::process::id(),
                        };
                        let logger = syslog::unix(formatter)
                            .map_err(|e| anyhow::anyhow!("Failed to connect to syslog: {}", e))?;
                        Ok(SyslogWriter {
                            logger: Mutex::new(logger),
                        })
                    }
                }

                impl Write for SyslogWriter {
                    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                        if let Ok(mut logger) = self.logger.lock() {
                            let msg_cow = String::from_utf8_lossy(buf);
                            let msg = msg_cow.trim();
                            let _ = logger.info(msg);
                        }
                        Ok(buf.len())
                    }

                    fn flush(&mut self) -> io::Result<()> {
                        Ok(())
                    }
                }

                let syslog_writer = SyslogWriter::new()?;
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .json()
                    .with_writer(Mutex::new(syslog_writer))
                    .with_target(false)
                    .with_thread_ids(false)
                    .with_file(false)
                    .with_line_number(false)
                    .with_ansi(false)
                    .init();
            }
            #[cfg(not(unix))]
            {
                return Err(anyhow::anyhow!("Syslog is only supported on Unix systems"));
            }
        }
        (LoggingOutput::Syslog, LogFormat::Terminal) => {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::sync::Mutex;
                use syslog::{Facility, Formatter3164};

                // Create a writer that wraps syslog
                struct SyslogWriter {
                    logger: Mutex<syslog::Logger<syslog::LoggerBackend, Formatter3164>>,
                }

                impl SyslogWriter {
                    fn new() -> anyhow::Result<Self> {
                        let formatter = Formatter3164 {
                            facility: Facility::LOG_DAEMON,
                            hostname: None,
                            process: "zebra-rs".to_string(),
                            pid: std::process::id(),
                        };
                        let logger = syslog::unix(formatter)
                            .map_err(|e| anyhow::anyhow!("Failed to connect to syslog: {}", e))?;
                        Ok(SyslogWriter {
                            logger: Mutex::new(logger),
                        })
                    }
                }

                impl Write for SyslogWriter {
                    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                        if let Ok(mut logger) = self.logger.lock() {
                            let msg_cow = String::from_utf8_lossy(buf);
                            let msg = msg_cow.trim();
                            let _ = logger.info(msg);
                        }
                        Ok(buf.len())
                    }

                    fn flush(&mut self) -> io::Result<()> {
                        Ok(())
                    }
                }

                let syslog_writer = SyslogWriter::new()?;
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_writer(Mutex::new(syslog_writer))
                    .with_target(false)
                    .with_thread_ids(false)
                    .with_file(false)
                    .with_line_number(false)
                    .with_ansi(false)
                    .init();
            }
        }
        (LoggingOutput::File(path), LogFormat::Elasticsearch) => {
            // Create a safe fallback path for log files
            let safe_log_path = if path.starts_with('/') {
                // Absolute path - validate and create directory if needed
                let path_obj = std::path::Path::new(&path);
                let parent = path_obj
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("Invalid log file path: {}", path))?;

                // Try to create the directory if it doesn't exist
                if !parent.exists() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to create log directory {}: {}",
                            parent.display(),
                            e
                        )
                    })?;
                }

                // Check if we can write to the directory
                if !parent.exists()
                    || std::fs::metadata(parent)
                        .map(|m| m.permissions().readonly())
                        .unwrap_or(true)
                {
                    return Err(anyhow::anyhow!(
                        "Cannot write to log directory: {}",
                        parent.display()
                    ));
                }

                path.clone()
            } else {
                // Relative path - try current dir first, fallback to user home or /var/log
                let fallback_paths = vec![
                    format!("./{}", path),
                    dirs::home_dir()
                        .map(|mut h| {
                            h.push(".zebra-rs");
                            h.push(&path);
                            h.to_string_lossy().to_string()
                        })
                        .unwrap_or_else(|| format!("/var/log/{}", path)),
                    format!("/var/log/{}", path),
                ];

                let mut chosen_path = None;
                for test_path in fallback_paths {
                    let path_obj = std::path::Path::new(&test_path);
                    let parent = path_obj
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("."));

                    // Try to create directory and test write permission
                    if let Ok(_) = std::fs::create_dir_all(parent) {
                        // Test write permission by trying to create a temp file
                        let test_file = parent.join(".zebra_write_test");
                        if std::fs::write(&test_file, "test").is_ok() {
                            let _ = std::fs::remove_file(&test_file);
                            chosen_path = Some(test_path);
                            break;
                        }
                    }
                }

                chosen_path.ok_or_else(|| {
                    anyhow::anyhow!("Cannot find writable directory for log file: {}", path)
                })?
            };

            // Extract directory and filename from the safe path
            let log_path = std::path::Path::new(&safe_log_path);
            let log_dir = log_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let log_filename = log_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid log filename"))?;

            let writer = rolling::never(log_dir, log_filename);
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .event_format(ElasticsearchFormatter::default())
                .with_writer(writer)
                .init();
        }
        (LoggingOutput::File(path), LogFormat::Json) => {
            // Create a safe fallback path for log files
            let safe_log_path = if path.starts_with('/') {
                // Absolute path - validate and create directory if needed
                let path_obj = std::path::Path::new(&path);
                let parent = path_obj
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("Invalid log file path: {}", path))?;

                // Try to create the directory if it doesn't exist
                if !parent.exists() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to create log directory {}: {}",
                            parent.display(),
                            e
                        )
                    })?;
                }

                // Check if we can write to the directory
                if !parent.exists()
                    || std::fs::metadata(parent)
                        .map(|m| m.permissions().readonly())
                        .unwrap_or(true)
                {
                    return Err(anyhow::anyhow!(
                        "Cannot write to log directory: {}",
                        parent.display()
                    ));
                }

                path.clone()
            } else {
                // Relative path - try current dir first, fallback to user home or /var/log
                let fallback_paths = vec![
                    format!("./{}", path),
                    dirs::home_dir()
                        .map(|mut h| {
                            h.push(".zebra-rs");
                            h.push(&path);
                            h.to_string_lossy().to_string()
                        })
                        .unwrap_or_else(|| format!("/var/log/{}", path)),
                    format!("/var/log/{}", path),
                ];

                let mut chosen_path = None;
                for test_path in fallback_paths {
                    let path_obj = std::path::Path::new(&test_path);
                    let parent = path_obj
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("."));

                    // Try to create directory and test write permission
                    if let Ok(_) = std::fs::create_dir_all(parent) {
                        // Test write permission by trying to create a temp file
                        let test_file = parent.join(".zebra_write_test");
                        if std::fs::write(&test_file, "test").is_ok() {
                            let _ = std::fs::remove_file(&test_file);
                            chosen_path = Some(test_path);
                            break;
                        }
                    }
                }

                chosen_path.ok_or_else(|| {
                    anyhow::anyhow!("Cannot find writable directory for log file: {}", path)
                })?
            };

            // Extract directory and filename from the safe path
            let log_path = std::path::Path::new(&safe_log_path);
            let log_dir = log_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let log_filename = log_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid log filename"))?;

            let writer = rolling::never(log_dir, log_filename);
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .with_writer(writer)
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .with_ansi(false)
                .init();
        }
        (LoggingOutput::File(path), LogFormat::Terminal) => {
            // Create a safe fallback path for log files
            let safe_log_path = if path.starts_with('/') {
                // Absolute path - validate and create directory if needed
                let path_obj = std::path::Path::new(&path);
                let parent = path_obj
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("Invalid log file path: {}", path))?;

                // Try to create the directory if it doesn't exist
                if !parent.exists() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to create log directory {}: {}",
                            parent.display(),
                            e
                        )
                    })?;
                }

                // Check if we can write to the directory
                if !parent.exists()
                    || std::fs::metadata(parent)
                        .map(|m| m.permissions().readonly())
                        .unwrap_or(true)
                {
                    return Err(anyhow::anyhow!(
                        "Cannot write to log directory: {}",
                        parent.display()
                    ));
                }

                path.clone()
            } else {
                // Relative path - try current dir first, fallback to user home or /var/log
                let fallback_paths = vec![
                    format!("./{}", path),
                    dirs::home_dir()
                        .map(|mut h| {
                            h.push(".zebra-rs");
                            h.push(&path);
                            h.to_string_lossy().to_string()
                        })
                        .unwrap_or_else(|| format!("/var/log/{}", path)),
                    format!("/var/log/{}", path),
                ];

                let mut chosen_path = None;
                for test_path in fallback_paths {
                    let path_obj = std::path::Path::new(&test_path);
                    let parent = path_obj
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("."));

                    // Try to create directory and test write permission
                    if let Ok(_) = std::fs::create_dir_all(parent) {
                        // Test write permission by trying to create a temp file
                        let test_file = parent.join(".zebra_write_test");
                        if std::fs::write(&test_file, "test").is_ok() {
                            let _ = std::fs::remove_file(&test_file);
                            chosen_path = Some(test_path);
                            break;
                        }
                    }
                }

                chosen_path.ok_or_else(|| {
                    anyhow::anyhow!("Cannot find writable directory for log file: {}", path)
                })?
            };

            // Extract directory and filename from the safe path
            let log_path = std::path::Path::new(&safe_log_path);
            let log_dir = log_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let log_filename = log_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid log filename"))?;

            let writer = rolling::never(log_dir, log_filename);
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(writer)
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .with_ansi(false)
                .init();
        }
    }
    Ok(())
}

// Compatibility function for code that still uses the old interface
pub fn setup_tracing(output: LoggingOutput) -> anyhow::Result<()> {
    setup_tracing_with_format(output, LogFormat::Terminal)
}
