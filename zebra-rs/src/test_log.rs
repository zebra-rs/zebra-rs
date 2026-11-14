//! Log capture for unit tests that assert on what was, or was not, logged.

use std::cell::RefCell;
use std::fmt::Write;
use std::sync::Once;

use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

thread_local! {
    static CAPTURE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// One event, as `message` then ` name=value` per field.
#[derive(Default)]
struct Line {
    message: String,
    fields: String,
}

impl Visit for Line {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

struct Capture;

impl<S: Subscriber> Layer<S> for Capture {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, _: &Metadata<'_>, _: Context<'_, S>) -> bool {
        CAPTURE.with(|c| c.borrow().is_some())
    }

    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        CAPTURE.with(|c| {
            if let Some(out) = c.borrow_mut().as_mut() {
                let mut line = Line::default();
                event.record(&mut line);
                let _ = writeln!(
                    out,
                    "{} {}{}",
                    event.metadata().level(),
                    line.message,
                    line.fields
                );
            }
        });
    }
}

/// The log lines `f` emits on this thread, as `LEVEL message name=value ...`.
///
/// Captured by one global layer rather than a scoped `with_default`
/// subscriber: tracing caches each callsite's interest process-wide, so a
/// scoped subscriber can miss a callsite another test thread registered while
/// there was none, and the test saw no line at all under the full parallel
/// suite. A test that asserts nothing was logged would pass on that. This
/// layer is installed once, answers every callsite `sometimes`, and records
/// only on a thread that is capturing.
///
/// It is the process's global subscriber, so every test that captures logs
/// has to come through here: a second one could not be installed.
pub fn logs(f: impl FnOnce()) -> String {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(Capture))
            .expect("no other global subscriber in unit tests");
    });
    // A callsite first hit before the layer was installed may still cache
    // the interest it had with no subscriber.
    tracing::callsite::rebuild_interest_cache();
    CAPTURE.with(|c| *c.borrow_mut() = Some(String::new()));
    f();
    CAPTURE.with(|c| c.borrow_mut().take()).unwrap_or_default()
}

/// The WARN lines among [`logs`].
pub fn warnings(f: impl FnOnce()) -> String {
    logs(f)
        .lines()
        .filter(|line| line.starts_with("WARN "))
        .fold(String::new(), |mut out, line| {
            out.push_str(line);
            out.push('\n');
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_level_message_and_fields() {
        let out = logs(|| {
            tracing::warn!(vrf = "V", count = 2, "bgp: something {}", "happened");
            tracing::info!("not a warning");
        });
        assert_eq!(
            out,
            "WARN bgp: something happened vrf=\"V\" count=2\nINFO not a warning\n"
        );
    }

    #[test]
    fn warnings_are_the_warn_lines_only() {
        let out = warnings(|| {
            tracing::info!("not a warning");
            tracing::warn!("one");
            tracing::debug!("nor this");
        });
        assert_eq!(out, "WARN one\n");
    }

    /// The reason the layer is global: a callsite first hit on a thread that
    /// captures nothing must still be seen by one that does.
    #[test]
    fn a_callsite_first_hit_elsewhere_is_still_captured() {
        fn emit() {
            tracing::warn!("from the shared callsite");
        }
        std::thread::spawn(emit).join().unwrap();
        assert_eq!(warnings(emit), "WARN from the shared callsite\n");
    }

    #[test]
    fn nothing_is_captured_outside_the_closure() {
        tracing::warn!("before");
        let out = logs(|| {});
        tracing::warn!("after");
        assert!(out.is_empty(), "{out}");
    }
}
