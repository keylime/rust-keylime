// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Output formatting and handling for keylimectl
//!
//! This module provides flexible output formatting capabilities for the keylimectl CLI tool.
//! It supports multiple output formats, animated progress spinners, and optional colors.
//!
//! # Features
//!
//! - **Multiple formats**: JSON, human-readable tables, and YAML-like output
//! - **Structured output**: JSON to stdout, logs to stderr for scriptability
//! - **Progress spinners**: Animated spinners for long-running operations (TTY only)
//! - **Optional colors**: `--color=auto|always|never` for stderr messages
//! - **Wait handles**: RAII spinners for polling loops with auto-cleanup

use crate::error::KeylimectlError;
use console::Style;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use serde_json::Value;
use std::cell::RefCell;
use std::sync::OnceLock;
use std::time::Duration;

/// Global `MultiProgress` that coordinates all spinner rendering with log output.
///
/// All progress bars are created through this instance so that `log` messages
/// (routed via [`SpinnerAwareLogger`](crate::SpinnerAwareLogger)) can suspend
/// rendering before writing, preventing garbled output.
static MULTI_PROGRESS: OnceLock<MultiProgress> = OnceLock::new();

/// Get the global `MultiProgress` instance (lazily initialized).
pub fn get_multi_progress() -> &'static MultiProgress {
    MULTI_PROGRESS.get_or_init(MultiProgress::new)
}

/// Output format options
///
/// Determines how the output will be formatted and displayed to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// JSON output - structured data suitable for machine processing
    Json,
    /// Human-readable table format - formatted for easy reading
    Table,
    /// YAML output - human-readable structured format
    Yaml,
}

impl From<crate::OutputFormat> for Format {
    fn from(format: crate::OutputFormat) -> Self {
        match format {
            crate::OutputFormat::Json => Format::Json,
            crate::OutputFormat::Table => Format::Table,
            crate::OutputFormat::Yaml => Format::Yaml,
        }
    }
}

/// Output handler for formatting and displaying results
///
/// The OutputHandler manages all output formatting, progress spinners, and
/// color styling for keylimectl. Spinners are only shown when stderr is a
/// terminal; piped or redirected output falls back to plain text.
///
/// # Design Principles
///
/// - JSON output goes to stdout for machine processing
/// - Human-readable messages and spinners go to stderr
/// - Quiet mode suppresses non-essential output
/// - Spinners auto-detect TTY; plain text fallback when piped
/// - Colors apply to stderr only; stdout stays plain
#[derive(Debug)]
pub struct OutputHandler {
    format: Format,
    quiet: bool,
    use_spinner: bool,
    use_color: bool,
    active_spinner: RefCell<Option<ProgressBar>>,
    /// Whether the active spinner should leave a permanent trace when finished.
    /// `step()` spinners leave a trace; `progress()` spinners are transient.
    spinner_is_step: RefCell<bool>,
}

impl OutputHandler {
    /// Create a new output handler
    ///
    /// Resolves spinner and color settings based on the color mode and
    /// whether stderr is a terminal.
    pub fn new(
        format: crate::OutputFormat,
        quiet: bool,
        color: crate::ColorMode,
    ) -> Self {
        let is_tty = console::Term::stderr().is_term();
        let use_color = match color {
            crate::ColorMode::Auto => is_tty,
            crate::ColorMode::Always => true,
            crate::ColorMode::Never => false,
        };
        let use_spinner = is_tty && !quiet;

        if !use_color {
            console::set_colors_enabled_stderr(false);
        }

        Self {
            format: format.into(),
            quiet,
            use_spinner,
            use_color,
            active_spinner: RefCell::new(None),
            spinner_is_step: RefCell::new(false),
        }
    }

    /// Output a successful result
    ///
    /// Finishes any active spinner then formats and displays the result.
    /// Output goes to stdout.
    pub fn success(&self, value: Value) {
        self.finish_spinner();

        let output = match self.format {
            Format::Json => self.format_json(value),
            Format::Table => self.format_table(value),
            Format::Yaml => self.format_yaml(value),
        };

        println!("{output}");
    }

    /// Output an error
    ///
    /// Finishes any active spinner then formats and displays the error.
    pub fn error(&self, error: KeylimectlError) {
        self.finish_spinner();

        let error_json = error.to_json();

        match self.format {
            Format::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&error_json)
                        .unwrap_or_default()
                );
            }
            Format::Table | Format::Yaml => {
                let prefix = if self.use_color {
                    format!("{}", Style::new().red().bold().apply_to("Error"))
                } else {
                    "Error".to_string()
                };
                eprintln!("{prefix}: {error}");
                if let Some(details) =
                    error_json.get("error").and_then(|e| e.get("details"))
                {
                    if !details.is_null() {
                        eprintln!(
                            "Details: {}",
                            serde_json::to_string_pretty(details)
                                .unwrap_or_default()
                        );
                    }
                }
            }
        }
    }

    /// Display informational message (only if not quiet)
    ///
    /// Prints directly to stderr (not through `log::info!`) so that
    /// user-facing status messages always appear regardless of log level.
    /// If a spinner is active, it is finished first.
    pub fn info<T: AsRef<str>>(&self, message: T) {
        if self.quiet {
            return;
        }
        self.finish_spinner();
        let msg = message.as_ref();
        let _ = get_multi_progress().println(format!("  {msg}"));
    }

    /// Display a progress message with animated spinner
    ///
    /// When stderr is a TTY, shows an animated spinner. When piped or
    /// in quiet mode, falls back to plain text or suppresses output.
    pub fn progress<T: Into<String>>(&self, message: T) {
        if self.quiet {
            return;
        }

        let msg = message.into();

        if self.use_spinner {
            self.finish_spinner();
            let pb = get_multi_progress().add(ProgressBar::new_spinner());
            pb.set_style(self.spinner_style());
            pb.set_message(msg);
            pb.enable_steady_tick(Duration::from_millis(80));
            *self.active_spinner.borrow_mut() = Some(pb);
            *self.spinner_is_step.borrow_mut() = false;
        } else {
            let _ = get_multi_progress().println(format!("  {msg}"));
        }
    }

    /// Display a step in a multi-step operation with animated spinner
    ///
    /// Shows `[N/TOTAL] message` with a spinner when on a TTY.
    pub fn step<T: AsRef<str>>(&self, step: u8, total: u8, message: T) {
        if self.quiet {
            return;
        }

        let msg = format!("[{step}/{total}] {}", message.as_ref());

        if self.use_spinner {
            self.finish_spinner();
            let pb = get_multi_progress().add(ProgressBar::new_spinner());
            pb.set_style(self.spinner_style());
            pb.set_message(msg);
            pb.enable_steady_tick(Duration::from_millis(80));
            *self.active_spinner.borrow_mut() = Some(pb);
            *self.spinner_is_step.borrow_mut() = true;
        } else {
            let _ = get_multi_progress().println(format!("  {msg}"));
        }
    }

    /// Start a spinner for an indeterminate wait
    ///
    /// Returns a `WaitHandle` that keeps the spinner alive until dropped.
    /// The spinner message can be updated via `WaitHandle::set_message()`.
    /// Useful for polling loops where the wait duration is unknown.
    pub fn start_wait<T: Into<String>>(&self, message: T) -> WaitHandle {
        if self.quiet || !self.use_spinner {
            if !self.quiet {
                let _ = get_multi_progress()
                    .println(format!("  {}", message.into()));
            }
            return WaitHandle { spinner: None };
        }

        self.finish_spinner();
        let pb = get_multi_progress().add(ProgressBar::new_spinner());
        pb.set_style(self.spinner_style());
        pb.set_message(message.into());
        pb.enable_steady_tick(Duration::from_millis(80));

        WaitHandle { spinner: Some(pb) }
    }

    /// Finish any active spinner
    ///
    /// For step spinners, prints the message as a permanent line so that
    /// completed steps always leave a trace even if they finish faster
    /// than a single frame can render. Progress spinners are transient
    /// and disappear silently when replaced.
    pub fn finish_spinner(&self) {
        if let Some(pb) = self.active_spinner.borrow_mut().take() {
            let is_step = *self.spinner_is_step.borrow();
            let msg = pb.message();
            pb.finish_and_clear();
            if is_step && !msg.is_empty() {
                let _ = get_multi_progress().println(format!("  {msg}"));
            }
        }
    }

    /// Build the spinner progress style
    fn spinner_style(&self) -> ProgressStyle {
        let template = if self.use_color {
            "{spinner:.cyan} {msg}"
        } else {
            "{spinner} {msg}"
        };
        ProgressStyle::with_template(template)
            .expect("valid spinner template") //#[allow_ci]
    }

    /// Format value as JSON
    fn format_json(&self, value: Value) -> String {
        serde_json::to_string_pretty(&value)
            .unwrap_or_else(|_| "{}".to_string())
    }

    /// Format value as human-readable table
    fn format_table(&self, value: Value) -> String {
        match value {
            Value::Object(map) => {
                let mut output = String::new();

                if let Some(results) = map.get("results") {
                    match results {
                        Value::Object(results_map) => {
                            if results_map.len() == 1 {
                                let (uuid, agent_data) =
                                    results_map.iter().next().unwrap(); //#[allow_ci]
                                output.push_str(&format!("Agent: {uuid}\n"));
                                output.push_str(
                                    &self.format_agent_table(agent_data),
                                );
                            } else {
                                output.push_str("Agents:\n");
                                for (uuid, agent_data) in results_map {
                                    output.push_str(&format!("  {uuid}:\n"));
                                    output.push_str(
                                        &self.format_agent_table_indented(
                                            agent_data,
                                        ),
                                    );
                                }
                            }
                        }
                        Value::Array(results_array) => {
                            if results_array.is_empty() {
                                output.push_str("(no results)\n");
                            } else {
                                for (i, item) in
                                    results_array.iter().enumerate()
                                {
                                    if i > 0 {
                                        output.push('\n');
                                    }
                                    output.push_str(
                                        &self.format_table_item(item),
                                    );
                                }
                            }
                        }
                        _ => {
                            output.push_str(
                                &serde_json::to_string_pretty(results)
                                    .unwrap_or_default(),
                            );
                        }
                    }
                } else if map.is_empty() {
                    output.push_str("(empty)\n");
                } else {
                    for (key, value) in map {
                        output.push_str(&format!(
                            "{key}: {}\n",
                            self.format_value_brief(&value)
                        ));
                    }
                }

                output
            }
            _ => serde_json::to_string_pretty(&value).unwrap_or_default(),
        }
    }

    /// Format value as YAML
    fn format_yaml(&self, value: Value) -> String {
        self.value_to_yaml(&value, 0)
    }

    /// Format agent data as a table
    fn format_agent_table(&self, agent_data: &Value) -> String {
        let mut output = String::new();

        if let Value::Object(map) = agent_data {
            let important_fields = [
                "operational_state",
                "ip",
                "port",
                "verifier_ip",
                "verifier_port",
            ];

            for field in &important_fields {
                if let Some(value) = map.get(*field) {
                    output.push_str(&format!(
                        "  {field}: {}\n",
                        self.format_value_brief(value)
                    ));
                }
            }

            for (key, value) in map {
                if !important_fields.contains(&key.as_str()) {
                    output.push_str(&format!(
                        "  {key}: {}\n",
                        self.format_value_brief(value)
                    ));
                }
            }
        }

        output
    }

    /// Format agent data as indented table
    fn format_agent_table_indented(&self, agent_data: &Value) -> String {
        self.format_agent_table(agent_data)
            .lines()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    /// Format a table item
    fn format_table_item(&self, item: &Value) -> String {
        match item {
            Value::Object(map) => {
                let mut output = String::new();
                for (key, value) in map {
                    output.push_str(&format!(
                        "{key}: {}\n",
                        self.format_value_brief(value)
                    ));
                }
                output
            }
            _ => format!("{}\n", self.format_value_brief(item)),
        }
    }

    /// Format a value briefly for table display
    #[allow(clippy::only_used_in_recursion)]
    fn format_value_brief(&self, value: &Value) -> String {
        match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "null".to_string(),
            Value::Array(arr) => {
                if arr.is_empty() {
                    "[]".to_string()
                } else if arr.len() == 1 {
                    self.format_value_brief(&arr[0])
                } else {
                    format!("[{} items]", arr.len())
                }
            }
            Value::Object(map) => {
                if map.is_empty() {
                    "{}".to_string()
                } else {
                    format!("{{{} fields}}", map.len())
                }
            }
        }
    }

    /// Convert value to YAML-like format
    fn value_to_yaml(&self, value: &Value, indent: usize) -> String {
        let indent_str = "  ".repeat(indent);

        match value {
            Value::Object(map) => {
                let mut output = String::new();
                for (key, value) in map {
                    match value {
                        Value::Object(_) | Value::Array(_) => {
                            output.push_str(&format!("{indent_str}{key}:\n"));
                            output.push_str(
                                &self.value_to_yaml(value, indent + 1),
                            );
                        }
                        _ => {
                            output.push_str(&format!(
                                "{}{}: {}\n",
                                indent_str,
                                key,
                                self.format_value_brief(value)
                            ));
                        }
                    }
                }
                output
            }
            Value::Array(arr) => {
                let mut output = String::new();
                for item in arr {
                    output.push_str(&format!("{}  - ", "  ".repeat(indent)));
                    match item {
                        Value::Object(_) | Value::Array(_) => {
                            output.push('\n');
                            output.push_str(
                                &self.value_to_yaml(item, indent + 1),
                            );
                        }
                        _ => {
                            output.push_str(&format!(
                                "{}\n",
                                self.format_value_brief(item)
                            ));
                        }
                    }
                }
                output
            }
            _ => {
                format!("{}{}\n", indent_str, self.format_value_brief(value))
            }
        }
    }
}

/// Handle for a long-lived wait spinner
///
/// Created by [`OutputHandler::start_wait()`]. The spinner runs until
/// the handle is dropped (RAII). Use `set_message()` to update the
/// spinner text during polling loops.
pub struct WaitHandle {
    spinner: Option<ProgressBar>,
}

impl WaitHandle {
    /// Update the spinner message
    pub fn set_message(&self, message: impl Into<String>) {
        if let Some(pb) = &self.spinner {
            pb.set_message(message.into());
        }
    }
}

impl Drop for WaitHandle {
    fn drop(&mut self) {
        if let Some(pb) = self.spinner.take() {
            pb.finish_and_clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Create a test handler (no TTY, no spinners, no color)
    fn test_handler(format: crate::OutputFormat) -> OutputHandler {
        OutputHandler {
            format: format.into(),
            quiet: false,
            use_spinner: false,
            use_color: false,
            active_spinner: RefCell::new(None),
            spinner_is_step: RefCell::new(false),
        }
    }

    #[test]
    fn test_format_conversion() {
        assert_eq!(Format::from(crate::OutputFormat::Json), Format::Json);
        assert_eq!(Format::from(crate::OutputFormat::Table), Format::Table);
        assert_eq!(Format::from(crate::OutputFormat::Yaml), Format::Yaml);
    }

    #[test]
    fn test_output_handler_creation() {
        let handler = OutputHandler::new(
            crate::OutputFormat::Json,
            false,
            crate::ColorMode::Never,
        );
        assert_eq!(handler.format, Format::Json);
        assert!(!handler.quiet);

        let quiet_handler = OutputHandler::new(
            crate::OutputFormat::Table,
            true,
            crate::ColorMode::Never,
        );
        assert_eq!(quiet_handler.format, Format::Table);
        assert!(quiet_handler.quiet);
    }

    #[test]
    fn test_format_json() {
        let handler = test_handler(crate::OutputFormat::Json);
        let value = json!({"status": "success", "count": 42});
        let result = handler.format_json(value);

        assert!(result.contains("\"status\": \"success\""));
        assert!(result.contains("\"count\": 42"));
    }

    #[test]
    fn test_format_value_brief() {
        let handler = test_handler(crate::OutputFormat::Table);

        assert_eq!(handler.format_value_brief(&json!("test")), "test");
        assert_eq!(handler.format_value_brief(&json!(42)), "42");
        assert_eq!(handler.format_value_brief(&json!(true)), "true");
        assert_eq!(handler.format_value_brief(&json!(null)), "null");
        assert_eq!(handler.format_value_brief(&json!([])), "[]");
        assert_eq!(handler.format_value_brief(&json!({})), "{}");
        assert_eq!(
            handler.format_value_brief(&json!([1, 2, 3])),
            "[3 items]"
        );
        assert_eq!(
            handler.format_value_brief(&json!({"a": 1, "b": 2})),
            "{2 fields}"
        );
    }

    #[test]
    fn test_format_agent_table() {
        let handler = test_handler(crate::OutputFormat::Table);
        let agent_data = json!({
            "operational_state": "active",
            "ip": "192.168.1.100",
            "port": 9002,
            "verifier_ip": "127.0.0.1",
            "verifier_port": 8881,
            "uuid": "12345-67890",
            "additional_field": "some_value"
        });

        let result = handler.format_agent_table(&agent_data);

        let lines: Vec<&str> = result.lines().collect();
        assert!(lines[0].contains("operational_state: active"));
        assert!(lines[1].contains("ip: 192.168.1.100"));
        assert!(lines[2].contains("port: 9002"));

        assert!(result.contains("uuid: 12345-67890"));
        assert!(result.contains("additional_field: some_value"));
    }

    #[test]
    fn test_format_table_single_agent() {
        let handler = test_handler(crate::OutputFormat::Table);
        let value = json!({
            "results": {
                "12345": {
                    "operational_state": "active",
                    "ip": "192.168.1.100"
                }
            }
        });

        let result = handler.format_table(value);
        assert!(result.starts_with("Agent: 12345"));
        assert!(result.contains("operational_state: active"));
    }

    #[test]
    fn test_format_table_multiple_agents() {
        let handler = test_handler(crate::OutputFormat::Table);
        let value = json!({
            "results": {
                "12345": {"operational_state": "active"},
                "67890": {"operational_state": "failed"}
            }
        });

        let result = handler.format_table(value);
        assert!(result.starts_with("Agents:"));
        assert!(result.contains("12345:"));
        assert!(result.contains("67890:"));
    }

    #[test]
    fn test_format_table_generic_object() {
        let handler = test_handler(crate::OutputFormat::Table);
        let value = json!({
            "status": "success",
            "message": "Operation completed",
            "count": 5
        });

        let result = handler.format_table(value);
        assert!(result.contains("status: success"));
        assert!(result.contains("message: Operation completed"));
        assert!(result.contains("count: 5"));
    }

    #[test]
    fn test_value_to_yaml() {
        let handler = test_handler(crate::OutputFormat::Yaml);
        let value = json!({
            "simple": "value",
            "nested": {
                "inner": "data"
            },
            "array": ["item1", "item2"]
        });

        let result = handler.value_to_yaml(&value, 0);

        assert!(result.contains("simple: value"));
        assert!(result.contains("nested:"));
        assert!(result.contains("  inner: data"));
        assert!(result.contains("array:"));
        assert!(result.contains("  - item1"));
        assert!(result.contains("  - item2"));
    }

    #[test]
    fn test_format_yaml() {
        let handler = test_handler(crate::OutputFormat::Yaml);
        let value = json!({"key": "value", "number": 42});
        let result = handler.format_yaml(value);

        assert!(result.contains("key: value"));
        assert!(result.contains("number: 42"));
    }

    #[test]
    fn test_format_table_item() {
        let handler = test_handler(crate::OutputFormat::Table);

        let obj_item = json!({"name": "test", "value": 123});
        let result = handler.format_table_item(&obj_item);
        assert!(result.contains("name: test"));
        assert!(result.contains("value: 123"));

        let simple_item = json!("simple_value");
        let result = handler.format_table_item(&simple_item);
        assert_eq!(result, "simple_value\n");
    }

    #[test]
    fn test_format_agent_table_indented() {
        let handler = test_handler(crate::OutputFormat::Table);
        let agent_data = json!({
            "operational_state": "active",
            "ip": "192.168.1.100"
        });

        let result = handler.format_agent_table_indented(&agent_data);

        for line in result.lines() {
            if !line.is_empty() {
                assert!(line.starts_with("    "));
            }
        }
    }

    #[test]
    fn test_format_json_error_handling() {
        let handler = test_handler(crate::OutputFormat::Json);

        let valid_json = json!({"test": "value"});
        let result = handler.format_json(valid_json);
        assert!(result.contains("\"test\": \"value\""));
    }

    #[test]
    fn test_edge_cases() {
        let handler = test_handler(crate::OutputFormat::Table);

        let empty_obj = json!({});
        let result = handler.format_table(empty_obj);
        assert!(!result.is_empty());

        let empty_results = json!({"results": []});
        let result = handler.format_table(empty_results);
        assert!(!result.is_empty());

        let simple_value = json!("simple");
        let result = handler.format_table(simple_value);
        assert_eq!(result, "\"simple\"");
    }

    #[test]
    fn test_wait_handle_drop() {
        // WaitHandle with no spinner should not panic on drop
        let handle = WaitHandle { spinner: None };
        drop(handle);
    }

    #[test]
    fn test_wait_handle_set_message_no_spinner() {
        // set_message with no spinner should not panic
        let handle = WaitHandle { spinner: None };
        handle.set_message("test");
    }

    #[test]
    fn test_quiet_mode_suppresses_output() {
        let handler = OutputHandler {
            format: Format::Json,
            quiet: true,
            use_spinner: false,
            use_color: false,
            active_spinner: RefCell::new(None),
            spinner_is_step: RefCell::new(false),
        };

        // These should not panic in quiet mode
        handler.progress("test");
        handler.step(1, 3, "test");
        handler.info("test");
    }
}
