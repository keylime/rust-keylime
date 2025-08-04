// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Output formatting and handling for keylimectl
//!
//! This module provides flexible output formatting capabilities for the keylimectl CLI tool.
//! It supports multiple output formats and handles both success and error cases.
//!
//! # Features
//!
//! - **Multiple formats**: JSON, human-readable tables, and YAML-like output
//! - **Structured output**: JSON to stdout, logs to stderr for scriptability
//! - **Progress reporting**: Step-by-step progress indicators for multi-step operations
//! - **Error formatting**: Consistent error display across all formats
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::output::{OutputHandler, Format};
//! use serde_json::json;
//!
//! let handler = OutputHandler::new(crate::OutputFormat::Json, false);
//! let data = json!({"status": "success", "message": "Operation completed"});
//! handler.success(data);
//! ```

use crate::error::KeylimectlError;
use log::info;
use serde_json::Value;

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
/// The OutputHandler manages all output formatting and display for keylimectl.
/// It ensures consistent formatting across different output modes and provides
/// utilities for progress reporting and error display.
///
/// # Design Principles
///
/// - JSON output goes to stdout for machine processing
/// - Human-readable messages go to stderr for logging
/// - Quiet mode suppresses non-essential output
/// - Structured error reporting with consistent format
///
/// # Examples
///
/// ```rust
/// use keylimectl::output::OutputHandler;
/// use serde_json::json;
///
/// let handler = OutputHandler::new(crate::OutputFormat::Json, false);
///
/// // Success output
/// handler.success(json!({"result": "success"}));
///
/// // Progress reporting
/// handler.step(1, 3, "Connecting to verifier");
/// handler.step(2, 3, "Validating agent data");
/// handler.step(3, 3, "Adding agent");
///
/// // Information messages
/// handler.info("Operation completed successfully");
/// ```
#[derive(Debug)]
pub struct OutputHandler {
    format: Format,
    quiet: bool,
}

impl OutputHandler {
    /// Create a new output handler
    ///
    /// # Arguments
    ///
    /// * `format` - The output format to use
    /// * `quiet` - Whether to suppress non-essential output
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::output::OutputHandler;
    ///
    /// let handler = OutputHandler::new(crate::OutputFormat::Json, false);
    /// let quiet_handler = OutputHandler::new(crate::OutputFormat::Table, true);
    /// ```
    pub fn new(format: crate::OutputFormat, quiet: bool) -> Self {
        Self {
            format: format.into(),
            quiet,
        }
    }

    /// Output a successful result
    ///
    /// This method formats and displays successful operation results.
    /// The output goes to stdout to support piping and scripting.
    ///
    /// # Arguments
    ///
    /// * `value` - The result data to display
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::output::OutputHandler;
    /// use serde_json::json;
    ///
    /// let handler = OutputHandler::new(crate::OutputFormat::Json, false);
    /// handler.success(json!({"agents": [{"uuid": "12345", "status": "active"}]}));
    /// ```
    pub fn success(&self, value: Value) {
        let output = match self.format {
            Format::Json => self.format_json(value),
            Format::Table => self.format_table(value),
            Format::Yaml => self.format_yaml(value),
        };

        println!("{output}");
    }

    /// Output an error
    ///
    /// This method formats and displays error information consistently
    /// across all output formats. JSON errors go to stdout, while
    /// human-readable errors go to stderr.
    ///
    /// # Arguments
    ///
    /// * `error` - The error to display
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::output::OutputHandler;
    /// use keylimectl::error::KeylimectlError;
    ///
    /// let handler = OutputHandler::new(crate::OutputFormat::Json, false);
    /// let error = KeylimectlError::validation("Invalid UUID format");
    /// handler.error(error);
    /// ```
    pub fn error(&self, error: KeylimectlError) {
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
                // For non-JSON formats, show user-friendly error messages
                eprintln!("Error: {error}");
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
    /// Information messages are logged to stderr and are suppressed in quiet mode.
    /// These messages provide context about what the tool is doing.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to display
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::output::OutputHandler;
    ///
    /// let handler = OutputHandler::new(crate::OutputFormat::Json, false);
    /// handler.info("Connecting to verifier at https://localhost:8881");
    /// ```
    pub fn info<T: AsRef<str>>(&self, message: T) {
        if !self.quiet {
            info!("{}", message.as_ref());
        }
    }

    /// Display a progress message
    ///
    /// Progress messages show the current operation status and are useful
    /// for long-running operations.
    ///
    /// # Arguments
    ///
    /// * `message` - The progress message to display
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::output::OutputHandler;
    ///
    /// let handler = OutputHandler::new(crate::OutputFormat::Json, false);
    /// handler.progress("Downloading agent certificate");
    /// ```
    pub fn progress<T: AsRef<str>>(&self, message: T) {
        if !self.quiet {
            eprintln!("● {}", message.as_ref());
        }
    }

    /// Display a step in a multi-step operation
    ///
    /// Step messages provide numbered progress indicators for operations
    /// that involve multiple stages.
    ///
    /// # Arguments
    ///
    /// * `step` - Current step number (1-based)
    /// * `total` - Total number of steps
    /// * `message` - Description of the current step
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::output::OutputHandler;
    ///
    /// let handler = OutputHandler::new(crate::OutputFormat::Json, false);
    /// handler.step(1, 3, "Validating agent UUID");
    /// handler.step(2, 3, "Connecting to verifier");
    /// handler.step(3, 3, "Adding agent to verifier");
    /// ```
    pub fn step<T: AsRef<str>>(&self, step: u8, total: u8, message: T) {
        if !self.quiet {
            eprintln!("[{step}/{total}] {}", message.as_ref());
        }
    }

    /// Format value as JSON
    ///
    /// Converts a JSON value to a pretty-printed JSON string.
    ///
    /// # Arguments
    ///
    /// * `value` - The JSON value to format
    ///
    /// # Returns
    ///
    /// Pretty-printed JSON string
    fn format_json(&self, value: Value) -> String {
        serde_json::to_string_pretty(&value)
            .unwrap_or_else(|_| "{}".to_string())
    }

    /// Format value as human-readable table
    ///
    /// Converts structured data into a human-readable table format.
    /// This method handles common Keylime response structures and formats
    /// them in an intuitive way.
    ///
    /// # Arguments
    ///
    /// * `value` - The JSON value to format as a table
    ///
    /// # Returns
    ///
    /// Human-readable table string
    fn format_table(&self, value: Value) -> String {
        match value {
            Value::Object(map) => {
                let mut output = String::new();

                // Handle common response structures
                if let Some(results) = map.get("results") {
                    match results {
                        Value::Object(results_map) => {
                            // Single agent result
                            if results_map.len() == 1 {
                                let (uuid, agent_data) =
                                    results_map.iter().next().unwrap(); //#[allow_ci]
                                output.push_str(&format!("Agent: {uuid}\n"));
                                output.push_str(
                                    &self.format_agent_table(agent_data),
                                );
                            } else {
                                // Multiple agents
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
                            // List of items
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
                } else {
                    // Generic object formatting
                    if map.is_empty() {
                        output.push_str("(empty)\n");
                    } else {
                        for (key, value) in map {
                            output.push_str(&format!(
                                "{key}: {}\n",
                                self.format_value_brief(&value)
                            ));
                        }
                    }
                }

                output
            }
            _ => serde_json::to_string_pretty(&value).unwrap_or_default(),
        }
    }

    /// Format value as YAML
    ///
    /// Converts a JSON value to a YAML-like format for human readability.
    /// This is a simplified YAML formatter - for production use, consider
    /// using the serde_yaml crate.
    ///
    /// # Arguments
    ///
    /// * `value` - The JSON value to format as YAML
    ///
    /// # Returns
    ///
    /// YAML-like formatted string
    fn format_yaml(&self, value: Value) -> String {
        // Simple YAML-like formatting
        // For a more complete implementation, could use serde_yaml crate
        self.value_to_yaml(&value, 0)
    }

    /// Format agent data as a table
    ///
    /// Formats agent information in a structured table with important
    /// fields (like operational state and network info) displayed first.
    ///
    /// # Arguments
    ///
    /// * `agent_data` - The agent data to format
    ///
    /// # Returns
    ///
    /// Formatted agent table string
    fn format_agent_table(&self, agent_data: &Value) -> String {
        let mut output = String::new();

        if let Value::Object(map) = agent_data {
            // Format important fields first
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

            // Format remaining fields
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
    ///
    /// Formats agent data with additional indentation for nested display.
    ///
    /// # Arguments
    ///
    /// * `agent_data` - The agent data to format
    ///
    /// # Returns
    ///
    /// Indented agent table string
    fn format_agent_table_indented(&self, agent_data: &Value) -> String {
        self.format_agent_table(agent_data)
            .lines()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    /// Format a table item
    ///
    /// Formats a single item for table display.
    ///
    /// # Arguments
    ///
    /// * `item` - The item to format
    ///
    /// # Returns
    ///
    /// Formatted item string
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
    ///
    /// Converts values to brief, human-readable representations suitable
    /// for table display. Complex objects are summarized rather than
    /// displayed in full.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to format briefly
    ///
    /// # Returns
    ///
    /// Brief string representation
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
    ///
    /// Recursively converts a JSON value to a YAML-like string representation
    /// with proper indentation.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to convert
    /// * `indent` - Current indentation level
    ///
    /// # Returns
    ///
    /// YAML-like formatted string
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_format_conversion() {
        assert_eq!(Format::from(crate::OutputFormat::Json), Format::Json);
        assert_eq!(Format::from(crate::OutputFormat::Table), Format::Table);
        assert_eq!(Format::from(crate::OutputFormat::Yaml), Format::Yaml);
    }

    #[test]
    fn test_output_handler_creation() {
        let handler = OutputHandler::new(crate::OutputFormat::Json, false);
        assert_eq!(handler.format, Format::Json);
        assert!(!handler.quiet);

        let quiet_handler =
            OutputHandler::new(crate::OutputFormat::Table, true);
        assert_eq!(quiet_handler.format, Format::Table);
        assert!(quiet_handler.quiet);
    }

    #[test]
    fn test_format_json() {
        let handler = OutputHandler::new(crate::OutputFormat::Json, false);
        let value = json!({"status": "success", "count": 42});
        let result = handler.format_json(value);

        assert!(result.contains("\"status\": \"success\""));
        assert!(result.contains("\"count\": 42"));
    }

    #[test]
    fn test_format_value_brief() {
        let handler = OutputHandler::new(crate::OutputFormat::Table, false);

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
        let handler = OutputHandler::new(crate::OutputFormat::Table, false);
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

        // Important fields should come first
        let lines: Vec<&str> = result.lines().collect();
        assert!(lines[0].contains("operational_state: active"));
        assert!(lines[1].contains("ip: 192.168.1.100"));
        assert!(lines[2].contains("port: 9002"));

        // Should contain all fields
        assert!(result.contains("uuid: 12345-67890"));
        assert!(result.contains("additional_field: some_value"));
    }

    #[test]
    fn test_format_table_single_agent() {
        let handler = OutputHandler::new(crate::OutputFormat::Table, false);
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
        let handler = OutputHandler::new(crate::OutputFormat::Table, false);
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
        let handler = OutputHandler::new(crate::OutputFormat::Table, false);
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
        let handler = OutputHandler::new(crate::OutputFormat::Yaml, false);
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
        let handler = OutputHandler::new(crate::OutputFormat::Yaml, false);
        let value = json!({"key": "value", "number": 42});
        let result = handler.format_yaml(value);

        assert!(result.contains("key: value"));
        assert!(result.contains("number: 42"));
    }

    #[test]
    fn test_format_table_item() {
        let handler = OutputHandler::new(crate::OutputFormat::Table, false);

        // Test object item
        let obj_item = json!({"name": "test", "value": 123});
        let result = handler.format_table_item(&obj_item);
        assert!(result.contains("name: test"));
        assert!(result.contains("value: 123"));

        // Test non-object item
        let simple_item = json!("simple_value");
        let result = handler.format_table_item(&simple_item);
        assert_eq!(result, "simple_value\n");
    }

    #[test]
    fn test_format_agent_table_indented() {
        let handler = OutputHandler::new(crate::OutputFormat::Table, false);
        let agent_data = json!({
            "operational_state": "active",
            "ip": "192.168.1.100"
        });

        let result = handler.format_agent_table_indented(&agent_data);

        // All lines should be indented with two additional spaces
        for line in result.lines() {
            if !line.is_empty() {
                assert!(line.starts_with("    ")); // 2 spaces from format_agent_table + 2 more
            }
        }
    }

    #[test]
    fn test_format_json_error_handling() {
        let handler = OutputHandler::new(crate::OutputFormat::Json, false);

        // Test with valid JSON
        let valid_json = json!({"test": "value"});
        let result = handler.format_json(valid_json);
        assert!(result.contains("\"test\": \"value\""));

        // format_json should not fail with any valid serde_json::Value
        // since we're already working with parsed JSON
    }

    #[test]
    fn test_edge_cases() {
        let handler = OutputHandler::new(crate::OutputFormat::Table, false);

        // Empty object
        let empty_obj = json!({});
        let result = handler.format_table(empty_obj);
        assert!(!result.is_empty());

        // Empty array in results
        let empty_results = json!({"results": []});
        let result = handler.format_table(empty_results);
        assert!(!result.is_empty());

        // Non-object, non-array value
        let simple_value = json!("simple");
        let result = handler.format_table(simple_value);
        assert_eq!(result, "\"simple\"");
    }
}
