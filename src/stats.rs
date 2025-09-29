use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    // Connection statistics
    pub connections_opened: u64,
    pub connections_closed: u64,
    pub active_connections: u64,
    pub total_connection_time: Duration,

    // Request statistics
    pub requests_processed: u64,
    pub requests_denied: u64,
    pub requests_failed: u64,

    // Data transfer statistics
    pub bytes_transferred: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,

    // Performance statistics
    pub average_request_time: Duration,
    pub peak_connections: u64,

    // Filter statistics
    pub requests_filtered: u64,

    // Authentication statistics
    pub auth_attempts: u64,
    pub auth_failures: u64,

    // Server statistics
    pub start_time: DateTime<Utc>,
    pub uptime: Duration,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            connections_opened: 0,
            connections_closed: 0,
            active_connections: 0,
            total_connection_time: Duration::new(0, 0),

            requests_processed: 0,
            requests_denied: 0,
            requests_failed: 0,

            bytes_transferred: 0,
            bytes_sent: 0,
            bytes_received: 0,

            average_request_time: Duration::new(0, 0),
            peak_connections: 0,

            requests_filtered: 0,

            auth_attempts: 0,
            auth_failures: 0,

            start_time: Utc::now(),
            uptime: Duration::new(0, 0),
        }
    }

    pub fn update_uptime(&mut self) {
        self.uptime = Utc::now()
            .signed_duration_since(self.start_time)
            .to_std()
            .unwrap_or_default();
    }

    pub fn update_peak_connections(&mut self) {
        if self.active_connections > self.peak_connections {
            self.peak_connections = self.active_connections;
        }
    }

    pub fn calculate_average_request_time(&mut self) {
        if self.requests_processed > 0 {
            let total_nanos = self.total_connection_time.as_nanos();
            let avg_nanos = total_nanos / self.requests_processed as u128;
            self.average_request_time = Duration::from_nanos(avg_nanos as u64);
        }
    }

    pub fn get_success_rate(&self) -> f64 {
        let total_requests = self.requests_processed + self.requests_failed;
        if total_requests == 0 {
            0.0
        } else {
            (self.requests_processed as f64 / total_requests as f64) * 100.0
        }
    }

    pub fn get_auth_success_rate(&self) -> f64 {
        if self.auth_attempts == 0 {
            0.0
        } else {
            let successes = self.auth_attempts - self.auth_failures;
            (successes as f64 / self.auth_attempts as f64) * 100.0
        }
    }

    pub fn to_html(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Tinyproxy Statistics</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .section {{ margin-bottom: 30px; }}
        .metric {{ margin: 10px 0; }}
        .value {{ font-weight: bold; color: #2c3e50; }}
    </style>
</head>
<body>
    <h1>Tinyproxy Statistics</h1>
    
    <div class="section">
        <h2>Server Information</h2>
        <div class="metric">Start Time: <span class="value">{}</span></div>
        <div class="metric">Uptime: <span class="value">{}</span></div>
    </div>

    <div class="section">
        <h2>Connection Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Active Connections</td><td class="value">{}</td></tr>
            <tr><td>Total Connections Opened</td><td class="value">{}</td></tr>
            <tr><td>Total Connections Closed</td><td class="value">{}</td></tr>
            <tr><td>Peak Connections</td><td class="value">{}</td></tr>
            <tr><td>Average Connection Time</td><td class="value">{:.2}s</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Request Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Requests Processed</td><td class="value">{}</td></tr>
            <tr><td>Requests Denied</td><td class="value">{}</td></tr>
            <tr><td>Requests Failed</td><td class="value">{}</td></tr>
            <tr><td>Requests Filtered</td><td class="value">{}</td></tr>
            <tr><td>Success Rate</td><td class="value">{:.1}%</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Data Transfer</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Bytes Transferred</td><td class="value">{}</td></tr>
            <tr><td>Bytes Sent</td><td class="value">{}</td></tr>
            <tr><td>Bytes Received</td><td class="value">{}</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Authentication Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Authentication Attempts</td><td class="value">{}</td></tr>
            <tr><td>Authentication Failures</td><td class="value">{}</td></tr>
            <tr><td>Authentication Success Rate</td><td class="value">{:.1}%</td></tr>
        </table>
    </div>

    <p><em>Generated at: {}</em></p>
</body>
</html>"#,
            self.start_time.format("%Y-%m-%d %H:%M:%S UTC"),
            format_duration(&self.uptime),
            self.active_connections,
            self.connections_opened,
            self.connections_closed,
            self.peak_connections,
            self.average_request_time.as_secs_f64(),
            self.requests_processed,
            self.requests_denied,
            self.requests_failed,
            self.requests_filtered,
            self.get_success_rate(),
            format_bytes(self.bytes_transferred),
            format_bytes(self.bytes_sent),
            format_bytes(self.bytes_received),
            self.auth_attempts,
            self.auth_failures,
            self.get_auth_success_rate(),
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

fn format_duration(duration: &Duration) -> String {
    let total_seconds = duration.as_secs();
    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_creation() {
        let stats = Stats::new();
        assert_eq!(stats.connections_opened, 0);
        assert_eq!(stats.requests_processed, 0);
        assert_eq!(stats.bytes_transferred, 0);
    }

    #[test]
    fn test_success_rate_calculation() {
        let mut stats = Stats::new();
        stats.requests_processed = 80;
        stats.requests_failed = 20;

        assert_eq!(stats.get_success_rate(), 80.0);
    }

    #[test]
    fn test_auth_success_rate() {
        let mut stats = Stats::new();
        stats.auth_attempts = 100;
        stats.auth_failures = 10;

        assert_eq!(stats.get_auth_success_rate(), 90.0);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(&Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(&Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(&Duration::from_secs(3661)), "1h 1m 1s");
        assert_eq!(format_duration(&Duration::from_secs(90061)), "1d 1h 1m 1s");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
    }
}
