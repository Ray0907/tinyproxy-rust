use crate::error::{ProxyError, ProxyResult};
use log::debug;
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: HashMap<String, String>,
}

pub fn parse_http_request(data: &[u8]) -> ProxyResult<HttpRequest> {
    let request_str = String::from_utf8_lossy(data);
    let lines: Vec<&str> = request_str.lines().collect();

    if lines.is_empty() {
        return Err(ProxyError::InvalidRequest("Empty request".to_string()));
    }

    // Parse request line
    let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
    if request_line_parts.len() != 3 {
        return Err(ProxyError::InvalidRequest(
            "Invalid request line format".to_string(),
        ));
    }

    let method = request_line_parts[0].to_string();
    let uri = request_line_parts[1].to_string();
    let version = request_line_parts[2]
        .strip_prefix("HTTP/")
        .unwrap_or("1.1")
        .to_string();

    // Parse headers
    let mut headers = HashMap::new();
    for line in &lines[1..] {
        if line.is_empty() {
            break;
        }

        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim().to_lowercase();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(name, value);
        }
    }

    Ok(HttpRequest {
        method,
        uri,
        version,
        headers,
    })
}

pub async fn copy_bidirectional<R1, W1, R2, W2>(
    mut reader1: R1,
    mut writer1: W1,
    mut reader2: R2,
    mut writer2: W2,
) -> ProxyResult<u64>
where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let mut buf1 = vec![0u8; 8192];
    let mut buf2 = vec![0u8; 8192];
    let mut total_bytes = 0u64;

    loop {
        tokio::select! {
            result1 = reader1.read(&mut buf1) => {
                match result1 {
                    Ok(0) => {
                        debug!("Reader1 EOF reached");
                        break;
                    }
                    Ok(n) => {
                        writer1.write_all(&buf1[..n]).await.map_err(ProxyError::Io)?;
                        writer1.flush().await.map_err(ProxyError::Io)?;
                        total_bytes += n as u64;
                        debug!("Copied {} bytes from reader1 to writer1", n);
                    }
                    Err(e) => {
                        debug!("Reader1 error: {}", e);
                        break;
                    }
                }
            }
            result2 = reader2.read(&mut buf2) => {
                match result2 {
                    Ok(0) => {
                        debug!("Reader2 EOF reached");
                        break;
                    }
                    Ok(n) => {
                        writer2.write_all(&buf2[..n]).await.map_err(ProxyError::Io)?;
                        writer2.flush().await.map_err(ProxyError::Io)?;
                        total_bytes += n as u64;
                        debug!("Copied {} bytes from reader2 to writer2", n);
                    }
                    Err(e) => {
                        debug!("Reader2 error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    debug!("Bidirectional copy completed, total bytes: {}", total_bytes);
    Ok(total_bytes)
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
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

pub fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    for part in hostname.split('.') {
        if part.is_empty() || part.len() > 63 {
            return false;
        }

        if !part.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }

        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
    }

    true
}

pub fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_request() {
        let request_data = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let request = parse_http_request(request_data).unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.uri, "http://example.com/path");
        assert_eq!(request.version, "1.1");
        assert_eq!(
            request.headers.get("host"),
            Some(&"example.com".to_string())
        );
        assert_eq!(request.headers.get("user-agent"), Some(&"test".to_string()));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
    }

    #[test]
    fn test_is_valid_hostname() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("sub.example.com"));
        assert!(is_valid_hostname("test-123.example.com"));

        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-example.com"));
        assert!(!is_valid_hostname("example-.com"));
        assert!(!is_valid_hostname("example..com"));
    }
}
