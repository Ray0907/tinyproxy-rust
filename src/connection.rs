use crate::acl::AccessControl;
use crate::auth::Authenticator;
use crate::config::Config;
use crate::error::{ProxyError, ProxyResult};
use crate::filter::Filter;
use crate::stats::Stats;
use crate::utils::{copy_bidirectional, parse_http_request, HttpRequest};

use bytes::BytesMut;
use log::{debug, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};

pub struct ConnectionHandler {
    stream: TcpStream,
    client_addr: SocketAddr,
    config: Arc<Config>,
    stats: Arc<RwLock<Stats>>,
    acl: AccessControl,
    auth: Authenticator,
    filter: Filter,
}

impl ConnectionHandler {
    pub fn new(
        stream: TcpStream,
        client_addr: SocketAddr,
        config: Arc<Config>,
        stats: Arc<RwLock<Stats>>,
    ) -> Self {
        let acl = AccessControl::new(&config);
        let auth = Authenticator::new(&config);
        let filter = Filter::new(&config);

        Self {
            stream,
            client_addr,
            config,
            stats,
            acl,
            auth,
            filter,
        }
    }

    pub async fn handle(mut self) -> ProxyResult<()> {
        debug!("Handling connection from {}", self.client_addr);

        // Check access control
        if !self.acl.is_allowed(&self.client_addr) {
            warn!("Access denied for {}", self.client_addr);
            self.send_error_response(403, "Forbidden").await?;
            return Err(ProxyError::AccessDenied(format!(
                "IP {} is not allowed",
                self.client_addr.ip()
            )));
        }

        // Read the initial request
        let mut buffer = BytesMut::with_capacity(self.config.buffer_size);
        let mut total_read = 0;

        loop {
            let timeout_duration = Duration::from_secs(self.config.timeout);
            let n = timeout(timeout_duration, self.stream.read_buf(&mut buffer))
                .await
                .map_err(|_| ProxyError::Timeout)?
                .map_err(ProxyError::Io)?;

            if n == 0 {
                if total_read == 0 {
                    debug!("Client closed connection before sending any data");
                    return Ok(());
                }
                break;
            }

            total_read += n;

            // Check if we have a complete HTTP request
            if let Some(end_of_headers) = find_end_of_headers(&buffer) {
                let request_data = buffer.split_to(end_of_headers + 4); // +4 for \r\n\r\n
                let request = parse_http_request(&request_data)?;

                return self.handle_request(request, buffer).await;
            }

            // Prevent buffer from growing too large
            if buffer.len() > 16384 {
                return Err(ProxyError::InvalidRequest(
                    "Request headers too large".to_string(),
                ));
            }
        }

        Err(ProxyError::InvalidRequest("Incomplete request".to_string()))
    }

    async fn handle_request(
        &mut self,
        request: HttpRequest,
        remaining_data: BytesMut,
    ) -> ProxyResult<()> {
        debug!(
            "Processing {} {} HTTP/{}",
            request.method, request.uri, request.version
        );

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.requests_processed += 1;
        }

        // Check authentication if required
        if let Some(_) = &self.config.basic_auth {
            if !self.auth.authenticate(&request)? {
                self.send_proxy_auth_required().await?;
                return Err(ProxyError::AuthenticationFailed);
            }
        }

        // Check for statistics request
        if let Some(stat_host) = &self.config.stat_host {
            let host_header = request.headers.get("host").unwrap_or(&request.uri);
            if host_header.contains(stat_host) {
                return self.handle_stats_request().await;
            }
        }

        // Apply filters
        if self.config.filter_urls && !self.filter.is_allowed(&request.uri)? {
            warn!("Request blocked by filter: {}", request.uri);
            self.send_error_response(403, "Forbidden by filter").await?;
            return Err(ProxyError::FilterBlocked(request.uri.clone()));
        }

        // Handle different request methods
        match request.method.as_str() {
            "CONNECT" => self.handle_connect_request(request).await,
            "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" => {
                self.handle_http_request(request, remaining_data).await
            }
            _ => {
                self.send_error_response(405, "Method Not Allowed").await?;
                Err(ProxyError::InvalidRequest(format!(
                    "Unsupported method: {}",
                    request.method
                )))
            }
        }
    }

    async fn handle_connect_request(&mut self, request: HttpRequest) -> ProxyResult<()> {
        debug!("Handling CONNECT request to {}", request.uri);

        // Parse the target host and port
        let (host, port) = parse_host_port(&request.uri)?;

        // Check if the port is allowed for CONNECT requests
        if !self.config.connect_ports.contains(&port) {
            warn!("CONNECT to port {} not allowed", port);
            self.send_error_response(403, "Port not allowed").await?;
            return Err(ProxyError::AccessDenied(format!(
                "CONNECT to port {} is not allowed",
                port
            )));
        }

        // Connect to the target server
        let target_addr = format!("{}:{}", host, port);
        let target_stream = timeout(Duration::from_secs(30), TcpStream::connect(&target_addr))
            .await
            .map_err(|_| ProxyError::Timeout)?
            .map_err(|e| {
                ProxyError::Upstream(format!("Failed to connect to {}: {}", target_addr, e))
            })?;

        debug!("Connected to {}", target_addr);

        // Send 200 Connection Established response
        let response = b"HTTP/1.1 200 Connection established\r\n\r\n";
        self.stream
            .write_all(response)
            .await
            .map_err(ProxyError::Io)?;

        // Start bidirectional copying
        let (client_read, client_write) = self.stream.split();
        let (target_read, target_write) = target_stream.into_split();

        let bytes_transferred =
            copy_bidirectional(client_read, target_write, target_read, client_write).await?;

        debug!(
            "CONNECT tunnel closed, transferred {} bytes",
            bytes_transferred
        );

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.bytes_transferred += bytes_transferred;
        }

        Ok(())
    }

    async fn handle_http_request(
        &mut self,
        request: HttpRequest,
        remaining_data: BytesMut,
    ) -> ProxyResult<()> {
        debug!("Handling HTTP request to {}", request.uri);

        // Handle both absolute and relative URLs
        let (host, port, target_uri) = if request.uri.starts_with("http://") || request.uri.starts_with("https://") {
            // Absolute URL
            let url = url::Url::parse(&request.uri)
                .map_err(|e| ProxyError::InvalidRequest(format!("Invalid URL: {}", e)))?;
            
            let host = url.host_str()
                .ok_or_else(|| ProxyError::InvalidRequest("No host in URL".to_string()))?;
            let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
            
            (host.to_string(), port, request.uri.clone())
        } else {
            // Relative URL - extract host from Host header
            let host = request.headers.get("host")
                .ok_or_else(|| ProxyError::InvalidRequest("No Host header for relative URL".to_string()))?;
            
            // Parse host:port
            let (hostname, port) = if let Some(colon_pos) = host.rfind(':') {
                let hostname = &host[..colon_pos];
                let port_str = &host[colon_pos + 1..];
                let port = port_str.parse::<u16>()
                    .map_err(|_| ProxyError::InvalidRequest(format!("Invalid port in Host header: {}", port_str)))?;
                (hostname.to_string(), port)
            } else {
                (host.clone(), 80)
            };
            
            // Construct absolute URL for upstream
            let target_uri = format!("http://{}:{}{}", hostname, port, request.uri);
            (hostname, port, target_uri)
        };

        // Connect to the target server
        let target_addr = format!("{}:{}", host, port);
        let mut target_stream = timeout(Duration::from_secs(30), TcpStream::connect(&target_addr))
            .await
            .map_err(|_| ProxyError::Timeout)?
            .map_err(|e| {
                ProxyError::Upstream(format!("Failed to connect to {}: {}", target_addr, e))
            })?;

        debug!("Connected to {}", target_addr);

        // Reconstruct and send the HTTP request
        let mut request_data = reconstruct_http_request(&request, &target_uri);
        if !remaining_data.is_empty() {
            request_data.extend_from_slice(&remaining_data);
        }

        target_stream
            .write_all(&request_data)
            .await
            .map_err(ProxyError::Io)?;

        // Start relaying data between client and server
        let (client_read, client_write) = self.stream.split();
        let (target_read, target_write) = target_stream.into_split();

        let bytes_transferred =
            copy_bidirectional(client_read, target_write, target_read, client_write).await?;

        debug!(
            "HTTP request completed, transferred {} bytes",
            bytes_transferred
        );

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.bytes_transferred += bytes_transferred;
        }

        Ok(())
    }

    async fn send_error_response(&mut self, status_code: u16, reason: &str) -> ProxyResult<()> {
        let response = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: text/html\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             <html><body><h1>{} {}</h1></body></html>",
            status_code,
            reason,
            reason.len() + 32, // Approximate HTML length
            status_code,
            reason
        );

        self.stream
            .write_all(response.as_bytes())
            .await
            .map_err(ProxyError::Io)?;
        Ok(())
    }

    async fn send_proxy_auth_required(&mut self) -> ProxyResult<()> {
        let response = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                        Proxy-Authenticate: Basic realm=\"Tinyproxy\"\r\n\
                        Content-Type: text/html\r\n\
                        Content-Length: 72\r\n\
                        Connection: close\r\n\
                        \r\n\
                        <html><body><h1>407 Proxy Authentication Required</h1></body></html>";

        self.stream
            .write_all(response)
            .await
            .map_err(ProxyError::Io)?;
        Ok(())
    }

    async fn handle_stats_request(&mut self) -> ProxyResult<()> {
        debug!("Handling statistics request");

        // Get current statistics
        let stats = self.stats.read().await;
        let stats_html = stats.to_html();

        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache\r\n\
             \r\n\
             {}",
            stats_html.len(),
            stats_html
        );

        self.stream
            .write_all(response.as_bytes())
            .await
            .map_err(ProxyError::Io)?;

        Ok(())
    }
}

fn find_end_of_headers(buffer: &[u8]) -> Option<usize> {
    for i in 0..buffer.len().saturating_sub(3) {
        if &buffer[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

fn parse_host_port(uri: &str) -> ProxyResult<(String, u16)> {
    let parts: Vec<&str> = uri.split(':').collect();
    match parts.len() {
        1 => Ok((parts[0].to_string(), 80)),
        2 => {
            let port = parts[1]
                .parse::<u16>()
                .map_err(|_| ProxyError::InvalidRequest(format!("Invalid port: {}", parts[1])))?;
            Ok((parts[0].to_string(), port))
        }
        _ => Err(ProxyError::InvalidRequest(format!(
            "Invalid host:port format: {}",
            uri
        ))),
    }
}

fn reconstruct_http_request(request: &HttpRequest, target_uri: &str) -> Vec<u8> {
    let mut data = Vec::new();

    // Request line - use the target URI for absolute URLs
    let uri_to_use = if target_uri.starts_with("http://") || target_uri.starts_with("https://") {
        // For absolute URLs, use the original relative path
        &request.uri
    } else {
        target_uri
    };
    
    data.extend_from_slice(
        format!(
            "{} {} HTTP/{}\r\n",
            request.method, uri_to_use, request.version
        )
        .as_bytes(),
    );

    // Headers
    for (name, value) in &request.headers {
        data.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
    }

    // End of headers
    data.extend_from_slice(b"\r\n");

    data
}
