# Tinyproxy-Rust

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-GPL%20v3-blue)
![Language](https://img.shields.io/badge/language-Rust-orange)

A modern, lightweight, and memory-safe HTTP/HTTPS proxy written in Rust. This project is a complete rewrite of the classic [tinyproxy](https://github.com/tinyproxy/tinyproxy), rewritten in rust.

## 📋 Implementation Status

This Rust implementation addresses many of the TODO items from the [original tinyproxy TODO list](https://github.com/tinyproxy/tinyproxy/blob/master/TODO):

### ✅ **Fully Implemented**

- **✅ Modular Proxy Architecture**: Complete modular design with separate modules for different proxy types (HTTP, filtering, authentication, ACL)
- **✅ User Authentication**: Full HTTP Basic authentication support with configurable username/password pairs (`src/auth.rs`)
- **✅ Consistent Error Logging**: Modern structured logging using `log` and `thiserror` crates with unified error handling (`src/error.rs`)
- **✅ Memory Debugging Removal**: Rust's ownership system eliminates memory leaks by design, no manual memory management needed
- **✅ Single Return Point Functions**: Rust's `Result<T>` type enforces consistent error handling patterns
- **✅ Header Order Issues**: N/A for Rust (this was a C-specific problem with `common.h`)

### 🔶 **Partially Implemented**

- **🔶 Request Rewriting**: Basic URL handling exists, but lacks full RegEx rewriting capabilities
- **🔶 External Filtering**: Built-in filtering system with regex/domain/exact matching (`src/filter.rs`), but no external program filtering
- **🔶 Header Rewriting**: Basic header processing with support for anonymous headers, Via headers, and custom headers, but lacks full bidirectional rewriting

### ❌ **Not Yet Implemented**

- **❌ chroot() Jailing**: Security sandboxing feature not implemented
- **❌ External Data Filtering**: Ability to pipe connection data through external filtering programs

### 🚀 **Rust-Specific Improvements**

Beyond the original TODO list, this implementation provides:

- **Async/Await Architecture**: High-performance concurrent connection handling with tokio
- **Type Safety**: Compile-time prevention of common programming errors
- **Comprehensive Statistics**: Detailed connection, request, and authentication metrics (`src/stats.rs`)
- **Modern Configuration**: Flexible configuration parsing with multiple format support
- **Complete Test Coverage**: Unit tests and benchmarks for reliability

## 📦 Getting Started

### Prerequisites

- **Rust:** Ensure you have the Rust toolchain installed. You can get it from [rustup.rs](https://rustup.rs/).
- **k6:** For running the performance benchmarks. ([Install k6](https://k6.io/docs/getting-started/installation/))
- **Original Tinyproxy:** For performance comparison. (e.g., `brew install tinyproxy` on macOS).

### Installation & Building

- **Build the release binary:**
  ```sh
  cargo build --release
  ```
  The executable will be located at `target/release/tinyproxy-rust`.

## ⚙️ Usage

1.  **Create a configuration file** (e.g., `config.toml`):

    ```toml
    # The address to bind to.
    Listen = "0.0.0.0"

    # The port to listen on.
    Port = 8888

    # Number of worker threads to use.
    Threads = 4

    # Log level (Error, Warn, Info, Debug, Trace)
    LogLevel = "Info"

    # Path to the PID file.
    PidFile = "/tmp/tinyproxy-rust.pid"
    ```

2.  **Run the proxy:**

    ```sh
    ./target/release/tinyproxy -c config.toml
    ```

3.  **Test the connection:**
    ```sh
    curl -x http://127.0.0.1:8888 http://httpbin.org/ip
    ```

## 🔧 Configuration

The proxy supports the same configuration format as the original tinyproxy. See `config/tinyproxy-rust.conf` for a full example with all available options.

Key configuration options include:

- **Port**: Listen port (default: 8888)
- **User/Group**: Process user/group
- **MaxClients**: Maximum concurrent connections
- **BasicAuth**: HTTP Basic authentication
- **Allow/Deny**: Access control rules
- **Filter**: URL/domain filtering
- **Upstream**: Upstream proxy configuration
- **ConnectPort**: Allowed CONNECT ports

## 📊 Performance & Benchmarks

Run the included benchmarks to compare performance:

```sh
cargo bench
```

The Rust implementation typically shows significant performance improvements over the original C version, especially under high concurrency loads, while maintaining memory safety.

## 🤝 Contributing

We welcome contributions! Here are some areas where help is needed:

### High Priority TODOs

- [ ] **chroot/Sandboxing Support**: Implement container-based or chroot jailing for enhanced security
- [ ] **Advanced Request Rewriting**: Add full RegEx-based URL rewriting capabilities
- [ ] **External Filter Programs**: Support piping data through external filtering applications

### Medium Priority

- [ ] **Enhanced Header Rewriting**: Complete bidirectional request/response header manipulation
- [ ] **Performance Optimizations**: Further async improvements and connection pooling
- [ ] **Additional Proxy Types**: SOCKS5, FTP proxy support

Please feel free to open issues or submit pull requests!

---

---

## 📝 Original TODO List Implementation Status

Below is a detailed mapping of the [original tinyproxy TODO items](https://github.com/tinyproxy/tinyproxy/blob/master/TODO) and their implementation status in this Rust version:

| Original TODO Item                                | Status          | Implementation Details                                                                    |
| ------------------------------------------------- | --------------- | ----------------------------------------------------------------------------------------- |
| **Modular proxy hooks for different proxy types** | ✅ **Complete** | Fully modular architecture with separate modules (`auth.rs`, `filter.rs`, `acl.rs`, etc.) |
| **Function to rewrite incoming requests**         | 🔶 **Partial**  | Basic URL handling implemented, RegEx rewriting needs enhancement                         |
| **External filtering program support**            | ❌ **Pending**  | Built-in filtering exists, but external program piping not implemented                    |
| **Bidirectional header rewriting**                | 🔶 **Partial**  | Basic header manipulation available, full bidirectional rewriting needed                  |
| **chroot() jailing option**                       | ❌ **Pending**  | Critical security feature, high priority for implementation                               |
| **Consistent error logging**                      | ✅ **Complete** | Modern structured logging with `log` crate and unified error handling                     |
| **User authentication**                           | ✅ **Complete** | Full HTTP Basic auth with configurable credentials and realm                              |
| **Remove common.h and fix headers**               | ✅ **N/A**      | C-specific issue, not applicable to Rust implementation                                   |
| **Remove memory debugging functions**             | ✅ **Complete** | Rust's ownership system eliminates need for manual memory management                      |
| **Single return point functions**                 | ✅ **Complete** | Rust's `Result<T>` pattern enforces consistent error handling                             |
