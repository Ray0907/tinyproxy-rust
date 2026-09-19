#!/usr/bin/env python3
"""Apply only the reviewed experimental socket option to an isolated checkout.

Baseline executable must be copied before running this script. The resulting
binary and git diff are reported separately; no repository ref is changed.
"""
from pathlib import Path
import sys
root = Path(sys.argv[1])
p = root / 'src/connection.rs'
s = p.read_text()
old = '    let negotiate = async {'
assert s.count(old) == 1
s = s.replace(old, '    stream.set_nodelay(true)?;\n' + old)
p.write_text(s)
p = root / 'src/transport.rs'
s = p.read_text()
assert s.count('pub async fn connect(') == 1
s = s.replace('pub async fn connect(', 'async fn connect_inner(', 1)
s += '''

/// Experimental low-latency socket option; no framing or policy changes.
pub async fn connect(
    host: &str,
    port: u16,
    bind: Option<IpAddr>,
    seconds: u64,
) -> io::Result<TcpStream> {
    let stream = connect_inner(host, port, bind, seconds).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}
'''
p.write_text(s)
