//! Half-close-safe relay for Hyper's HTTP/2 CONNECT upgrade adapter.
use std::io;
use std::time::Duration;
use tokio::io::{copy, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{interval_at, Instant, MissedTickBehavior};

/// Hyper 1.11 maps received CANCEL/NO_ERROR resets to read EOF. Its upgrade
/// writer, however, exposes the reset through poll_flush. A plain bidirectional
/// copy can therefore mistake RST_STREAM for END_STREAM and retain an idle TCP
/// socket indefinitely. Check the writer every 250ms without sending bytes.
///
/// This is deliberately restricted to the H2 upgrade adapter. Normal TCP/H1
/// tunnels still use Tokio copy_bidirectional. Independent copying preserves
/// real half-close; a reset error aborts both directions. The outer exchange
/// enforces idle/forced-shutdown deadlines. The tick does not count as activity.
pub async fn relay<C, T>(client: C, target: T) -> io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = split(client);
    let (mut target_read, mut target_write) = split(target);
    let upload = async {
        let count = copy(&mut client_read, &mut target_write).await?;
        target_write.shutdown().await?;
        Ok::<_, io::Error>(count)
    };
    let download = async {
        let period = Duration::from_millis(250);
        let mut check = interval_at(Instant::now() + period, period);
        check.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Keep the backing buffer out of the nested async state machines.
        // Capacity stays bounded at 8 KiB; this does not buffer a whole body.
        let mut buffer = vec![0u8; 8192];
        let mut count = 0u64;
        loop {
            tokio::select! {
                read = target_read.read(&mut buffer) => {
                    let size = read?;
                    if size == 0 {
                        client_write.shutdown().await?;
                        return Ok::<_, io::Error>(count);
                    }
                    client_write.write_all(&buffer[..size]).await?;
                    count += size as u64;
                }
                _ = check.tick() => {
                    // Also observes remote resets when target_read is idle.
                    client_write.flush().await?;
                }
            }
        }
    };
    tokio::try_join!(upload, download)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_future_does_not_embed_bulk_buffers() {
        let (client, _client_peer) = tokio::io::duplex(64);
        let (target, _target_peer) = tokio::io::duplex(64);
        let future = relay(client, target);
        assert!(
            std::mem::size_of_val(&future) < 4096,
            "relay future unexpectedly embeds a bulk buffer"
        );
    }
}
