// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! WebSocket framing — RFC 6455 server-side codec.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;

const OP_CONT: u8 = 0x0;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

const MAX_FRAME: u64 = 16 * 1024 * 1024;
/// Largest control-frame payload (RFC 6455 §5.5).
const MAX_CONTROL: u64 = 125;
const DUPLEX_CAP: usize = 16 * 1024;

/// Wrap a post-101 socket in the WS codec. Data frames are streamed into the
/// tunnel as their bytes arrive, so neither a declared length nor a fragmented
/// message is buffered ahead of it, and the frame reader ends when the tunnel's
/// end of the pipe is gone.
pub fn wrap(stream: TcpStream, leftover: Vec<u8>) -> DuplexStream {
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let (tunnel_end, pump_end) = tokio::io::duplex(DUPLEX_CAP);
    let (mut pump_r, mut pump_w) = tokio::io::split(pump_end);
    let (rd, wr) = stream.into_split();
    let wr = Arc::new(Mutex::new(wr));

    let wr_reader = wr.clone();
    let reader = tokio::spawn(async move {
        let mut rd = std::io::Cursor::new(leftover).chain(rd);
        let mut buf = vec![0u8; DUPLEX_CAP];
        'frames: while let Some((op, len, mask)) = read_header(&mut rd).await {
            if op >= OP_CLOSE {
                if len > MAX_CONTROL {
                    break;
                }
                let payload = &mut buf[..len as usize];
                if rd.read_exact(payload).await.is_err() {
                    break;
                }
                unmask(payload, mask, 0);
                match op {
                    OP_CLOSE => {
                        let mut w = wr_reader.lock().await;
                        let _ = w.write_all(&frame_bytes(OP_CLOSE, &[])).await;
                        let _ = w.flush().await;
                        break;
                    }
                    OP_PING => {
                        let mut w = wr_reader.lock().await;
                        if w.write_all(&frame_bytes(OP_PONG, payload)).await.is_err()
                            || w.flush().await.is_err()
                        {
                            break;
                        }
                    }
                    _ => {}
                }
                continue;
            }
            let data = matches!(op, OP_BINARY | OP_CONT);
            let mut done = 0u64;
            while done < len {
                let want = (len - done).min(buf.len() as u64) as usize;
                let n = match rd.read(&mut buf[..want]).await {
                    Ok(0) | Err(_) => break 'frames,
                    Ok(n) => n,
                };
                unmask(&mut buf[..n], mask, done);
                if data && pump_w.write_all(&buf[..n]).await.is_err() {
                    break 'frames;
                }
                done += n as u64;
            }
        }
        let _ = pump_w.shutdown().await;
    });

    tokio::spawn(async move {
        let mut up_buf = vec![0u8; 32 * 1024];
        loop {
            let n = match pump_r.read(&mut up_buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut w = wr.lock().await;
            if w.write_all(&frame_bytes(OP_BINARY, &up_buf[..n]))
                .await
                .is_err()
            {
                break;
            }
            if w.flush().await.is_err() {
                break;
            }
        }
        reader.abort();
        let _ = wr.lock().await.shutdown().await;
    });

    tunnel_end
}

fn frame_bytes(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 10);
    v.push(0x80 | op);
    if payload.len() < 126 {
        v.push(payload.len() as u8);
    } else if payload.len() <= 0xFFFF {
        v.push(126);
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        v.push(127);
        v.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    v.extend_from_slice(payload);
    v
}

/// Read a frame header: (opcode, payload length, mask). None on EOF, error or a
/// length above [`MAX_FRAME`]. An unmasked frame gets the all-zero mask.
async fn read_header<R: AsyncRead + Unpin>(rd: &mut R) -> Option<(u8, u64, [u8; 4])> {
    let mut h = [0u8; 2];
    rd.read_exact(&mut h).await.ok()?;
    let len = match h[1] & 0x7F {
        126 => u64::from(rd.read_u16().await.ok()?),
        127 => rd.read_u64().await.ok()?,
        n => u64::from(n),
    };
    if len > MAX_FRAME {
        return None;
    }
    let mut mask = [0u8; 4];
    if h[1] & 0x80 != 0 {
        rd.read_exact(&mut mask).await.ok()?;
    }
    Some((h[0] & 0x0F, len, mask))
}

/// Unmask `data`, which starts `at` bytes into its frame's payload.
fn unmask(data: &mut [u8], mask: [u8; 4], at: u64) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= mask[(at as usize + i) & 3];
    }
}

/// RFC 6455 §4.2.2 accept key: base64(SHA-1(key + GUID)).
pub fn accept_key(key: &str) -> String {
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(key.as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A server socket wrapped in the codec, and the client end of it.
    async fn pair() -> (DuplexStream, TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (server, _) = l.accept().await.unwrap();
        (wrap(server, Vec::new()), client)
    }

    /// A client frame header declaring `len` payload bytes, masked with zeros so
    /// the payload goes on the wire as it is.
    fn header(op: u8, fin: bool, len: u64) -> Vec<u8> {
        let mut h = vec![if fin { 0x80 | op } else { op }];
        match len {
            0..=125 => h.push(0x80 | len as u8),
            126..=0xFFFF => {
                h.push(0x80 | 126);
                h.extend_from_slice(&(len as u16).to_be_bytes());
            }
            _ => {
                h.push(0x80 | 127);
                h.extend_from_slice(&len.to_be_bytes());
            }
        }
        h.extend_from_slice(&[0; 4]);
        h
    }

    /// Nothing is held back for a FIN or for the rest of a declared length.
    #[tokio::test]
    async fn data_reaches_the_tunnel_before_its_message_or_frame_ends() {
        let (mut tunnel, mut client) = pair().await;
        let mut wire = header(OP_BINARY, false, 3);
        wire.extend_from_slice(b"abc");
        wire.extend(header(OP_CONT, true, 1 << 20));
        wire.extend_from_slice(b"def");
        client.write_all(&wire).await.unwrap();
        let mut got = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(2), tunnel.read_exact(&mut got))
            .await
            .expect("bytes were buffered instead of streamed")
            .unwrap();
        assert_eq!(&got, b"abcdef");
    }

    #[tokio::test]
    async fn an_oversized_control_frame_ends_the_stream() {
        let (mut tunnel, mut client) = pair().await;
        let mut wire = header(OP_PING, true, MAX_CONTROL + 1);
        wire.extend_from_slice(&[0u8; MAX_CONTROL as usize + 1]);
        client.write_all(&wire).await.unwrap();
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), tunnel.read(&mut b))
            .await
            .expect("the stream stayed open")
            .unwrap();
        assert_eq!(n, 0);
    }

    /// Once the tunnel end is dropped the socket is closed, so a client that keeps
    /// sending is refused instead of read for ever.
    #[tokio::test]
    async fn dropping_the_tunnel_end_closes_the_socket() {
        let (tunnel, mut client) = pair().await;
        drop(tunnel);
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "the server must close its side");
        let mut frame = header(OP_BINARY, false, 4);
        frame.extend_from_slice(b"more");
        let refused = async {
            while client.write_all(&frame).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(2), refused)
                .await
                .is_ok(),
            "the server kept reading after its tunnel was gone"
        );
    }
}
