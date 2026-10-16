// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Stream relays stalled on a target that never reads end with their carrier.
//! Its own binary: it reads the process-wide relay gauge.

use std::time::Duration;

use e2e_harness::*;
use redsocket_http::metrics::active_relays;
use tokio::io::AsyncWriteExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_stream_relays_end_with_their_carrier() {
    redsocket_http::proxy::init_destination_policy(Some(&[]), &[]);
    let server = start_server().await;
    let sink = tokio::net::TcpSocket::new_v4().unwrap();
    sink.set_recv_buffer_size(4096).unwrap();
    sink.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    let sink = sink.listen(16).unwrap();
    let never_read = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((c, _)) = sink.accept().await {
            held.push(c);
        }
    });

    let before = active_relays();
    let carrier = MuxClient::connect(&server, "MUX2|UTC|rostam||0123456789abcdef||")
        .await
        .unwrap();
    for _ in 0..4 {
        let mut s = carrier
            .request(&trimmed("127.0.0.1", sink_port))
            .await
            .unwrap();
        expect_ok(&mut s).await.unwrap();
        tokio::spawn(async move {
            let chunk = vec![0u8; 64 * 1024];
            while s.write_all(&chunk).await.is_ok() {}
        });
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(active_relays(), before + 4, "the stalled relays are live");

    drop(carrier);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while active_relays() != before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{} relays outlived their carrier",
            active_relays() - before
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    never_read.abort();
}
