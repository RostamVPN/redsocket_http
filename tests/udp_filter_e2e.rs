// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A UDP association hands the client datagrams only from addresses it has
//! sent to. Its own binary: it opens the destination policy to loopback.

use std::time::Duration;

use e2e_harness::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

/// The target is on `::1` and the stranger on `127.0.0.1`: the association's
/// `[::]` socket hears both, and filtering is by address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_association_drops_datagrams_from_strangers() {
    redsocket_http::proxy::init_destination_policy(Some(&[]), &[]);
    let server = start_server().await;
    let target = UdpSocket::bind("[::1]:0").await.unwrap();
    let carrier = MuxClient::connect(&server, "MUX2|UTC|rostam||0123456789abcdef||")
        .await
        .unwrap();
    let mut s = carrier.request(&[0x05, 0xFD]).await.unwrap();
    expect_ok(&mut s).await.unwrap();

    let mut d = vec![0u8, 0, 0];
    d.extend_from_slice(&trimmed("::1", target.local_addr().unwrap().port())[1..]);
    d.extend_from_slice(b"ping");
    s.write_all(&(d.len() as u16).to_be_bytes()).await.unwrap();
    s.write_all(&d).await.unwrap();
    s.flush().await.unwrap();
    let mut buf = [0u8; 64];
    let (n, assoc) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"ping");

    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stranger
        .send_to(b"injected", ("127.0.0.1", assoc.port()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    target.send_to(b"pong", assoc).await.unwrap();

    let mut len = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut len))
        .await
        .unwrap()
        .unwrap();
    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut frame).await.unwrap();
    assert_eq!(frame[3], 4, "the first datagram must come from the target");
    assert_eq!(&frame[4..20], &std::net::Ipv6Addr::LOCALHOST.octets());
    assert_eq!(&frame[22..], b"pong");
}
