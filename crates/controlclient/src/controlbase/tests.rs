use std::io::Cursor;

use rustscale_key::MachinePrivate;

use super::*;

/// In-process pipe: client writes to a Vec, server reads from a cursor
/// over that Vec, and vice versa. This tests the full handshake transcript
/// and post-handshake framing without real network.
#[test]
fn handshake_client_server_roundtrip() {
    let server_key = MachinePrivate::generate();
    let client_key = MachinePrivate::generate();
    let server_pub = server_key.public();
    let version: ProtocolVersion = 1;

    // Client: build initiation.
    let deferred = client_deferred(&client_key, &server_pub, version);
    let init = deferred.init.clone();

    // Server: process initiation, write response.
    let mut server_writer = Vec::new();
    let mut init_reader = Cursor::new(&init);
    let server_conn = server_handshake(
        &mut init_reader,
        &mut server_writer,
        &server_key,
        Some(&init),
    )
    .expect("server handshake");

    // Client: read server response, finalize.
    let mut resp_reader = Cursor::new(&server_writer);
    let client_conn = deferred
        .continue_handshake(&mut resp_reader)
        .expect("client handshake");

    // Both sides should agree on the handshake hash.
    assert_eq!(
        client_conn.handshake_hash(),
        server_conn.handshake_hash(),
        "client and server disagree on handshake hash"
    );

    // Protocol version matches.
    assert_eq!(client_conn.protocol_version(), version);
    assert_eq!(server_conn.protocol_version(), version);

    // Peer keys match.
    assert_eq!(
        client_conn.peer().raw32(),
        server_pub.raw32(),
        "client peer should be server key"
    );
    assert_eq!(
        server_conn.peer().raw32(),
        client_key.public().raw32(),
        "server peer should be client key"
    );
}

/// Post-handshake framing: client writes, server reads and vice versa.
#[test]
fn post_handshake_framing_roundtrip() {
    let server_key = MachinePrivate::generate();
    let client_key = MachinePrivate::generate();
    let server_pub = server_key.public();

    // Handshake.
    let deferred = client_deferred(&client_key, &server_pub, 1);
    let init = deferred.init.clone();

    let mut server_writer = Vec::new();
    let mut server_conn = server_handshake(
        &mut Cursor::new(&[]),
        &mut server_writer,
        &server_key,
        Some(&init),
    )
    .unwrap();

    let mut resp_reader = Cursor::new(&server_writer);
    let mut client_conn = deferred.continue_handshake(&mut resp_reader).unwrap();

    // Client -> server: write a record, server reads it.
    let msg1 = b"hello from client";
    let mut client_tx = Vec::new();
    client_conn.write_record(&mut client_tx, msg1).unwrap();

    let mut server_rx = Cursor::new(&client_tx);
    let received1 = server_conn.read_record(&mut server_rx).unwrap();
    assert_eq!(received1, msg1);

    // Server -> client: write a record, client reads it.
    let msg2 = b"hello from server";
    let mut server_tx = Vec::new();
    server_conn.write_record(&mut server_tx, msg2).unwrap();

    let mut client_rx = Cursor::new(&server_tx);
    let received2 = client_conn.read_record(&mut client_rx).unwrap();
    assert_eq!(received2, msg2);
}

/// Verify that multiple records can be written and read in sequence,
/// and that nonces increment correctly (no reuse).
#[test]
fn multiple_records_sequential() {
    let server_key = MachinePrivate::generate();
    let client_key = MachinePrivate::generate();
    let server_pub = server_key.public();

    let deferred = client_deferred(&client_key, &server_pub, 1);
    let init = deferred.init.clone();

    let mut server_writer = Vec::new();
    let mut server_conn = server_handshake(
        &mut Cursor::new(&[]),
        &mut server_writer,
        &server_key,
        Some(&init),
    )
    .unwrap();

    let mut client_conn = deferred
        .continue_handshake(&mut Cursor::new(&server_writer))
        .unwrap();

    // Write three records from client to server.
    let messages: Vec<Vec<u8>> = vec![
        b"first".to_vec(),
        b"second message".to_vec(),
        b"third and final".to_vec(),
    ];

    let mut all_frames = Vec::new();
    for msg in &messages {
        client_conn.write_record(&mut all_frames, msg).unwrap();
    }

    let mut reader = Cursor::new(&all_frames);
    for expected in &messages {
        let received = server_conn.read_record(&mut reader).unwrap();
        assert_eq!(received, *expected);
    }
}

/// The initiation message should be exactly 101 bytes.
#[test]
fn initiation_message_size() {
    let server_key = MachinePrivate::generate();
    let client_key = MachinePrivate::generate();
    let deferred = client_deferred(&client_key, &server_key.public(), 1);
    assert_eq!(deferred.init.len(), 101);
}

/// Tamper detection: flipping any byte of the initiation should cause
/// the server handshake to fail (mirrors Go's TestTampering, spot-checked).
#[test]
fn tamper_initiation_byte_0_fails() {
    let server_key = MachinePrivate::generate();
    let client_key = MachinePrivate::generate();

    let deferred = client_deferred(&client_key, &server_key.public(), 1);
    let mut tampered = deferred.init.clone();
    tampered[0] ^= 0x01; // tamper with protocol version byte

    let mut writer = Vec::new();
    let result = server_handshake(
        &mut Cursor::new(&[]),
        &mut writer,
        &server_key,
        Some(&tampered),
    );
    assert!(result.is_err(), "server should reject tampered initiation");
}

/// Different handshakes with fresh ephemeral keys should produce different
/// handshake hashes (no key reuse).
#[test]
fn handshake_hashes_are_unique() {
    let server_key = MachinePrivate::generate();
    let client_key = MachinePrivate::generate();
    let server_pub = server_key.public();

    let mut hashes = std::collections::HashSet::new();
    for _ in 0..5 {
        let deferred = client_deferred(&client_key, &server_pub, 1);
        let init = deferred.init.clone();

        let mut sw = Vec::new();
        let sc =
            server_handshake(&mut Cursor::new(&[]), &mut sw, &server_key, Some(&init)).unwrap();
        let cc = deferred.continue_handshake(&mut Cursor::new(&sw)).unwrap();

        assert_eq!(cc.handshake_hash(), sc.handshake_hash());
        hashes.insert(cc.handshake_hash());
    }
    assert_eq!(hashes.len(), 5, "each handshake should have a unique hash");
}
