use std::net::{ToSocketAddrs, UdpSocket};

use webrtc::stun::{StunMessage, StunMessageType};

fn main() -> std::io::Result<()> {
    // サーバーにメッセージを送信
    let host = "stun.l.google.com";
    let port = 19302;

    // ホスト名とポートをもとにIPアドレスを取得
    let server_addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unable to resolve domain",
        ))?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    println!("UDPソケットを開きました");

    // サーバーからの応答を受信
    let mut buf = [0; 1024];

    let msg = StunMessage::new(
        StunMessageType::BindingRequest,
        StunMessage::make_new_transaction_id(),
        vec![],
    );

    let size = msg.to_bytes(&mut buf, 0).unwrap();

    // サーバーにメッセージを送信
    let send_size = sock.send_to(&buf[..size], server_addr)?;
    println!(
        "サーバーにメッセージを送信しました: {}: {}",
        send_size, server_addr
    );

    let (recv_size, src) = sock.recv_from(&mut buf)?;
    println!(
        "サーバーからの応答を受信しました: {} バイト from {}",
        recv_size, src
    );

    let recv_msg = StunMessage::from_bytes(&buf, 0, recv_size).unwrap();
    println!(
        "受信したメッセージ: {}: {:?}",
        msg.equals_transaction_id(&recv_msg),
        recv_msg
    );

    // ソケットを閉じる
    drop(sock);
    println!("UDPソケットを閉じました");

    Ok(())
}
