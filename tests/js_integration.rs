mod common;

use futures::SinkExt;
use futures_lite::StreamExt;
use hypercore_handshake::{Cipher, CipherEvent, Error, state_machine::SecStream};
use tokio::{join, net::TcpListener};
use tokio_util::compat::TokioAsyncReadCompatExt;
use uint24le_framing::Uint24LELengthPrefixedFraming;

use rusty_nodejs_repl::{Config, Repl};

use common::{
    LOOPBACK, Result,
    js::{REQUIRE_JS, path_to_node_modules},
};

async fn setup_rust_responder_js_initiator() -> Result<(Repl, Cipher)> {
    let _ = &*REQUIRE_JS;
    let kp = hypercore_handshake::state_machine::hc_specific::generate_keypair()?;

    let listener = TcpListener::bind(format!("{}:0", LOOPBACK)).await?;
    let port = listener.local_addr()?.port();
    let hostname = LOOPBACK;
    let setup_rs = async move {
        let tcp = listener.accept().await?.0;

        // Setup Cipher here
        let framed = Uint24LELengthPrefixedFraming::new(tcp.compat());
        let resp = SecStream::new_responder(&kp.private)?;
        let cipher = Cipher::new_resp(Box::new(framed), resp);
        Ok::<_, Error>(cipher)
    };

    let setup_js = async move {
        let pub_key_str = kp
            .public
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        let pub_key_str = format!("[{pub_key_str}]");

        let mut conf = Config::build()?;
        conf.imports.push(
            "
NoiseSecretStream = require('@hyperswarm/secret-stream');
net = require('net');
    "
            .to_string(),
        );
        conf.path_to_node_modules = Some(path_to_node_modules()?.display().to_string());
        let mut repl = conf.start().await?;
        repl.run(format!(
            "
socket = net.connect('{port}', '{hostname}');
noiseStream = new NoiseSecretStream(true, socket, {{
    pattern: 'IK',
    remotePublicKey: Buffer.from({pub_key_str}, )
}});
    "
        ))
        .await?;
        Ok::<Repl, Box<dyn std::error::Error>>(repl)
    };
    let (cipher, repl) = join!(setup_rs, setup_js);
    let cipher = cipher?;
    let repl: Repl = repl?;
    Ok((repl, cipher))
}
#[tokio::test]
async fn rust_responder_js_initiator_js_tx_first() -> Result<()> {
    let (mut repl, mut cipher) = setup_rust_responder_js_initiator().await?;

    let rs = async move {
        let x = cipher.next().await.unwrap();
        assert!(matches!(x, CipherEvent::HandshakePayload(_)));

        let CipherEvent::Message(msg) = cipher.next().await.unwrap() else {
            panic!();
        };
        assert_eq!(msg, b"aaaa");
        cipher.send(b"zzzz".to_vec()).await?;
        Ok::<_, Error>(cipher)
    };
    let js = async move {
        let _ = repl
            .run(
                "

js_rx_first_msg = Deferred();
datas = []
noiseStream.on('data', (data) => {{
    js_rx_first_msg.resolve([...data]);
    datas.push(data);
}})
// js sends first message
noiseStream.write(Buffer.from('aaaa'));
",
            )
            .await?;

        let js_rx_first_msg: Vec<u8> = repl.get_name("js_rx_first_msg").await?;
        assert_eq!(js_rx_first_msg, b"zzzz");
        Ok::<Repl, Box<dyn std::error::Error>>(repl)
    };
    let (cipher, repl) = join!(rs, js);
    cipher?;
    repl?;
    Ok(())
}

#[tokio::test]
async fn rust_responder_js_initiator_rs_tx_first() -> Result<()> {
    let (mut repl, mut cipher) = setup_rust_responder_js_initiator().await?;

    let rs = async move {
        // TODO FIXME why do I have to listen for the HandshakePayload before sending?
        let x = cipher.next().await.unwrap();
        assert!(matches!(x, CipherEvent::HandshakePayload(_)));
        cipher.send(b"zzzz".to_vec()).await?;
        let CipherEvent::Message(msg) = cipher.next().await.unwrap() else {
            panic!();
        };
        assert_eq!(msg, b"aaa");
        Ok::<_, Error>(cipher)
    };
    let js = async move {
        let _ = repl
            .run(
                "

js_rx_first_msg = Deferred();
datas = []
noiseStream.on('data', (data) => {{
    js_rx_first_msg.resolve([...data]);
    datas.push(data);
}})
// js wait to send msg
",
            )
            .await?;

        let js_rx_first_msg: Vec<u8> = repl.get_name("js_rx_first_msg").await?;
        assert_eq!(js_rx_first_msg, b"zzzz");
        repl.run(
            "
noiseStream.write(Buffer.from('aaa'));
        ",
        )
        .await?;
        Ok::<Repl, Box<dyn std::error::Error>>(repl)
    };
    let (cipher, repl) = join!(rs, js);
    cipher?;
    repl?;
    Ok(())
}
