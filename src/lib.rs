//! State machine for creating a Noise IK pattern (using a typestate pattern)
//! ```
//!// Excessive typing to demonstrate flow through typestates
//!use hypercore_handshake::{
//!    EncryptorReady, HsDone, HsMsgSent, Initiator, Ready, Responder, SecStream, Start,
//!    hc_specific::generate_keypair,
//!};
//!let kp: snow::Keypair = generate_keypair()?;
//!// Create an initiator and responder
//!let init: SecStream<Initiator<Start>> =
//!    SecStream::new_initiator(&kp.public.try_into().unwrap(), &[])?;
//!let resp: SecStream<Responder<Start>> = SecStream::new_responder(&kp.private)?;
//!
//!// initiator sends the first handshake message, a payload can be included to send extra data to the
//!// responder.
//!let (init, msg): (SecStream<Initiator<HsMsgSent>>, Vec<u8>) = init.write_msg(Some(b"one"))?;
//!
//!// responder receives the hs message, extracts the payload
//!let (resp, payload): (SecStream<Responder<HsDone>>, Vec<u8>) = resp.read_msg(&msg)?;
//!assert_eq!(payload, b"one");
//!
//!// responder sends a handshake message, which can include a payload. As well as a second
//!// message which contains the symmetric key needed to set up the decryptor
//!let (resp, [msg1, msg2]): (SecStream<EncryptorReady>, [Vec<u8>; 2]) =
//!    resp.write_msg(Some(b"two"))?;
//!
//!// Initiator receives last handshake message, use handshake to create the extract payload.
//!let (init, payload_recv): (SecStream<Initiator<HsDone>>, Vec<u8>) = init.read_msg(&msg1)?;
//!assert_eq!(payload_recv, b"two");
//!
//!// receive decryptor keey
//!let (init, to_resp_final): (SecStream<EncryptorReady>, Vec<u8>) = init.write_msg()?;
//!
//!// finalize both sides
//!let mut init: SecStream<Ready> = init.read_msg(&msg2)?;
//!let mut resp: SecStream<Ready> = resp.read_msg(&to_resp_final)?;
//!
//!// Now both sides can send and receive messages
//!let mut msg = b"three".to_vec();
//!init.push(&mut msg, &[], crypto_secretstream::Tag::Message)?;
//!let tag = resp.pull(&mut msg, &[])?;
//!assert_eq!(msg, b"three");
//!Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![warn(
    unreachable_pub,
    missing_debug_implementations,
    missing_docs,
    redundant_lifetimes,
    unsafe_code,
    non_local_definitions,
    clippy::needless_pass_by_value,
    clippy::needless_pass_by_ref_mut
)]

mod cipher;
mod crypto;
mod error;

use crypto_secretstream::{Header, Key, PullStream, PushStream, Tag};
use rand::rngs::OsRng;
use snow::HandshakeState;
use std::{fmt::Debug, marker::PhantomData};

use crate::crypto::write_stream_id;

pub use cipher::{Cipher, CipherIo, Event as CipherEvent};
pub use error::Error;
pub use hc_specific::generate_keypair;

/// NB: This is what the params SHOULD be, but hypercore uses "..Ed25519.."
//pub const PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
const STREAM_ID_LENGTH: usize = 32;
const RAW_HEADER_MSG_LEN: usize = STREAM_ID_LENGTH + Header::BYTES;
const SNOW_CIPHERKEYLEN: usize = 32;
const PUBLIC_KEYLEN: usize = 32;

/// Secret Stream protocol state
pub struct SecStream<Step> {
    is_initiator: bool,
    state: HandshakeState,
    msg_buf: [u8; 1024],
    step: Step,
}

impl<Step: Debug> std::fmt::Debug for SecStream<Step> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecStream")
            .field("is_initiator", &self.is_initiator)
            .field("state", &self.state)
            .field("msg_buf", &"[...]")
            .field("step", &self.step)
            .finish()
    }
}

impl<Step> SecStream<Step> {
    /// split handshake into (tx, rx)
    pub fn split_handshake(&mut self) -> ([u8; SNOW_CIPHERKEYLEN], [u8; SNOW_CIPHERKEYLEN]) {
        let (a, b) = self.state.dangerously_get_raw_split();
        if self.is_initiator { (a, b) } else { (b, a) }
    }
}

/// Initiator
#[derive(Debug)]
pub struct Initiator<Step> {
    _res_step: PhantomData<Step>,
}

/// Initial responder state
/// This first is before it receives the first message.
/// The second is after it reads it and gets the payload, but before creating the encyptor and
/// emitting the next message. This distinction is necessary so we can handle the received payload
/// and send a new one
#[derive(Debug)]
pub struct Responder<Step> {
    _res_step: PhantomData<Step>,
}
/// The first step. We must send or receive a handshake message to proceed.
#[derive(Debug)]
pub struct Start;
/// The handshake message has been sent. We must receive a handshake message to proceed to
/// [`HsDone`]. Only on [`Initiator`].
#[derive(Debug)]
pub struct HsMsgSent;
/// [`snow::HandshakeState::is_handshake_finished`] is `true`.
/// We are ready create a [`PushStream`] and proeed to [`EncryptorReady`].
#[derive(Debug)]
pub struct HsDone;

/// No decryptor yet
pub struct EncryptorReady {
    rx: Key,
    pusher: PushStream,
    handshake_hash: Vec<u8>,
}

/// Encryptor and decryptor
pub struct Ready {
    puller: PullStream,
    pusher: PushStream,
}
impl Debug for EncryptorReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorEnc")
            .field("rx", &"Key(..)")
            .field("pusher", &"PushStream(..)")
            .field("handshake_hash", &self.handshake_hash)
            .finish()
    }
}
impl Debug for Ready {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ready")
            .field("pusher", &"PushStream(..)")
            .field("puller", &"PullStream(..)")
            .finish()
    }
}
pub mod hc_specific {
    //! Stuff for generating Hypercore specific things like Noise parameters, keys, etc
    use std::sync::LazyLock;

    use snow::{
        Builder, Keypair,
        params::{BaseChoice, HandshakeChoice, HandshakePattern, NoiseParams},
        resolvers::{DefaultResolver, FallbackResolver},
    };

    use crate::Error;

    /// The Hypercore specific parameter string
    const PARAM_STR: &str = "Noise_IK_Ed25519_ChaChaPoly_BLAKE2b";
    static NOISE_PARAMS: LazyLock<NoiseParams> = LazyLock::new(|| {
        NoiseParams::new(
            PARAM_STR.to_string(),
            BaseChoice::Noise,
            HandshakeChoice {
                pattern: HandshakePattern::IK,
                modifiers: snow::params::HandshakeModifierList { list: vec![] },
            },
            snow::params::DHChoice::Curve25519,
            snow::params::CipherChoice::ChaChaPoly,
            snow::params::HashChoice::Blake2b,
        )
    });

    /// Get Hypercore Noise parameters.
    fn noise_params() -> &'static NoiseParams {
        &NOISE_PARAMS
    }
    pub(super) fn builder() -> Builder<'static> {
        let params = noise_params();
        Builder::with_resolver(
            params.clone(),
            //Box::new(DefaultResolver::default()),
            Box::new(FallbackResolver::new(
                Box::<crate::crypto::CurveResolver>::default(),
                Box::<DefaultResolver>::default(),
            )),
        )
    }

    /// Generate Hypercore key pair.
    pub fn generate_keypair() -> Result<Keypair, Error> {
        Ok(builder().generate_keypair()?)
    }
}

impl SecStream<Initiator<Start>> {
    /// Create an initiator of a secret stream
    pub fn new_initiator(
        remote_public_key: &[u8; PUBLIC_KEYLEN],
        prologue: &[u8],
    ) -> Result<Self, Error> {
        let key_pair = hc_specific::generate_keypair()?;

        let state = hc_specific::builder()
            .prologue(prologue)?
            .local_private_key(&key_pair.private)?
            .remote_public_key(remote_public_key.as_slice())?
            .build_initiator()?;

        Ok(Self {
            is_initiator: true,
            state,
            msg_buf: [0; 1024],
            step: Initiator {
                _res_step: PhantomData,
            },
        })
    }
    /// Create the first message the initiator sends to the responder
    pub fn write_msg(
        mut self,
        payload: Option<&[u8]>,
    ) -> Result<(SecStream<Initiator<HsMsgSent>>, Vec<u8>), Error> {
        let payload = payload.unwrap_or_default();
        let len = self.state.write_message(payload, &mut self.msg_buf)?;
        let msg = self.msg_buf[..len].to_vec();
        let Self {
            is_initiator,
            state,
            msg_buf,
            ..
        } = self;
        Ok((
            SecStream {
                is_initiator,
                state,
                msg_buf,
                step: Initiator {
                    _res_step: PhantomData,
                },
            },
            msg,
        ))
    }
}

impl SecStream<Responder<Start>> {
    /// Create a responder of a secret stream
    pub fn new_responder(private: &[u8]) -> Result<Self, Error> {
        let state = hc_specific::builder()
            .local_private_key(private)?
            .build_responder()?;
        Ok(Self {
            is_initiator: false,
            state,
            msg_buf: [0; 1024],
            step: Responder {
                _res_step: PhantomData,
            },
        })
    }

    /// Read msg and return it's payload
    pub fn read_msg(
        mut self,
        msg: &[u8],
    ) -> Result<(SecStream<Responder<HsDone>>, Vec<u8>), Error> {
        let len = self.state.read_message(msg, &mut self.msg_buf)?;
        let payload = &self.msg_buf[..len];
        let Self {
            is_initiator,
            state,
            msg_buf,
            ..
        } = self;
        Ok((
            SecStream {
                is_initiator,
                state,
                msg_buf,
                step: Responder {
                    _res_step: PhantomData,
                },
            },
            payload.to_vec(),
        ))
    }
    /// Read the first message of the protocol, create the next two messages to send to the initiator.
    pub fn read_and_write_msg(
        self,
        msg: &[u8],
    ) -> Result<(SecStream<EncryptorReady>, [Vec<u8>; 2]), Error> {
        let (self2, _rx_payload) = self.read_msg(msg)?;
        self2.write_msg(Some(&[]))
    }
}

impl SecStream<Responder<HsDone>> {
    /// Make second message with the given payload. Returns two messages, the first completes the
    /// Noise handshake. The second has the shared key for the remote to set up a Decryptor.
    pub fn write_msg(
        mut self,
        payload: Option<&[u8]>,
    ) -> Result<(SecStream<EncryptorReady>, [Vec<u8>; 2]), Error> {
        let payload = payload.unwrap_or_default();
        let len = self.state.write_message(payload, &mut self.msg_buf)?;
        let hs_msg = self.msg_buf[..len].to_vec();
        assert!(self.state.is_handshake_finished());

        let handshake_hash = self.state.get_handshake_hash().to_vec();
        let mut pull_stream_msg: [u8; RAW_HEADER_MSG_LEN] = [0; RAW_HEADER_MSG_LEN];
        // write stream id to front of pull_stream_msg
        write_stream_id(
            &handshake_hash,
            self.is_initiator,
            &mut pull_stream_msg[..STREAM_ID_LENGTH],
        );

        let (tx, rx) = self.split_handshake();
        let (header, pusher) = PushStream::init(OsRng, &Key::from(tx));

        // write push header to back of pull_stream_msg
        pull_stream_msg[STREAM_ID_LENGTH..].copy_from_slice(header.as_ref());

        let Self {
            is_initiator,
            state,
            msg_buf,
            ..
        } = self;
        Ok((
            SecStream {
                is_initiator,
                state,
                msg_buf,
                step: EncryptorReady {
                    rx: Key::from(rx),
                    pusher,
                    handshake_hash,
                },
            },
            [hs_msg, pull_stream_msg.to_vec()],
        ))
    }
}

impl SecStream<Initiator<HsMsgSent>> {
    /// Recieve the last message to complet the handsake
    pub fn read_msg(
        mut self,
        msg: &[u8],
    ) -> Result<(SecStream<Initiator<HsDone>>, Vec<u8>), Error> {
        let len = self.state.read_message(msg, &mut self.msg_buf)?;
        let payload = &self.msg_buf[..len];
        let Self {
            is_initiator,
            state,
            msg_buf,
            ..
        } = self;
        Ok((
            SecStream {
                is_initiator,
                state,
                msg_buf,
                step: Initiator {
                    _res_step: PhantomData,
                },
            },
            payload.to_vec(),
        ))
    }

    /// read in a message, and write the next message. Any payload in the recieved message is
    /// dropped.
    pub fn read_and_write_msg(
        self,
        msg: &[u8],
    ) -> Result<(SecStream<EncryptorReady>, Vec<u8>), Error> {
        let (self2, _payload) = self.read_msg(msg)?;
        self2.write_msg()
    }
}

impl SecStream<Initiator<HsDone>> {
    /// Write the final setup message  
    pub fn write_msg(mut self) -> Result<(SecStream<EncryptorReady>, Vec<u8>), Error> {
        let (tx, rx) = self.split_handshake();
        let key: [u8; SNOW_CIPHERKEYLEN] = tx[..SNOW_CIPHERKEYLEN]
            .try_into()
            .expect("split_tx with incorrect length");
        let key = Key::from(key);
        let handshake_hash = self.state.get_handshake_hash().to_vec();
        let (header, pusher) = PushStream::init(OsRng, &key);

        let mut msg: [u8; RAW_HEADER_MSG_LEN] = [0; RAW_HEADER_MSG_LEN];
        // write stream id to front of msg
        write_stream_id(
            &handshake_hash,
            self.is_initiator,
            &mut msg[..STREAM_ID_LENGTH],
        );
        // write push header to back of msg
        msg[STREAM_ID_LENGTH..].copy_from_slice(header.as_ref());

        let SecStream {
            is_initiator,
            state,
            msg_buf,
            ..
        } = self;
        Ok((
            SecStream {
                is_initiator,
                state,
                msg_buf,
                step: EncryptorReady {
                    pusher,
                    rx: Key::from(rx),
                    handshake_hash,
                },
            },
            msg.to_vec(),
        ))
    }
}

impl SecStream<EncryptorReady> {
    /// Recieve message the last message, used to set up the decryption stream
    pub fn read_msg(self, msg: &[u8]) -> Result<SecStream<Ready>, Error> {
        let Self {
            is_initiator,
            step:
                EncryptorReady {
                    pusher,
                    rx,
                    handshake_hash,
                },
            state,
            msg_buf,
        } = self;
        // Read the received message from the other peer
        let mut expected_stream_id: [u8; STREAM_ID_LENGTH] = [0; STREAM_ID_LENGTH];
        write_stream_id(&handshake_hash, !is_initiator, &mut expected_stream_id);
        if expected_stream_id != msg[..STREAM_ID_LENGTH] {
            panic!(
                "stream ID's don't match\n{expected_stream_id:?}\n != \n{:?}",
                &msg[..STREAM_ID_LENGTH]
            );
        }

        let header: [u8; Header::BYTES] =
            msg[STREAM_ID_LENGTH..].try_into().expect("TODO wrong size");
        let puller = PullStream::init(header.into(), &rx);
        Ok(SecStream {
            is_initiator,
            state,
            msg_buf,
            step: Ready { pusher, puller },
        })
    }

    /// Encrypt a message in place
    pub fn push(
        &mut self,
        msg: &mut Vec<u8>,
        associated_data: &[u8],
        tag: Tag,
    ) -> Result<(), Error> {
        Ok(self.step.pusher.push(msg, associated_data, tag)?)
    }
}

impl SecStream<Ready> {
    /// Encrypt a message in place
    pub fn push(
        &mut self,
        msg: &mut Vec<u8>,
        associated_data: &[u8],
        tag: Tag,
    ) -> Result<(), Error> {
        Ok(self.step.pusher.push(msg, associated_data, tag)?)
    }
    /// Decrypt a message in place
    pub fn pull(&mut self, msg: &mut Vec<u8>, associated_data: &[u8]) -> Result<Tag, Error> {
        Ok(self.step.puller.pull(msg, associated_data)?)
    }
}
