//! Interface for an encrypted channel
use std::{
    collections::VecDeque,
    fmt::Debug,
    io::Error as IoError,
    mem::replace,
    pin::Pin,
    task::{Context, Poll},
};

use crypto_secretstream::Tag;
use futures::{Sink, Stream};
use tracing::{instrument, trace, warn};

use crate::{
    Error,
    state_machine::{
        EncryptorReady, HsMsgSent, Initiator, PUBLIC_KEYLEN, Ready, Responder, SecStream, Start,
    },
};

pub(crate) enum State {
    InitiatorStart(SecStream<Initiator<Start>>),
    InitiatorSent(SecStream<Initiator<HsMsgSent>>),
    RespStart(SecStream<Responder<Start>>),
    EncReady(SecStream<EncryptorReady>),
    Ready(SecStream<Ready>),
    Invalid,
}

impl Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::InitiatorStart(_) => "InitiatorStart",
                Self::InitiatorSent(_) => "InitiatorSent",
                Self::RespStart(_) => "RespStart",
                Self::EncReady(_) => "EncReady",
                Self::Ready(_) => "Ready",
                Self::Invalid => "Invalid",
            }
        )
    }
}

/// Like [`Machine`] but no IO
struct SansIoMachine {
    state: State,
    encrypted_tx: VecDeque<Vec<u8>>,
    encrypted_rx: VecDeque<Result<Vec<u8>, std::io::Error>>,
    plain_tx: VecDeque<Vec<u8>>,
    plain_rx: VecDeque<Event>,
}

impl SansIoMachine {
    fn new(state: State) -> Self {
        Self {
            state,
            encrypted_tx: Default::default(),
            encrypted_rx: Default::default(),
            plain_tx: Default::default(),
            plain_rx: Default::default(),
        }
    }
    fn new_init(state: SecStream<Initiator<Start>>) -> Self {
        Self {
            state: State::InitiatorStart(state),
            encrypted_tx: Default::default(),
            encrypted_rx: Default::default(),
            plain_tx: Default::default(),
            plain_rx: Default::default(),
        }
    }

    fn new_resp(state: SecStream<Responder<Start>>) -> Self {
        Self {
            state: State::RespStart(state),
            encrypted_tx: Default::default(),
            encrypted_rx: Default::default(),
            plain_tx: Default::default(),
            plain_rx: Default::default(),
        }
    }

    #[instrument(skip_all, err)]
    fn handshake_start(&mut self, payload: &[u8]) -> Result<(), std::io::Error> {
        match replace(&mut self.state, State::Invalid) {
            State::InitiatorStart(s) => {
                let (s2, out) = s.write_msg(Some(payload))?;
                self.encrypted_tx.push_back(out);
                self.state = State::InitiatorSent(s2);
                Ok(())
            }
            _e => todo!("{_e:?}"),
        }
    }

    #[instrument(skip_all, err)]
    /// Encrypt outgoing messages, and decrypt encomming messages.
    /// This also processes messages to complete the handshake.
    fn poll_encrypt_decrypt(&mut self) -> Result<Option<()>, std::io::Error> {
        trace!(
            state =? self.state,
            plain_tx = self.plain_tx.len(),
            plain_rx = self.plain_rx.len(),
            enc_tx = self.encrypted_tx.len(),
            enc_rx = self.encrypted_rx.len(),
            "poll_encrypt_decrypt"
        );

        match replace(&mut self.state, State::Invalid) {
            State::InitiatorSent(s) => {
                let Some(msg) = self.encrypted_rx.pop_front() else {
                    self.state = State::InitiatorSent(s);
                    return Ok(None);
                };
                let (s2, payload) = s.read_msg(&msg?)?;
                // Ensure payload jumps to the front of the line
                self.plain_rx.push_front(Event::HandshakePayload(payload));
                let (s3, out) = s2.write_msg()?;
                self.encrypted_tx.push_front(out);
                self.state = State::EncReady(s3);
                Ok(Some(()))
            }
            State::RespStart(s) => {
                let Some(msg) = self.encrypted_rx.pop_front() else {
                    // Not ready
                    self.state = State::RespStart(s);
                    return Ok(None);
                };
                let (s2, payload) = s.read_msg(&msg?)?;
                // Ensure payload jumps to the front of the line
                self.plain_rx.push_front(Event::HandshakePayload(payload));
                let next_tx = self.plain_tx.pop_front();
                let (s3, [msg1, msg2]) = s2.write_msg(next_tx.as_deref())?;
                self.encrypted_tx.push_front(msg2);
                self.encrypted_tx.push_front(msg1);
                self.state = State::EncReady(s3);
                Ok(Some(()))
            }
            State::EncReady(mut s) => {
                let mut made_progress = false;
                while let Some(mut msg) = self.plain_tx.pop_front() {
                    s.push(&mut msg, &[], Tag::Message)?;
                    self.encrypted_tx.push_back(msg);
                    made_progress = true;
                }
                let Some(msg) = self.encrypted_rx.pop_front() else {
                    self.state = State::EncReady(s);
                    return Ok(made_progress.then_some(()));
                };
                self.state = State::Ready(s.read_msg(&msg?)?);
                Ok(Some(()))
            }
            State::Ready(mut s) => {
                let mut made_progress = false;

                if let Some(encrypted_result) = self.encrypted_rx.pop_front() {
                    match encrypted_result {
                        Ok(mut encrypted_msg) => {
                            let _tag = s.pull(&mut encrypted_msg, &[])?;

                            self.plain_rx.push_back(Event::Message(encrypted_msg));
                            made_progress = true;
                        }
                        Err(_e) => todo!("How should we handle an error in receiving a message?"),
                    }
                }

                // encrypt outgoing messages
                if let Some(mut plain_msg) = self.plain_tx.pop_front() {
                    s.push(&mut plain_msg, &[], Tag::Message)?;
                    self.encrypted_tx.push_back(plain_msg);
                    made_progress = true;
                }

                self.state = State::Ready(s);
                Ok(if made_progress { Some(()) } else { None })
            }
            State::InitiatorStart(s) => {
                // no handshake message.. We use first thing in plain_tx, but maybe it should be an
                // error bc we might want the payload to be handled explicitly
                let payload = self.plain_tx.pop_front();
                let (s2, out) = s.write_msg(payload.as_deref())?;
                self.encrypted_tx.push_back(out);
                self.state = State::InitiatorSent(s2);
                Ok(Some(()))
            }
            State::Invalid => Err(IoError::other("Invalid state")),
        }
    }

    /// Do as much work as possible encrypting plaintext and decrypting ciphertext
    fn poll_all_enc_dec(&mut self) -> Result<Option<()>, IoError> {
        let mut made_progress = false;
        while self.poll_encrypt_decrypt()?.is_some() {
            made_progress = true;
        }
        Ok(made_progress.then_some(()))
    }

    // NB: vectorized version of 'get_next_sendable_message'. currently just used in tests
    #[cfg(test)]
    fn get_sendable_messages(&mut self) -> Result<Vec<Vec<u8>>, IoError> {
        self.poll_all_enc_dec()?;
        Ok(self.encrypted_tx.drain(..).collect())
    }

    fn get_next_sendable_message(&mut self) -> Result<Option<Vec<u8>>, IoError> {
        self.poll_all_enc_dec()?;
        Ok(self.encrypted_tx.pop_front())
    }

    #[cfg(test)]
    // NB: vectorized version of 'receive_next'. currently just used in tests
    fn receive_next_messages(&mut self, encrypted_messages: Vec<Vec<u8>>) {
        self.encrypted_rx
            .extend(encrypted_messages.into_iter().map(Ok));
    }

    fn receive_next(&mut self, encrypted_msg: Vec<u8>) {
        self.encrypted_rx.push_back(Ok(encrypted_msg));
    }

    fn queue_msg(&mut self, msg: Vec<u8>) {
        self.plain_tx.push_back(msg);
    }

    fn next_decrypted_message(&mut self) -> Result<Option<Event>, IoError> {
        self.poll_all_enc_dec()?;
        Ok(self.plain_rx.pop_front())
    }

    fn ready(&self) -> bool {
        matches!(self.state, State::Ready(_))
    }
}

impl Debug for SansIoMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SansIoMachine")
            .field("state", &self.state)
            .field("encrypted_tx", &self.encrypted_tx.len())
            .field("encrypted_rx", &self.encrypted_rx.len())
            .field("plain_tx", &self.plain_tx.len())
            .field("plain_rx", &self.plain_rx.len())
            .finish()
    }
}

#[derive(Debug)]
/// Encryption event
pub enum Event {
    /// Data passed through the handshake payload
    HandshakePayload(Vec<u8>),
    /// Decrypted message
    Message(Vec<u8>),
    /// Error occured in encryption
    ErrStuff(IoError),
}

/// Supertrait for duplex channel required by [`Machine`]
pub trait CipherIo:
    Stream<Item = Result<Vec<u8>, IoError>> + Sink<Vec<u8>> + Send + Sync + Unpin + 'static
{
}

impl<T> CipherIo for T
where
    T: Stream<Item = Result<Vec<u8>, IoError>> + Sink<Vec<u8>> + Send + Sync + Unpin + 'static,
    <T as Sink<Vec<u8>>>::Error: Into<crate::Error> + std::fmt::Debug,
{
}
/// For each tx/rx VecDeque messages go in with `.push_back` then taken out with `.pop_front`.
/// If a message should skip the line it should be inserted with `.push_front`.
pub struct Cipher {
    io: Option<Box<dyn CipherIo<Error = std::io::Error>>>,
    inner: SansIoMachine,
}

impl Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Machine")
            .field("io", &"")
            .field("inner", &self.inner)
            .finish()
    }
}

impl Cipher {
    /// Create a new [`Machine`]
    fn new(io: Option<Box<dyn CipherIo<Error = std::io::Error>>>, inner: SansIoMachine) -> Self {
        Self { io, inner }
    }

    /// Create a new initiator
    pub fn new_dht_init(
        io: Option<Box<dyn CipherIo<Error = std::io::Error>>>,
        remote_pub_key: &[u8; PUBLIC_KEYLEN],
        prologue: &[u8],
    ) -> Result<Self, Error> {
        let ss = SecStream::new_initiator(remote_pub_key, prologue)?;
        let state = State::InitiatorStart(ss);
        let inner = SansIoMachine::new(state);
        Ok(Self::new(io, inner))
    }

    /// Create a new initiator
    pub fn new_init(
        io: Box<dyn CipherIo<Error = std::io::Error>>,
        state: SecStream<Initiator<Start>>,
    ) -> Self {
        Self::new(Some(io), SansIoMachine::new_init(state))
    }

    /// Create a new responder from a private key
    pub fn resp_from_private(
        io: Option<Box<dyn CipherIo<Error = std::io::Error>>>,
        private: &[u8],
    ) -> Result<Self, Error> {
        Self::resp_from_private_with_prologue(io, private, &[])
    }

    /// Create a new responder from a private key with a prologue
    pub fn resp_from_private_with_prologue(
        io: Option<Box<dyn CipherIo<Error = std::io::Error>>>,
        private: &[u8],
        prologue: &[u8],
    ) -> Result<Self, Error> {
        let ss = SecStream::new_responder_with_prologue(private, prologue)?;
        let state = State::RespStart(ss);
        let inner = SansIoMachine::new(state);
        Ok(Self::new(io, inner))
    }

    /// Create a new responder
    pub fn new_resp(
        io: Box<dyn CipherIo<Error = std::io::Error>>,
        state: SecStream<Responder<Start>>,
    ) -> Self {
        Self::new(Some(io), SansIoMachine::new_resp(state))
    }

    /// Wait for handshake to complete
    pub async fn complete_handshake(&mut self) -> Result<(), IoError> {
        use futures::{SinkExt, StreamExt};

        loop {
            if !self.inner.ready() {
                self.send(vec![]).await?;
                if self.inner.ready() {
                    return Ok(());
                }
                let _ = self.next().await;
            } else {
                return Ok(());
            }
        }
    }

    #[instrument(skip_all, err)]
    /// Start the handshake
    pub fn handshake_start(&mut self, payload: &[u8]) -> Result<(), IoError> {
        self.inner.handshake_start(payload)
    }

    /// Try to get the next encrypted message to send.
    pub fn get_next_sendable_message(&mut self) -> Result<Option<Vec<u8>>, IoError> {
        self.inner.get_next_sendable_message()
    }

    /// Manually add a received encrypted message to be decrypted.
    pub fn receive_next(&mut self, encrypted_msg: Vec<u8>) {
        self.inner.receive_next(encrypted_msg)
    }

    /// Try to get the next decrypted message.
    pub fn next_decrypted_message(&mut self) -> Result<Option<Event>, IoError> {
        self.inner.next_decrypted_message()
    }

    /// Queue a plaintext message into encrypted and sent
    pub fn queue_msg(&mut self, payload: Vec<u8>) {
        self.inner.queue_msg(payload);
    }

    fn get_io(&mut self) -> Result<&mut Box<dyn CipherIo<Error = std::io::Error>>, IoError> {
        if let Some(io) = self.io.as_mut() {
            return Ok(io);
        }
        Err(IoError::other(Error::NoIoSetError))
    }
    /// Set the IO connection for sending and receiving encrypted messages.
    pub fn set_io(&mut self, io: Box<dyn CipherIo<Error = std::io::Error>>) {
        self.io = Some(io);
    }

    #[instrument(skip_all, err)]
    /// Encrypt outgoing messages, and decrypt encomming messages.
    /// This also processes messages to complete the handshake.
    fn poll_encrypt_decrypt(&mut self) -> Result<Option<()>, IoError> {
        trace!(
            state =? self.inner.state,
            plain_tx = self.inner.plain_tx.len(),
            plain_rx = self.inner.plain_rx.len(),
            enc_tx = self.inner.encrypted_tx.len(),
            enc_rx = self.inner.encrypted_rx.len(),
            "poll_encrypt_decrypt before"
        );
        self.inner.poll_encrypt_decrypt()
    }

    /// pull in new incomming encrypted messages.
    #[instrument(skip_all)]
    fn poll_incoming_encrypted(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        while let Poll::Ready(Some(result)) =
            Pin::new(&mut self.get_io().expect("Missing IO")).poll_next(cx)
        {
            match result {
                Ok(_) => {
                    self.inner.encrypted_rx.push_back(result);
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => {
                        // this happens when nothing can be read from udx? I think?
                        return Poll::Pending;
                    }
                    std::io::ErrorKind::ConnectionReset => {
                        // idk???
                        return Poll::Pending;
                    }
                    e => {
                        todo!("some other error?? add these as we find them")
                    }
                },
            }
        }
        Poll::Ready(())
    }

    #[instrument(skip_all)]
    fn poll_outgoing_encrypted(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        while let Some(msg) = self.inner.encrypted_tx.pop_front() {
            match Pin::new(&mut self.get_io().unwrap()).poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    if let Err(_e) =
                        Pin::new(&mut self.get_io().expect("Missing IO")).start_send(msg)
                    {
                        return Poll::Ready(Err(IoError::other(
                            "Send failed: TODO Error should have fmt::Debug here",
                        )));
                    }
                }
                Poll::Ready(Err(_e)) => {
                    return Poll::Ready(Err(IoError::other(
                        "IO error: TODO Error should have fmt::Debug here",
                    )));
                }
                Poll::Pending => {
                    self.inner.encrypted_tx.push_front(msg);
                    return Poll::Pending;
                }
            }
        }

        match Pin::new(&mut self.get_io().expect("Missing IO")).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_e)) => Poll::Ready(Err(IoError::other(
                "Flush failed: TODO Error should have fmt::Debug here",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    /// `true` when handshake is completed.
    pub fn ready(&self) -> bool {
        self.inner.ready()
    }
}

impl Stream for Cipher {
    type Item = Event;

    #[instrument(skip_all)]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // 1. First, try to return any ready plaintext messages
            if let Some(event) = self.inner.plain_rx.pop_front() {
                return Poll::Ready(Some(event));
            }

            // 2. Pull new encrypted data from IO into our queue
            let _ = self.poll_incoming_encrypted(cx);

            // 3. Send any pending encrypted data to IO
            match self.poll_outgoing_encrypted(cx) {
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Some(Event::ErrStuff(e)));
                }
                Poll::Pending => {
                    // IO is busy, we can't make progress on sending
                    // but we can still try to process incoming messages
                }
                Poll::Ready(Ok(())) => {
                    // Successfully sent outgoing data
                }
            }

            // 4. Process crypto operations (handshake, encrypt/decrypt)
            match self.poll_encrypt_decrypt() {
                Ok(Some(())) => {
                    // Made progress, loop again to check for more work
                    continue;
                }
                Ok(None) => {
                    // No progress made, no more work available
                    break;
                }
                Err(e) => {
                    return Poll::Ready(Some(Event::ErrStuff(e)));
                }
            }
        }

        // No messages ready and no progress can be made
        Poll::Pending
    }
}

impl Sink<Vec<u8>> for Cipher {
    type Error = IoError;

    #[instrument(skip_all)]
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Process any pending work to make space in queues
        let _ = self.poll_incoming_encrypted(cx);

        match self.poll_outgoing_encrypted(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                // IO is busy, but we can still accept messages for queuing
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Ok(())) => {
                // IO is ready
            }
        }

        // Process crypto operations to make progress
        match self.poll_encrypt_decrypt() {
            Ok(_) => {
                // Always ready to accept more plaintext messages for queuing
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    #[instrument(skip_all)]
    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        // Queue the plaintext message for encryption
        self.inner.plain_tx.push_back(item);
        Ok(())
    }

    #[instrument(skip_all)]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let _always_poll_ready_but_why = self.poll_incoming_encrypted(cx);
        loop {
            // Process crypto operations to encrypt any pending plaintext
            match self.poll_encrypt_decrypt() {
                Ok(Some(())) => {
                    // Made progress, continue processing
                    continue;
                }
                Ok(None) => {
                    // No more crypto work to do
                    break;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        // Send any pending encrypted data to IO
        match self.poll_outgoing_encrypted(cx) {
            Poll::Ready(Ok(())) => {
                // Check if we have any pending plaintext that hasn't been encrypted yet
                if self.inner.plain_tx.is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    // Still have pending plaintext, not fully flushed
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    #[instrument(skip_all)]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // First flush any pending data
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                // Now close the underlying IO
                Pin::new(&mut self.get_io().expect("Missing IO"))
                    .poll_close(cx)
                    .map_err(|_e| {
                        IoError::other("Close failed TODO Error should have fmt::debug here")
                    })
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::state_machine::hc_specific;

    use super::*;
    use futures::{SinkExt, StreamExt, channel::mpsc, join};

    // Mock IO that implements Stream + Sink for testing
    #[derive(Debug)]
    struct MockIo<S>
    where
        S: Stream<Item = Result<Vec<u8>, std::io::Error>>,
    {
        receiver: S,
        sender: mpsc::UnboundedSender<Vec<u8>>,
    }

    impl<S: Stream<Item = Result<Vec<u8>, IoError>> + Unpin> Stream for MockIo<S> {
        type Item = Result<Vec<u8>, IoError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Pin::new(&mut self.receiver).poll_next(cx)
        }
    }

    impl<S: Stream<Item = Result<Vec<u8>, std::io::Error>>> Sink<Vec<u8>> for MockIo<S> {
        type Error = std::io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
            self.sender
                .unbounded_send(item)
                .map_err(|_| IoError::other("Send failed"))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[expect(clippy::type_complexity)]
    fn create_mock_io_pair() -> (
        MockIo<impl Stream<Item = Result<Vec<u8>, std::io::Error>>>,
        mpsc::UnboundedSender<Result<Vec<u8>, std::io::Error>>,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let (io_tx, io_rx) = mpsc::unbounded();
        let (out_tx, out_rx) = mpsc::unbounded();

        let mock_io = MockIo {
            receiver: io_rx,
            sender: out_tx,
        };

        (mock_io, io_tx, out_rx)
    }

    fn new_connected_secret_stream() -> (SecStream<Initiator<Start>>, SecStream<Responder<Start>>) {
        let kp = hc_specific::generate_keypair().unwrap();
        (
            SecStream::new_initiator(&kp.public.try_into().unwrap(), &[]).unwrap(),
            SecStream::new_responder(&kp.private).unwrap(),
        )
    }

    fn new_connected_streams() -> (
        impl CipherIo<Error = std::io::Error>,
        impl CipherIo<Error = std::io::Error>,
    ) {
        let (left_tx, left_rx) = mpsc::unbounded();
        let res_left_rx = left_rx.map(|msg: Vec<u8>| Ok::<_, std::io::Error>(msg));

        let (right_tx, right_rx) = mpsc::unbounded();
        let res_right_rx = right_rx.map(|msg: Vec<u8>| Ok::<_, std::io::Error>(msg));

        let left = MockIo {
            sender: left_tx,
            receiver: res_right_rx,
        };
        let right = MockIo {
            sender: right_tx,
            receiver: res_left_rx,
        };
        (left, right)
    }

    fn connected_machines() -> (Cipher, Cipher) {
        let (lss, rss) = new_connected_secret_stream();
        let (lio, rio) = new_connected_streams();
        let (lm, rm) = (
            Cipher::new_init(Box::new(lio), lss),
            Cipher::new_resp(Box::new(rio), rss),
        );
        (lm, rm)
    }

    #[test]
    fn sans_io() -> Result<(), Error> {
        let (lss, rss) = new_connected_secret_stream();
        let (mut l, mut r) = (SansIoMachine::new_init(lss), SansIoMachine::new_resp(rss));

        let lx = l.get_sendable_messages()?;
        r.receive_next_messages(lx);

        let rx = r.get_sendable_messages()?; // <-- here. r is responder
        l.receive_next_messages(rx);

        let lx = l.get_sendable_messages()?;
        r.receive_next_messages(lx);

        assert!(l.ready());
        let rx = r.get_sendable_messages()?;
        l.receive_next_messages(rx);
        assert!(r.ready());
        Ok(())
    }

    #[tokio::test]
    async fn test_complete_handshake() -> Result<(), Error> {
        let (mut lm, mut rm) = connected_machines();
        let (rl, rr) = join!(lm.complete_handshake(), rm.complete_handshake());
        rl?;
        rr?;
        assert!(lm.inner.ready());
        assert!(rm.inner.ready());
        Ok(())
    }

    #[tokio::test]
    async fn test_streams() -> Result<(), Error> {
        let (mut l, mut r) = new_connected_streams();
        let (a, b) = join!(l.send(b"yo".to_vec()), r.next());
        assert!(a.is_ok());
        assert_eq!(b.unwrap()?, b"yo".to_vec());

        let (a, b) = join!(r.send(b"yo".to_vec()), l.next());
        assert!(a.is_ok());
        assert_eq!(b.unwrap()?, b"yo".to_vec());
        Ok(())
    }
    #[tokio::test]
    async fn test_machine_io_l_to_r() -> Result<(), Error> {
        let (mut lm, mut rm) = connected_machines();

        let payload = b"Hello, World!".to_vec();
        lm.handshake_start(&payload)?;
        let (lres, rres) = join!(lm.flush(), rm.next());
        assert!(matches!(rres, Some(Event::HandshakePayload(_))));
        lres?;
        Ok(())
    }

    #[tokio::test]
    async fn test_machine_io_both_ways() -> Result<(), Error> {
        let (mut lm, mut rm) = connected_machines();

        let res = join!(lm.send(b"ltor".into()), rm.send(b"rtol".into()));
        assert_eq!((res.0?, res.1?), ((), ()));

        let (Some(lr), Some(rr)) = join!(lm.next(), rm.next()) else {
            panic!()
        };

        let (empty, rtol, ltor): (Vec<u8>, _, _) = (vec![], b"rtol".to_vec(), b"ltor".to_vec());
        assert!(matches!(lr, Event::HandshakePayload(x) if x == empty));
        assert!(matches!(rr, Event::HandshakePayload(x) if x == empty));

        let (Some(lr), Some(rr)) = join!(lm.next(), rm.next()) else {
            panic!()
        };
        assert!(matches!(lr, Event::Message(x) if x == rtol));
        assert!(matches!(rr, Event::Message(x) if x == ltor));

        Ok(())
    }
    #[tokio::test]
    async fn test_machine_sink_multiple_messages() -> Result<(), Error> {
        let (mut lm, mut rm) = connected_machines();

        let (rl, rr) = join!(lm.complete_handshake(), rm.complete_handshake());
        rl?;
        rr?;

        let mut msgs = vec![];
        for i in 0..5 {
            let msg = format!("Message {}", i).into_bytes();
            msgs.push(msg.clone());
            lm.send(msg).await?;
        }

        let mut results = vec![];
        for _ in 0..5 {
            let Event::Message(m) = rm.next().await.unwrap() else {
                panic!();
            };
            results.push(m);
        }
        assert_eq!(results, msgs);

        Ok(())
    }

    #[tokio::test]
    async fn test_machine_stream_returns_pending_when_no_data() -> Result<(), Error> {
        let remote_key = [3u8; 32];
        let initiator_state = SecStream::new_initiator(&remote_key, &[])?;

        let (mock_io, _io_tx, _out_rx) = create_mock_io_pair();
        let mut machine = Cipher::new_init(Box::new(mock_io), initiator_state);

        // Test that stream returns None when no data is available
        let mut stream = Box::pin(&mut machine);

        // Use a timeout to ensure we don't wait forever
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(100), stream.next()).await;

        // Should timeout because no data is available
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_machine_handshake_start() -> Result<(), Error> {
        let kp = hc_specific::generate_keypair().unwrap();
        let public = kp.public.try_into().unwrap();
        let initiator_state = SecStream::new_initiator(&public, &[])?;

        let (mock_io, _io_tx, mut out_rx) = create_mock_io_pair();
        let mut machine = Cipher::new_init(Box::new(mock_io), initiator_state);

        // Start handshake
        let payload = b"handshake payload";
        machine.handshake_start(payload)?;

        // Should have transitioned to InitiatorSent state
        assert!(matches!(machine.inner.state, State::InitiatorSent(_)));

        // Should have queued encrypted handshake message
        assert!(!machine.inner.encrypted_tx.is_empty());

        // Process outgoing to send the handshake message
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let _result = machine.poll_outgoing_encrypted(&mut cx);

        // Should have sent handshake message to IO
        let sent_msg = out_rx.try_next().unwrap();
        assert!(sent_msg.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_machine_ready_state_processing() -> Result<(), Error> {
        // This test would require more complex setup to reach Ready state
        // For now, test that we can create a machine in different states

        let remote_key = [5u8; 32];
        let initiator_state = SecStream::new_initiator(&remote_key, &[])?;

        let (mock_io, _io_tx, _out_rx) = create_mock_io_pair();
        let machine = Cipher::new_init(Box::new(mock_io), initiator_state);

        // Verify initial state
        assert!(matches!(machine.inner.state, State::InitiatorStart(_)));
        assert!(machine.inner.plain_tx.is_empty());
        assert!(machine.inner.plain_rx.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_machine_poll_ready_always_succeeds() -> Result<(), Error> {
        let remote_key = [6u8; 32];
        let initiator_state = SecStream::new_initiator(&remote_key, &[])?;

        let (mock_io, _io_tx, _out_rx) = create_mock_io_pair();
        let mut machine = Cipher::new_init(Box::new(mock_io), initiator_state);

        // poll_ready should always succeed since we queue internally
        let mut sink = Box::pin(&mut machine);
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let ready_result = sink.as_mut().poll_ready(&mut cx);

        assert!(matches!(ready_result, Poll::Ready(Ok(()))));

        Ok(())
    }
}
