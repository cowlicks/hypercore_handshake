//! State machine
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
pub mod state_machine;

pub use cipher::{Cipher, CipherIo, Event as CipherEvent};
pub use error::Error;
