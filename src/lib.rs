#![feature(cursor_remaining)]

/* Expose internal functions to fuzzer */
#[cfg(fuzzing)]
pub mod tls;
#[cfg(not(fuzzing))]
mod tls;

pub mod pass1;
