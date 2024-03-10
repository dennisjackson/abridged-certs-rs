#![feature(cursor_remaining)]
#![feature(custom_test_frameworks)]
#![test_runner(datatest::runner)]

/* Expose internal functions to fuzzer */
#[cfg(fuzzing)]
pub mod tls;
#[cfg(not(fuzzing))]
mod tls;

pub mod pass1;
