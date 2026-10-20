//! A heap-free async executor for firmware and small kernels.
//!
//! Tasks are `'static` futures placed in a fixed number of slots (`N`), so
//! nothing is allocated. Wakers are plain pointers to a slot's ready flag,
//! so they may be woken from interrupt handlers. When no task is ready the
//! executor waits for an interrupt, with no window in which a wake-up could
//! be lost.
//!
//! ```no_run
//! use core::pin::pin;
//! use osmium_exec::{Executor, Signal, yield_now};
//!
//! static EXEC: Executor<4> = Executor::new();
//! static RX: Signal<u8> = Signal::new();
//!
//! /// Called from the UART receive interrupt.
//! fn uart_irq(byte: u8) {
//!     RX.signal(byte);
//! }
//!
//! async fn echo() {
//!     loop {
//!         let byte = RX.wait().await;
//!         let _ = byte; // ... write it back ...
//!     }
//! }
//!
//! async fn heartbeat() {
//!     loop {
//!         yield_now().await;
//!     }
//! }
//!
//! fn main_loop() -> ! {
//!     // No heap: the futures live on this (never-returning) stack frame.
//!     EXEC.run_with(&mut [pin!(echo()), pin!(heartbeat())])
//! }
//! # let _ = (uart_irq, main_loop);
//! ```
//!
//! Tasks can also be spawned at run time with [`Executor::spawn`] from
//! `'static` storage such as a [`StaticCell`].
#![no_std]

#[cfg(test)]
extern crate std;

mod executor;
mod signal;
mod static_cell;

pub use executor::{Executor, SpawnError, yield_now};
pub use signal::{AtomicWaker, Signal};
pub use static_cell::StaticCell;
