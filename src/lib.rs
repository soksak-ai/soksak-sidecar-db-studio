//! DB Studio service sidecar library. Op handlers + the serve entry point.

pub mod gate;
pub mod service;

pub use service::run_serve;
