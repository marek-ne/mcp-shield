//! mcp-shield library surface (the CLI binary in `main.rs` is a thin dispatcher).

pub mod audit;
pub mod cli;
pub mod config;
pub mod doctor;
pub mod hitl;
pub mod keychain;
pub mod mock_server;
pub mod policy;
pub mod proxy;
pub mod redactor;
pub mod util;
pub mod verify;
