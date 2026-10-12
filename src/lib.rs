//! tidyscan: analyse directory trees and clean them up safely.
//!
//! The library is UI-agnostic; `cli` and `ui` are thin layers over it.

pub mod actions;
pub mod age;
pub mod analysis;
pub mod cli;
pub mod context;
pub mod dupes;
pub mod model;
pub mod organize;
pub mod rules;
pub mod scan;
pub mod triage;
pub mod ui;
