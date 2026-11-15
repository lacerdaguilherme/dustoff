//! dustoff: find and safely remove disk-space hogs.
//!
//! The library holds all logic so other front ends (TUI, GUI) can reuse it.

pub mod clean;
pub mod fmt;
pub mod orphans;
pub mod projects;
pub mod rules;
pub mod safety;
pub mod scan;
