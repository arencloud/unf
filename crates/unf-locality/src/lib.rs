//! Production locality building blocks. A journal lease alone is NOT placement,
//! kernel device/route proof, policy permission or observed packet delivery.

mod incarnation;

pub use incarnation::{IncarnationGate, IncarnationLease, LocalityGateError};
