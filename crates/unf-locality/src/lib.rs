//! Production locality building blocks. A journal lease alone is NOT placement,
//! kernel device/route proof, policy permission or observed packet delivery.

mod admission;
pub mod helper;
mod incarnation;
mod kernel;
mod observed;
mod worker;

pub use admission::{LocalityAdmission, LocalityApplyComponent, LocalityApplyGuard};
pub use incarnation::{IncarnationGate, IncarnationLease, LocalityGateError};
pub use kernel::{KernelLocalityBank, LocalityRuntimeMaps};
pub use observed::{
    LeasedLocalityBank, LocalityAddress, LocalityBankError, ObservedLocalityBank,
    ObservedLocalityEndpoint,
};
pub use worker::{LocalityObservationTask, LocalityObservationWorker, LocalityPreparationTask};
