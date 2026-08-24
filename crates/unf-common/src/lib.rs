#![cfg_attr(not(feature = "serde"), no_std)]

//! Small domain primitives shared across UNF components.

macro_rules! numeric_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[repr(transparent)]
        pub struct $name(pub u32);

        impl $name {
            #[must_use]
            pub const fn new(value: u32) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn get(self) -> u32 {
                self.0
            }
        }
    };
}

numeric_id!(IdentityId);
numeric_id!(PolicyId);
numeric_id!(RuleId);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Revision(pub u64);

impl Revision {
    pub const INITIAL: Self = Self(0);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Protocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Sctp = 132,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PolicyAction {
    Allow = 1,
    Deny = 2,
    Audit = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Verdict {
    Unknown = 0,
    Allow = 1,
    Deny = 2,
    Audit = 3,
}

/// Stable machine-readable provenance for an effective policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PolicyReason {
    NoApplicablePolicy = 0,
    ExplicitRule = 1,
    DefaultAction = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_do_not_implicitly_mix() {
        let identity = IdentityId::new(7);
        let policy = PolicyId::new(7);
        assert_eq!(identity.get(), policy.get());
    }

    #[test]
    fn revision_is_monotonic_and_saturating() {
        assert_eq!(Revision::INITIAL.next(), Revision::new(1));
        assert_eq!(Revision::new(u64::MAX).next(), Revision::new(u64::MAX));
    }
}
