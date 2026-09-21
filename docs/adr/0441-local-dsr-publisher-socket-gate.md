# ADR 0441: Local DSR publisher/socket gate

Date: 2026-09-21

Status: implemented; local checks pass; cl02-first execution pending

Extend the actual publisher/main-classifier socket fixture to DSR LoadBalancer
frontends. Use the real Service selection contract, reachability snapshot and
Service bank activation. Keep the structurally admitted empty transport cut:
there is no ordinary Native decision to hide a locality-bank miss.

The application binds only its backend PodIP and port, never the frontend VIP.
Eight successful IPv4/IPv6 TCP/UDP request/reply exchanges therefore require
the actual locality DSR continuation to create reversible translation. Read
the actual Service connection map for the successful source ports and require
sixteen forward/reverse entries with encrypted-NAT flags and no VIP-only DSR
flag. This flag names the shared reversible-translation implementation; these
same-Node exchanges do not claim ciphertext.

The identity writer boundary withdraws locality before mutation. Four new
DSR connections must time out while withdrawn; completing the writer and
fresh publication must recover delivery. Denied requests may retain provisional
forward selection state, which is not packet authority and must not be mistaken
for successful reply state. The complete fixture now requires 24 positive
exchanges and 24 denials, explicit DSR evidence and exact resource cleanup.

Strict agent all-target Clippy and all 912 workspace tests pass; the 31 ignored
privileged tests are not platform passes. Run the expanded immutable diagnostic
on cl02 before the same image on Kind. Existing ADR 0440 qualification retains
its own earlier 16-positive/20-negative gate and is not relabeled.

This is private-network DSR composition, not complete authenticated fleet
validation, remote Required transport, mixed replicas, restart recovery or a
performance result. L3/L4/L5/Q and S1–S5 remain open.
