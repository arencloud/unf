use super::*;
use unf_encryption::EncryptionGenerationRecipient;

#[derive(Default)]
struct MockRuntime {
    events: Vec<&'static str>,
    fail_withdraw: bool,
    fail_arm: bool,
}

impl FenceRuntime for MockRuntime {
    fn withdraw(&mut self) -> Result<()> {
        self.events.push("withdraw");
        ensure!(!self.fail_withdraw, "injected withdrawal failure");
        Ok(())
    }
    fn arm(&mut self, _: &EncryptionLocalityContext) -> Result<()> {
        self.events.push("arm");
        ensure!(!self.fail_arm, "injected fence write failure");
        Ok(())
    }
}

fn state() -> Arc<Mutex<State<MockRuntime>>> {
    Arc::new(Mutex::new(State::new(MockRuntime::default()).unwrap()))
}

fn context() -> EncryptionLocalityContext {
    EncryptionLocalityContext {
        cluster_id: "test".into(),
        recipient: EncryptionGenerationRecipient {
            node_name: "node".into(),
            node_uid: "uid".into(),
        },
        membership_revision: Revision::new(3),
        identity_epoch: 7,
        identity_revision: Revision::new(11),
        routing_revision: Revision::new(13),
    }
}

fn settle(state: &Arc<Mutex<State<MockRuntime>>>) {
    Update::begin(state, LocalityApplyComponent::Identity)
        .unwrap()
        .complete(7, Revision::new(11))
        .unwrap();
    Update::begin(state, LocalityApplyComponent::Routing)
        .unwrap()
        .complete(7, Revision::new(13))
        .unwrap();
}

#[test]
fn startup_unknown_cannot_publish_or_arm() {
    let state = state();
    assert!(
        lock(&state)
            .unwrap()
            .admit::<()>(&context(), |_| panic!("publication on unknown inputs"))
            .is_err()
    );
    assert_eq!(
        lock(&state).unwrap().runtime.events,
        ["withdraw", "withdraw"]
    );
}

#[test]
fn concurrent_components_cannot_rearm_each_other() {
    for reverse in [false, true] {
        let state = state();
        let identity = Update::begin(&state, LocalityApplyComponent::Identity).unwrap();
        let routing = Update::begin(&state, LocalityApplyComponent::Routing).unwrap();
        let (first, revision, last, last_revision) = if reverse {
            (routing, 13, identity, 11)
        } else {
            (identity, 11, routing, 13)
        };
        first.complete(7, Revision::new(revision)).unwrap();
        assert!(lock(&state).unwrap().check(&context()).is_err());
        assert!(!lock(&state).unwrap().runtime.events.contains(&"arm"));
        last.complete(7, Revision::new(last_revision)).unwrap();
        let mut state = lock(&state).unwrap();
        state
            .admit(&context(), |runtime| {
                runtime.events.push("publish");
                Ok(19)
            })
            .unwrap();
        assert_eq!(
            state.runtime.events,
            [
                "withdraw", "withdraw", "withdraw", "withdraw", "publish", "arm"
            ]
        );
    }
}

#[test]
fn cancelled_writer_stays_failed_after_other_writer_succeeds() {
    let state = state();
    settle(&state);
    let identity = Update::begin(&state, LocalityApplyComponent::Identity).unwrap();
    let routing = Update::begin(&state, LocalityApplyComponent::Routing).unwrap();
    drop(identity);
    routing.complete(7, Revision::new(13)).unwrap();
    assert!(lock(&state).unwrap().check(&context()).is_err());
    Update::begin(&state, LocalityApplyComponent::Identity)
        .unwrap()
        .complete(7, Revision::new(11))
        .unwrap();
    lock(&state).unwrap().check(&context()).unwrap();
}

#[test]
fn same_component_overlap_is_rejected_without_losing_first_token() {
    let state = state();
    let first = Update::begin(&state, LocalityApplyComponent::Identity).unwrap();
    assert!(Update::begin(&state, LocalityApplyComponent::Identity).is_err());
    first.complete(7, Revision::new(11)).unwrap();
    assert_eq!(
        lock(&state).unwrap().applied[0],
        Applied::Current {
            epoch: 7,
            revision: 11
        }
    );
}

#[test]
fn invalid_completion_retires_writer_and_cannot_arm() {
    for (epoch, revision) in [(0, 11), (7, 0)] {
        let state = state();
        let update = Update::begin(&state, LocalityApplyComponent::Identity).unwrap();
        assert!(update.complete(epoch, Revision::new(revision)).is_err());
        assert_eq!(lock(&state).unwrap().applied[0], Applied::Failed);
    }
}

#[test]
fn withdrawal_failure_poison_is_sticky() {
    let state = state();
    settle(&state);
    lock(&state).unwrap().runtime.fail_withdraw = true;
    assert!(Update::begin(&state, LocalityApplyComponent::Routing).is_err());
    lock(&state).unwrap().runtime.fail_withdraw = false;
    assert!(Update::begin(&state, LocalityApplyComponent::Identity).is_err());
    assert!(lock(&state).unwrap().check(&context()).is_err());
}

#[test]
fn publication_or_arm_failure_requires_both_inputs_to_be_revalidated() {
    for fail_publish in [false, true] {
        let state = state();
        settle(&state);
        {
            let mut state = lock(&state).unwrap();
            state.runtime.fail_arm = !fail_publish;
            assert!(
                state
                    .admit(&context(), |runtime| {
                        runtime.events.push("publish");
                        ensure!(!fail_publish, "injected publication failure");
                        Ok(())
                    })
                    .is_err()
            );
            assert_eq!(state.applied, [Applied::Failed; 2]);
            assert_eq!(state.runtime.events.last(), Some(&"withdraw"));
        }
        Update::begin(&state, LocalityApplyComponent::Identity)
            .unwrap()
            .complete(7, Revision::new(11))
            .unwrap();
        assert!(lock(&state).unwrap().check(&context()).is_err());
        Update::begin(&state, LocalityApplyComponent::Routing)
            .unwrap()
            .complete(7, Revision::new(13))
            .unwrap();
        lock(&state).unwrap().check(&context()).unwrap();
    }
}

#[test]
fn exhausted_serial_never_wraps_to_old_token() {
    let state = state();
    lock(&state).unwrap().serial = u64::MAX;
    assert!(Update::begin(&state, LocalityApplyComponent::Identity).is_err());
    assert!(lock(&state).unwrap().poisoned);
    assert_eq!(lock(&state).unwrap().serial, u64::MAX);
}

#[test]
fn each_changed_or_zero_coordinate_rejects_before_publication() {
    let state = state();
    settle(&state);
    for index in 0..3 {
        for zero in [false, true] {
            let mut changed = context();
            match index {
                0 => changed.identity_epoch = if zero { 0 } else { 8 },
                1 => changed.identity_revision = Revision::new(if zero { 0 } else { 12 }),
                _ => changed.routing_revision = Revision::new(if zero { 0 } else { 14 }),
            }
            assert!(
                lock(&state)
                    .unwrap()
                    .admit::<()>(&changed, |_| panic!("stale publication"))
                    .is_err()
            );
        }
    }
    lock(&state).unwrap().check(&context()).unwrap();
}

#[test]
fn panic_poison_is_not_silently_recovered() {
    let state = state();
    let other = Arc::clone(&state);
    assert!(
        std::thread::spawn(move || {
            let _locked = other.lock().unwrap();
            panic!("injected writer panic");
        })
        .join()
        .is_err()
    );
    assert!(Update::begin(&state, LocalityApplyComponent::Identity).is_err());
}
