use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
struct DelayedRegistration {
    clock: AtomicU64,
    completed: u64,
    wait_before_commit: bool,
    committed: AtomicU64,
}
impl RegistrationStore for DelayedRegistration {
    async fn reserve(
        &self,
        _: &ScopedIdentity,
        _: &str,
        _: u64,
        _: &str,
        valid_until: u64,
    ) -> Result<(), Error> {
        assert_eq!(valid_until, 1500);
        yield_once().await;
        if self.wait_before_commit {
            self.clock.store(self.completed, Ordering::SeqCst);
        }
        if self.clock.load(Ordering::SeqCst) >= valid_until {
            return Err(Error::Registration);
        }
        self.committed.fetch_add(1, Ordering::SeqCst);
        yield_once().await;
        self.clock.store(self.completed, Ordering::SeqCst);
        Ok(())
    }
}
#[test]
fn registration_deadline_is_checked_inside_commit_and_after_the_wait() {
    let identity = wallet()
        .verify(&sign(claims(), binding(), &[]), &context(), 1100)
        .unwrap()
        .comparison(&IdentityKey::new([7; 32]).unwrap(), "scope")
        .unwrap();
    let request = Registration {
        policy_scope: "window".into(),
        maximum: 2,
        operation: "registration".into(),
    };
    for (completed, wait_before_commit) in [(1500, true), (1500, false), (1100 - 1, false)] {
        let store = DelayedRegistration {
            clock: AtomicU64::new(1100),
            completed,
            wait_before_commit,
            committed: AtomicU64::new(0),
        };
        let result =
            block_on(identity.register(&store, &request, &|| store.clock.load(Ordering::SeqCst)));
        if wait_before_commit {
            assert_eq!(result, Err(Error::Registration));
            assert_eq!(store.committed.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(store.committed.load(Ordering::SeqCst), 1);
            assert_eq!(
                result,
                if completed >= 1500 || completed < 1100 {
                    Err(Error::Rejected)
                } else {
                    Ok(())
                }
            );
        }
    }
}

async fn yield_once() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await
}
