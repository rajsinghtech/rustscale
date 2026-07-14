//! Asynchronous duplicate-suppressing function calls.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_util::FutureExt;
use tokio::sync::Mutex;

/// Result of a [`Group::do_`] call.
#[derive(Debug, Clone)]
pub struct Result<V, E> {
    /// The value returned by the function, when `err` is `None`.
    pub val: Option<V>,
    /// The error returned by the function, if any.
    pub err: Option<E>,
    /// Whether another caller joined this invocation.
    pub shared: bool,
}

/// Duplicate-suppressing asynchronous function call group.
///
/// Concurrent calls with the same key run only one future; joined callers
/// receive a clone of its result. Completed calls are removed, so this is not
/// a cache. Panics are propagated to every joined caller.
pub struct Group<K, V, E> {
    inner: Mutex<HashMap<K, Arc<Call<V, E>>>>,
}

struct Call<V, E> {
    slot: Mutex<Slot<V, E>>,
    shared: AtomicBool,
}

enum Slot<V, E> {
    Vacant,
    Filled(Result<V, E>),
    Panicked(String),
}

impl<K, V, E> Group<K, V, E> {
    /// Creates an empty group.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Removes `key` from the group, allowing a later call to start fresh.
    pub async fn forget(&self, key: &K)
    where
        K: Eq + Hash,
    {
        self.inner.lock().await.remove(key);
    }

    /// Returns the number of currently tracked calls.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Returns whether the group has no tracked calls.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }
}

impl<K, V, E> Default for Group<K, V, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V, E> Group<K, V, E>
where
    K: Eq + Hash + Clone,
    V: Clone,
    E: Clone,
{
    /// Executes `f` once for concurrent calls using `key`.
    ///
    /// If the task selected to run `f` is cancelled, another waiting caller
    /// can take over the vacant slot using its own closure.
    pub async fn do_<F, Fut>(&self, key: K, f: F) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = std::result::Result<V, E>>,
    {
        let call = {
            let mut calls = self.inner.lock().await;
            if let Some(call) = calls.get(&key) {
                call.shared.store(true, Ordering::Release);
                Arc::clone(call)
            } else {
                let call = Arc::new(Call {
                    slot: Mutex::new(Slot::Vacant),
                    shared: AtomicBool::new(false),
                });
                calls.insert(key.clone(), Arc::clone(&call));
                call
            }
        };

        let mut slot = call.slot.lock().await;
        match &*slot {
            Slot::Filled(result) => return result.clone(),
            Slot::Panicked(message) => panic!("singleflight call panicked: {message}"),
            Slot::Vacant => {}
        }

        let outcome = AssertUnwindSafe(f()).catch_unwind().await;
        let result = match outcome {
            Ok(Ok(val)) => Result {
                val: Some(val),
                err: None,
                shared: call.shared.load(Ordering::Acquire),
            },
            Ok(Err(err)) => Result {
                val: None,
                err: Some(err),
                shared: call.shared.load(Ordering::Acquire),
            },
            Err(panic) => {
                let message = panic_message(panic);
                *slot = Slot::Panicked(message.clone());
                self.remove_if_current(&key, &call).await;
                panic!("singleflight call panicked: {message}");
            }
        };

        *slot = Slot::Filled(result.clone());
        self.remove_if_current(&key, &call).await;
        result
    }

    async fn remove_if_current(&self, key: &K, call: &Arc<Call<V, E>>) {
        let mut calls = self.inner.lock().await;
        if calls
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, call))
        {
            calls.remove(key);
        }
    }
}

fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::Group;

    #[tokio::test]
    async fn do_dedup() {
        let group = Arc::new(Group::<String, usize, String>::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());
        let mut tasks = Vec::new();

        for _ in 0..10 {
            let group = Arc::clone(&group);
            let calls = Arc::clone(&calls);
            let gate = Arc::clone(&gate);
            tasks.push(tokio::spawn(async move {
                group
                    .do_("k".to_owned(), || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        gate.notified().await;
                        Ok(42)
                    })
                    .await
            }));
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
        gate.notify_waiters();
        let results: Vec<_> = futures_util::future::join_all(tasks)
            .await
            .into_iter()
            .map(|task| task.expect("task should not panic"))
            .collect();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(results
            .iter()
            .all(|result| result.val == Some(42) && result.err.is_none()));
        assert!(results.iter().any(|result| result.shared));
    }

    #[tokio::test]
    async fn do_error() {
        let group = Arc::new(Group::<String, (), String>::new());
        let gate = Arc::new(Notify::new());
        let first_group = Arc::clone(&group);
        let first_gate = Arc::clone(&gate);
        let first = tokio::spawn(async move {
            first_group
                .do_("k".to_owned(), || async move {
                    first_gate.notified().await;
                    Err("nope".to_owned())
                })
                .await
        });
        tokio::task::yield_now().await;
        let second_group = Arc::clone(&group);
        let second = tokio::spawn(async move {
            second_group
                .do_("k".to_owned(), || async { Err("wrong".to_owned()) })
                .await
        });
        gate.notify_waiters();
        assert_eq!(
            first.await.expect("first task").err.as_deref(),
            Some("nope")
        );
        assert_eq!(
            second.await.expect("second task").err.as_deref(),
            Some("nope")
        );
    }

    #[tokio::test]
    async fn do_forget() {
        let group = Arc::new(Group::<String, usize, String>::new());
        let gate = Arc::new(Notify::new());
        let first_group = Arc::clone(&group);
        let first_gate = Arc::clone(&gate);
        let first = tokio::spawn(async move {
            first_group
                .do_("k".to_owned(), || async move {
                    first_gate.notified().await;
                    Ok(1)
                })
                .await
        });
        tokio::task::yield_now().await;
        group.forget(&"k".to_owned()).await;
        let second = group.do_("k".to_owned(), || async { Ok(2) }).await;
        gate.notify_waiters();
        assert_eq!(second.val, Some(2));
        assert_eq!(first.await.expect("first task").val, Some(1));
    }

    #[tokio::test]
    async fn do_empty() {
        let group = Group::<String, usize, String>::new();
        assert!(group.is_empty().await);
        let _ = group.do_("k".to_owned(), || async { Ok(1) }).await;
        assert_eq!(group.len().await, 0);
    }

    #[tokio::test]
    async fn do_panic() {
        let group = Arc::new(Group::<String, (), String>::new());
        let gate = Arc::new(Notify::new());
        let first_group = Arc::clone(&group);
        let first_gate = Arc::clone(&gate);
        let first = tokio::spawn(async move {
            first_group
                .do_("k".to_owned(), || async move {
                    first_gate.notified().await;
                    panic!("boom")
                })
                .await
        });
        tokio::task::yield_now().await;
        let second_group = Arc::clone(&group);
        let second =
            tokio::spawn(
                async move { second_group.do_("k".to_owned(), || async { Ok(()) }).await },
            );
        tokio::time::sleep(Duration::from_millis(10)).await;
        gate.notify_waiters();
        assert!(first.await.is_err());
        assert!(second.await.is_err());
    }

    #[tokio::test]
    async fn do_cancel_resume() {
        let group = Arc::new(Group::<String, usize, String>::new());
        let gate = Arc::new(Notify::new());
        let cancelled_group = Arc::clone(&group);
        let cancelled_gate = Arc::clone(&gate);
        let cancelled = tokio::spawn(async move {
            cancelled_group
                .do_("k".to_owned(), || async move {
                    cancelled_gate.notified().await;
                    Ok(1)
                })
                .await
        });
        tokio::task::yield_now().await;
        cancelled.abort();
        let resumed = group.do_("k".to_owned(), || async { Ok(2) }).await;
        assert_eq!(resumed.val, Some(2));
    }
}
