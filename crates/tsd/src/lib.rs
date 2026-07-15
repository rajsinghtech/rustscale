//! Typed, set-once daemon dependency storage.
//!
//! [`System`] is the RustScale equivalent of Tailscale's `tsd.System`. Values
//! are shared through `Arc`, may be installed once, and are retrieved with
//! their concrete type checked at runtime. [`SubSystem`] is useful when a
//! consumer wants a dedicated typed slot instead of the heterogeneous system.

#![forbid(unsafe_code)]

use std::any::{type_name, Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

/// A typed subsystem slot that can be populated once.
#[derive(Debug)]
pub struct SubSystem<T> {
    value: Mutex<Option<Arc<T>>>,
}

impl<T> SubSystem<T> {
    /// Creates an empty subsystem slot.
    pub const fn new() -> Self {
        Self {
            value: Mutex::new(None),
        }
    }

    /// Sets the subsystem.
    ///
    /// Setting the exact same `Arc` again is idempotent. A different value is
    /// rejected, preserving the set-once invariant.
    pub fn set(&self, value: Arc<T>) -> Result<(), DependencyError> {
        let mut current = self.value.lock().expect("subsystem lock poisoned");
        match current.as_ref() {
            Some(old) if Arc::ptr_eq(old, &value) => Ok(()),
            Some(_) => Err(DependencyError::AlreadySet {
                key: type_name::<T>(),
            }),
            None => {
                *current = Some(value);
                Ok(())
            }
        }
    }

    /// Gets the subsystem, failing if it has not been set.
    pub fn get(&self) -> Result<Arc<T>, DependencyError> {
        self.get_ok().ok_or(DependencyError::NotSet {
            key: type_name::<T>(),
        })
    }

    /// Gets the subsystem if it has been set.
    pub fn get_ok(&self) -> Option<Arc<T>> {
        self.value.lock().expect("subsystem lock poisoned").clone()
    }
}

impl<T> Default for SubSystem<T> {
    fn default() -> Self {
        Self::new()
    }
}

struct Entry {
    type_id: TypeId,
    type_name: &'static str,
    value: Arc<dyn Any + Send + Sync>,
}

/// Thread-safe typed dependency container for daemon subsystems.
///
/// The ordinary [`set`](Self::set) and [`get`](Self::get) methods key values by
/// their Rust type. Named methods are provided for the uncommon case where a
/// host needs multiple values with the same concrete type.
#[derive(Default)]
pub struct System {
    entries: Mutex<HashMap<&'static str, Entry>>,
}

impl System {
    /// Creates an empty dependency container.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a dependency under its concrete Rust type.
    pub fn set<T>(&self, value: Arc<T>) -> Result<(), DependencyError>
    where
        T: Any + Send + Sync,
    {
        self.set_named(type_name::<T>(), value)
    }

    /// Allocates and registers an owned dependency value.
    pub fn set_value<T>(&self, value: T) -> Result<Arc<T>, DependencyError>
    where
        T: Any + Send + Sync,
    {
        let value = Arc::new(value);
        self.set(Arc::clone(&value))?;
        Ok(value)
    }

    /// Registers a dependency under `key`.
    pub fn set_named<T>(&self, key: &'static str, value: Arc<T>) -> Result<(), DependencyError>
    where
        T: Any + Send + Sync,
    {
        let mut entries = self.entries.lock().expect("system lock poisoned");
        if let Some(current) = entries.get(key) {
            if current.type_id != TypeId::of::<T>() {
                return Err(DependencyError::TypeMismatch {
                    key,
                    expected: current.type_name,
                    actual: type_name::<T>(),
                });
            }
            let current = Arc::clone(&current.value)
                .downcast::<T>()
                .expect("matching dependency TypeId must downcast");
            return if Arc::ptr_eq(&current, &value) {
                Ok(())
            } else {
                Err(DependencyError::AlreadySet { key })
            };
        }

        entries.insert(
            key,
            Entry {
                type_id: TypeId::of::<T>(),
                type_name: type_name::<T>(),
                value,
            },
        );
        Ok(())
    }

    /// Gets a dependency registered under its concrete Rust type.
    pub fn get<T>(&self) -> Result<Arc<T>, DependencyError>
    where
        T: Any + Send + Sync,
    {
        self.get_named(type_name::<T>())
    }

    /// Gets a named dependency and verifies its concrete Rust type.
    pub fn get_named<T>(&self, key: &'static str) -> Result<Arc<T>, DependencyError>
    where
        T: Any + Send + Sync,
    {
        let value = {
            let entries = self.entries.lock().expect("system lock poisoned");
            let entry = entries.get(key).ok_or(DependencyError::NotSet { key })?;
            if entry.type_id != TypeId::of::<T>() {
                return Err(DependencyError::TypeMismatch {
                    key,
                    expected: entry.type_name,
                    actual: type_name::<T>(),
                });
            }
            Arc::clone(&entry.value)
        };
        value
            .downcast::<T>()
            .map_err(|_| DependencyError::TypeMismatch {
                key,
                expected: "registered dependency type",
                actual: type_name::<T>(),
            })
    }

    /// Gets a dependency if it is set.
    pub fn get_ok<T>(&self) -> Result<Option<Arc<T>>, DependencyError>
    where
        T: Any + Send + Sync,
    {
        match self.get::<T>() {
            Ok(value) => Ok(Some(value)),
            Err(DependencyError::NotSet { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Returns the number of registered dependencies.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("system lock poisoned").len()
    }

    /// Returns whether no dependencies have been registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for System {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().expect("system lock poisoned");
        let mut keys: Vec<_> = entries.keys().copied().collect();
        keys.sort_unstable();
        f.debug_struct("System")
            .field("dependencies", &keys)
            .finish()
    }
}

/// A typed dependency registration or lookup error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DependencyError {
    /// The dependency slot already contains another value.
    AlreadySet { key: &'static str },
    /// The dependency slot has not been populated.
    NotSet { key: &'static str },
    /// A named dependency exists with another concrete Rust type.
    TypeMismatch {
        key: &'static str,
        expected: &'static str,
        actual: &'static str,
    },
}

impl fmt::Display for DependencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadySet { key } => write!(f, "{key} is already set"),
            Self::NotSet { key } => write!(f, "{key} is not set"),
            Self::TypeMismatch {
                key,
                expected,
                actual,
            } => write!(
                f,
                "dependency {key} has type {expected}, not requested type {actual}"
            ),
        }
    }
}

impl std::error::Error for DependencyError {}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::{DependencyError, SubSystem, System};

    #[test]
    fn subsystem_is_set_once_and_allows_same_arc() {
        let subsystem = SubSystem::new();
        let first = Arc::new(String::from("first"));
        subsystem.set(Arc::clone(&first)).unwrap();
        subsystem.set(Arc::clone(&first)).unwrap();
        assert!(Arc::ptr_eq(&subsystem.get().unwrap(), &first));
        assert!(matches!(
            subsystem.set(Arc::new(String::from("second"))),
            Err(DependencyError::AlreadySet { .. })
        ));
    }

    #[test]
    fn system_reports_missing_duplicate_and_type_mismatch() {
        let system = System::new();
        assert!(matches!(
            system.get::<u64>(),
            Err(DependencyError::NotSet { .. })
        ));

        let value = Arc::new(42_u64);
        system.set_named("answer", Arc::clone(&value)).unwrap();
        system.set_named("answer", Arc::clone(&value)).unwrap();
        assert_eq!(*system.get_named::<u64>("answer").unwrap(), 42);
        assert!(matches!(
            system.set_named("answer", Arc::new(7_u64)),
            Err(DependencyError::AlreadySet { .. })
        ));
        assert!(matches!(
            system.get_named::<String>("answer"),
            Err(DependencyError::TypeMismatch { .. })
        ));
        assert!(matches!(
            system.set_named("answer", Arc::new(String::new())),
            Err(DependencyError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn concurrent_set_has_one_winner_and_concurrent_gets_are_safe() {
        const WORKERS: usize = 16;
        let system = Arc::new(System::new());
        let barrier = Arc::new(Barrier::new(WORKERS));
        let threads: Vec<_> = (0..WORKERS)
            .map(|index| {
                let system = Arc::clone(&system);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    system.set(Arc::new(index))
                })
            })
            .collect();

        let winners = threads.into_iter().fold(0, |winners, thread| {
            winners + usize::from(thread.join().unwrap().is_ok())
        });
        assert_eq!(winners, 1);
        let value = system.get::<usize>().unwrap();

        let readers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let system = Arc::clone(&system);
                thread::spawn(move || system.get::<usize>().unwrap())
            })
            .collect();
        for reader in readers {
            assert_eq!(*reader.join().unwrap(), *value);
        }
    }
}
