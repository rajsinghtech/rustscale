//! Login flags — bitmask of options that change registration behavior.
//!
//! Ports Go's `controlclient.LoginFlags` (`control/client.go:18-26`).

/// Bitmask of options to change the behavior of registration and
/// `LocalBackend` login. Matches Go's `LoginFlags int`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct LoginFlags(pub u8);

/// No flags — default behavior (refresh existing key, no interaction).
pub const LOGIN_DEFAULT: LoginFlags = LoginFlags(0);

/// Force user login and key refresh. When set, the client generates a
/// new node key even if the current one has not expired.
pub const LOGIN_INTERACTIVE: LoginFlags = LoginFlags(1);

/// Set `RegisterRequest.Ephemeral = true` — the node is auto-deleted
/// when it goes offline.
pub const LOGIN_EPHEMERAL: LoginFlags = LoginFlags(2);

impl LoginFlags {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: LoginFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn insert(self, other: LoginFlags) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_interactive(self) -> bool {
        self.contains(LOGIN_INTERACTIVE)
    }

    pub const fn is_ephemeral(self) -> bool {
        self.contains(LOGIN_EPHEMERAL)
    }
}

impl std::ops::BitOr for LoginFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_flags_bitmask() {
        assert!(!LOGIN_DEFAULT.is_interactive());
        assert!(LOGIN_INTERACTIVE.is_interactive());
        assert!(!LOGIN_EPHEMERAL.is_interactive());
        assert!(!LOGIN_INTERACTIVE.is_ephemeral());
        assert!(LOGIN_EPHEMERAL.is_ephemeral());

        let both = LOGIN_INTERACTIVE | LOGIN_EPHEMERAL;
        assert!(both.is_interactive());
        assert!(both.is_ephemeral());
        assert!(both.contains(LOGIN_INTERACTIVE));
        assert!(both.contains(LOGIN_EPHEMERAL));
    }
}
