use std::{fmt, str::FromStr};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

/// The broadest scope at which a setting applies.
///
/// The ordering is significant: device policy has higher merge precedence than
/// profile policy, which has higher precedence than user policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Scope {
    /// A setting that applies to the whole device.
    Device,
    /// A setting that applies to a Tailscale profile.
    Profile,
    /// A setting that applies to an operating-system user.
    User,
}

/// A concrete policy query or provider scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyScope {
    /// Device-global policy.
    Device,
    /// Policy for the current or named profile.
    Profile(Option<String>),
    /// Policy for the current or named user, optionally within a profile.
    User {
        user_id: Option<String>,
        profile_id: Option<String>,
    },
}

impl PolicyScope {
    /// Returns the broad scope kind.
    pub const fn kind(&self) -> Scope {
        match self {
            Self::Device => Scope::Device,
            Self::Profile(_) => Scope::Profile,
            Self::User { .. } => Scope::User,
        }
    }

    /// Returns a scope for a named user.
    pub fn user(user_id: impl Into<String>) -> Self {
        Self::User {
            user_id: Some(user_id.into()),
            profile_id: None,
        }
    }

    /// Reports whether settings from this provider scope apply to `other`.
    pub fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Device, _) => true,
            (Self::Profile(a), Self::Profile(b)) => a == b,
            (Self::Profile(a), Self::User { profile_id: b, .. }) => a == b,
            (Self::User { user_id: a, .. }, Self::User { user_id: b, .. }) => a == b,
            _ => false,
        }
    }

    /// Reports whether a setting can be configured by a provider at this scope.
    pub fn can_configure(&self, definition: &SettingDefinition) -> bool {
        definition.scope >= self.kind()
    }

    /// Reports whether a setting can be queried at this scope.
    pub fn is_applicable(&self, definition: &SettingDefinition) -> bool {
        definition.scope <= self.kind()
    }
}

impl fmt::Display for PolicyScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device => formatter.write_str("Device"),
            Self::Profile(None) => formatter.write_str("Profile"),
            Self::Profile(Some(id)) => write!(formatter, "Profile({id})"),
            Self::User {
                user_id: None,
                profile_id: None,
            } => formatter.write_str("User"),
            Self::User {
                user_id,
                profile_id,
            } => {
                if let Some(profile_id) = profile_id {
                    write!(formatter, "Profile({profile_id})/")?;
                }
                match user_id {
                    Some(id) => write!(formatter, "User({id})"),
                    None => formatter.write_str("User"),
                }
            }
        }
    }
}

/// The kind of value expected for a policy key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueType {
    /// A boolean value.
    Boolean,
    /// An unsigned 64-bit integer.
    Integer,
    /// A plain string.
    String,
    /// A list of strings.
    StringList,
    /// One of `always`, `never`, or `user-decides`.
    PreferenceOption,
    /// One of `show` or `hide`.
    Visibility,
    /// A Go `time.Duration` formatted string.
    Duration,
}

/// A typed policy setting definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SettingDefinition {
    /// Stable policy key.
    pub key: PolicyKey,
    /// Broadest scope at which this setting applies.
    pub scope: Scope,
    /// Effective value type.
    pub value_type: ValueType,
}

impl SettingDefinition {
    /// Creates a definition.
    pub const fn new(key: PolicyKey, scope: Scope, value_type: ValueType) -> Self {
        Self {
            key,
            scope,
            value_type,
        }
    }
}

/// A known enterprise policy key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyKey {
    ControlURL,
    LogTarget,
    Tailnet,
    ExitNodeID,
    ExitNodeIP,
    Hostname,
    AuthKey,
    DeviceSerialNumber,
    ManagedByCaption,
    ManagedByOrganizationName,
    ManagedByURL,
    MachineCertificateSubject,
    AlwaysOn,
    AlwaysOnOverrideWithReason,
    AllowTailscaledRestart,
    AllowExitNodeOverride,
    LogSCMInteractions,
    FlushDNSOnSessionUnlock,
    EncryptState,
    HardwareAttestation,
    EnableIncomingConnections,
    EnableServerMode,
    ExitNodeAllowLANAccess,
    EnableTailscaleDNS,
    EnableTailscaleSubnets,
    EnableDNSRegistration,
    CheckUpdates,
    ApplyUpdates,
    EnableRunExitNode,
    PostureChecking,
    ReconnectAfter,
    KeyExpirationNoticeTime,
    AdminConsoleVisibility,
    NetworkDevicesVisibility,
    TestMenuVisibility,
    UpdateMenuVisibility,
    ResetToDefaultsVisibility,
    RunExitNodeVisibility,
    PreferencesMenuVisibility,
    ExitNodeMenuVisibility,
    AutoUpdateVisibility,
    SuggestedExitNodeVisibility,
    OnboardingFlowVisibility,
    AllowedSuggestedExitNodes,
}

impl PolicyKey {
    /// Every supported policy key.
    pub const ALL: [Self; 44] = [
        Self::ControlURL,
        Self::LogTarget,
        Self::Tailnet,
        Self::ExitNodeID,
        Self::ExitNodeIP,
        Self::Hostname,
        Self::AuthKey,
        Self::DeviceSerialNumber,
        Self::ManagedByCaption,
        Self::ManagedByOrganizationName,
        Self::ManagedByURL,
        Self::MachineCertificateSubject,
        Self::AlwaysOn,
        Self::AlwaysOnOverrideWithReason,
        Self::AllowTailscaledRestart,
        Self::AllowExitNodeOverride,
        Self::LogSCMInteractions,
        Self::FlushDNSOnSessionUnlock,
        Self::EncryptState,
        Self::HardwareAttestation,
        Self::EnableIncomingConnections,
        Self::EnableServerMode,
        Self::ExitNodeAllowLANAccess,
        Self::EnableTailscaleDNS,
        Self::EnableTailscaleSubnets,
        Self::EnableDNSRegistration,
        Self::CheckUpdates,
        Self::ApplyUpdates,
        Self::EnableRunExitNode,
        Self::PostureChecking,
        Self::ReconnectAfter,
        Self::KeyExpirationNoticeTime,
        Self::AdminConsoleVisibility,
        Self::NetworkDevicesVisibility,
        Self::TestMenuVisibility,
        Self::UpdateMenuVisibility,
        Self::ResetToDefaultsVisibility,
        Self::RunExitNodeVisibility,
        Self::PreferencesMenuVisibility,
        Self::ExitNodeMenuVisibility,
        Self::AutoUpdateVisibility,
        Self::SuggestedExitNodeVisibility,
        Self::OnboardingFlowVisibility,
        Self::AllowedSuggestedExitNodes,
    ];

    /// The Go-compatible name used in MDM, environment, and JSON policy sources.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ControlURL => "LoginURL",
            Self::LogTarget => "LogTarget",
            Self::Tailnet => "Tailnet",
            Self::ExitNodeID => "ExitNodeID",
            Self::ExitNodeIP => "ExitNodeIP",
            Self::Hostname => "Hostname",
            Self::AuthKey => "AuthKey",
            Self::DeviceSerialNumber => "DeviceSerialNumber",
            Self::ManagedByCaption => "ManagedByCaption",
            Self::ManagedByOrganizationName => "ManagedByOrganizationName",
            Self::ManagedByURL => "ManagedByURL",
            Self::MachineCertificateSubject => "MachineCertificateSubject",
            Self::AlwaysOn => "AlwaysOn.Enabled",
            Self::AlwaysOnOverrideWithReason => "AlwaysOn.OverrideWithReason",
            Self::AllowTailscaledRestart => "AllowTailscaledRestart",
            Self::AllowExitNodeOverride => "ExitNode.AllowOverride",
            Self::LogSCMInteractions => "LogSCMInteractions",
            Self::FlushDNSOnSessionUnlock => "FlushDNSOnSessionUnlock",
            Self::EncryptState => "EncryptState",
            Self::HardwareAttestation => "HardwareAttestation",
            Self::EnableIncomingConnections => "AllowIncomingConnections",
            Self::EnableServerMode => "UnattendedMode",
            Self::ExitNodeAllowLANAccess => "ExitNodeAllowLANAccess",
            Self::EnableTailscaleDNS => "UseTailscaleDNSSettings",
            Self::EnableTailscaleSubnets => "UseTailscaleSubnets",
            Self::EnableDNSRegistration => "EnableDNSRegistration",
            Self::CheckUpdates => "CheckUpdates",
            Self::ApplyUpdates => "InstallUpdates",
            Self::EnableRunExitNode => "AdvertiseExitNode",
            Self::PostureChecking => "PostureChecking",
            Self::ReconnectAfter => "ReconnectAfter",
            Self::KeyExpirationNoticeTime => "KeyExpirationNotice",
            Self::AdminConsoleVisibility => "AdminConsole",
            Self::NetworkDevicesVisibility => "NetworkDevices",
            Self::TestMenuVisibility => "TestMenu",
            Self::UpdateMenuVisibility => "UpdateMenu",
            Self::ResetToDefaultsVisibility => "ResetToDefaults",
            Self::RunExitNodeVisibility => "RunExitNode",
            Self::PreferencesMenuVisibility => "PreferencesMenu",
            Self::ExitNodeMenuVisibility => "ExitNodesPicker",
            Self::AutoUpdateVisibility => "ApplyUpdates",
            Self::SuggestedExitNodeVisibility => "SuggestedExitNode",
            Self::OnboardingFlowVisibility => "OnboardingFlow",
            Self::AllowedSuggestedExitNodes => "AllowedSuggestedExitNodes",
        }
    }

    /// Returns this key's well-known definition.
    pub const fn definition(self) -> SettingDefinition {
        let scope = match self {
            Self::ManagedByCaption
            | Self::ManagedByOrganizationName
            | Self::ManagedByURL
            | Self::KeyExpirationNoticeTime
            | Self::AdminConsoleVisibility
            | Self::NetworkDevicesVisibility
            | Self::TestMenuVisibility
            | Self::UpdateMenuVisibility
            | Self::ResetToDefaultsVisibility
            | Self::RunExitNodeVisibility
            | Self::PreferencesMenuVisibility
            | Self::ExitNodeMenuVisibility
            | Self::AutoUpdateVisibility
            | Self::SuggestedExitNodeVisibility
            | Self::OnboardingFlowVisibility => Scope::User,
            _ => Scope::Device,
        };
        let value_type = match self {
            Self::AlwaysOn
            | Self::AlwaysOnOverrideWithReason
            | Self::AllowTailscaledRestart
            | Self::AllowExitNodeOverride
            | Self::LogSCMInteractions
            | Self::FlushDNSOnSessionUnlock
            | Self::EncryptState
            | Self::HardwareAttestation => ValueType::Boolean,
            Self::EnableIncomingConnections
            | Self::EnableServerMode
            | Self::ExitNodeAllowLANAccess
            | Self::EnableTailscaleDNS
            | Self::EnableTailscaleSubnets
            | Self::EnableDNSRegistration
            | Self::CheckUpdates
            | Self::ApplyUpdates
            | Self::EnableRunExitNode
            | Self::PostureChecking => ValueType::PreferenceOption,
            Self::ReconnectAfter | Self::KeyExpirationNoticeTime => ValueType::Duration,
            Self::AdminConsoleVisibility
            | Self::NetworkDevicesVisibility
            | Self::TestMenuVisibility
            | Self::UpdateMenuVisibility
            | Self::ResetToDefaultsVisibility
            | Self::RunExitNodeVisibility
            | Self::PreferencesMenuVisibility
            | Self::ExitNodeMenuVisibility
            | Self::AutoUpdateVisibility
            | Self::SuggestedExitNodeVisibility
            | Self::OnboardingFlowVisibility => ValueType::Visibility,
            Self::AllowedSuggestedExitNodes => ValueType::StringList,
            _ => ValueType::String,
        };
        SettingDefinition::new(self, scope, value_type)
    }

    /// Finds a known key by its wire name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|key| key.wire_name() == name)
    }
}

/// Returns all built-in setting definitions in stable key order.
pub fn well_known_definitions() -> Vec<SettingDefinition> {
    PolicyKey::ALL
        .into_iter()
        .map(PolicyKey::definition)
        .collect()
}

impl fmt::Display for PolicyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

impl FromStr for PolicyKey {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_name(value).ok_or(())
    }
}

impl Serialize for PolicyKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.wire_name())
    }
}

impl<'de> Deserialize<'de> for PolicyKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        Self::from_name(&name).ok_or_else(|| D::Error::custom("unknown policy key"))
    }
}
