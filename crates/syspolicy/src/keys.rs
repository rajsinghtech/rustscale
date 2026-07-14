use std::{fmt, str::FromStr};

/// The kind of value expected for a policy key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    /// A plain string.
    String,
    /// A boolean value.
    Boolean,
    /// A list of strings.
    StringList,
    /// One of `always`, `never`, or `user-decides`.
    PreferenceOption,
    /// One of `show` or `hide`.
    Visibility,
    /// A Go `time.Duration` formatted string.
    Duration,
}

/// A known enterprise policy key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

    /// The Go-compatible name used in MDM and JSON policy files.
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

    /// The expected value type for this key.
    pub const fn value_type(self) -> ValueType {
        match self {
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
        }
    }

    /// Finds a known key by its wire name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|key| key.wire_name() == name)
    }
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
