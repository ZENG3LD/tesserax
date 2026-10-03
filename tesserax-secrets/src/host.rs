//! [`HostFactors`]: the host-identity values a seal or tripwire binds to.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::platform::{self, PlatformIdError};

/// The factors of a host fingerprint. Read from the live host with
/// [`HostFactors::read`], or supplied explicitly (tests, fixtures, a
/// deployment that derives them some other way) with [`HostFactors::new`].
///
/// Never stored in a sealed blob (only hashes of them are); zeroized on
/// drop.
///
/// # The no-DMI fallback on Linux
///
/// [`platform::product_uuid`] on Linux reads
/// `/sys/class/dmi/id/product_uuid` and, when that node is unreadable (no
/// root, a container, a hypervisor that exposes no DMI), silently returns
/// the `machine_id` instead. [`HostFactors::read`] keeps that value in the
/// product-UUID slot, so seals made on such a host keep their exact bytes
/// and keep opening, but the "reboot-stable hardware factor" is then just
/// `/etc/machine-id` a second time: a cloned image that keeps its
/// machine-id opens them, and a regenerated machine-id loses them.
/// [`HostFactors::binding_strength`] reports which case a host is in so it
/// can warn at startup; nothing about sealing changes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HostFactors {
    pub(crate) product_uuid: Option<String>,
    pub(crate) machine_id: String,
    pub(crate) primary_mac: String,
    pub(crate) uid: String,
    #[zeroize(skip)]
    binding: BindingStrength,
}

/// What the product-UUID factor of a [`HostFactors`] actually binds to.
///
/// Informational only: seals and fingerprints are computed exactly as
/// before whatever this says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BindingStrength {
    /// A hardware / hypervisor UUID independent of `machine_id` is folded
    /// in (Linux DMI, Windows `csproduct` UUID, macOS `IOPlatformUUID`).
    Dmi,
    /// No independent hardware UUID: the product UUID is absent, or (the
    /// Linux no-DMI fallback) it is the `machine_id` again. The binding is
    /// only as strong as `machine_id`, which a cloned image may share and
    /// a first boot may regenerate.
    MachineIdOnly,
}

impl BindingStrength {
    /// Strength implied by the factor values alone: [`Self::MachineIdOnly`]
    /// when there is no product UUID or it equals the machine id (trimmed,
    /// ASCII case-insensitive), [`Self::Dmi`] otherwise.
    fn from_values(product_uuid: Option<&str>, machine_id: &str) -> Self {
        match product_uuid {
            Some(u) if !u.trim().eq_ignore_ascii_case(machine_id.trim()) => Self::Dmi,
            _ => Self::MachineIdOnly,
        }
    }
}

impl HostFactors {
    /// Explicit factors. `product_uuid = None` means DMI is unavailable and
    /// only the legacy (three-factor) variant can be used.
    ///
    /// [`binding_strength`](Self::binding_strength) is judged from the
    /// values: a product UUID equal to `machine_id` (the shape the Linux
    /// no-DMI fallback produces) counts as [`BindingStrength::MachineIdOnly`].
    pub fn new(
        product_uuid: Option<String>,
        machine_id: impl Into<String>,
        primary_mac: impl Into<String>,
        uid: impl Into<String>,
    ) -> Self {
        let machine_id = machine_id.into();
        let binding = BindingStrength::from_values(product_uuid.as_deref(), &machine_id);
        Self {
            product_uuid,
            machine_id,
            primary_mac: primary_mac.into(),
            uid: uid.into(),
            binding,
        }
    }

    /// Reads the live host: `machine_id` is required; a missing MAC reads
    /// as `"no-mac"`; `uid` never fails; `product_uuid` is best-effort and,
    /// on Linux without readable DMI, is the `machine_id` again (see the
    /// type docs; [`binding_strength`](Self::binding_strength) then reports
    /// [`BindingStrength::MachineIdOnly`]).
    pub fn read() -> Result<Self, PlatformIdError> {
        let machine_id = platform::machine_id()?;
        let product_uuid = platform::product_uuid().ok();
        let binding = live_binding(product_uuid.as_deref(), &machine_id);
        Ok(Self {
            machine_id,
            primary_mac: platform::primary_mac().unwrap_or_else(|_| "no-mac".into()),
            uid: platform::uid(),
            product_uuid,
            binding,
        })
    }

    /// What the product-UUID factor binds to; a host may log a warning at
    /// startup when this is [`BindingStrength::MachineIdOnly`].
    pub fn binding_strength(&self) -> BindingStrength {
        self.binding
    }

    /// True if the DMI product UUID is known.
    pub fn has_product_uuid(&self) -> bool {
        self.product_uuid.is_some()
    }
}

impl std::fmt::Debug for HostFactors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostFactors")
            .field("has_product_uuid", &self.product_uuid.is_some())
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

/// Strength of factors read from the live host.
///
/// macOS: `machine_id` *is* `IOPlatformUUID`, a hardware id, so equal
/// values there still mean a hardware binding. Linux: DMI counts only if
/// the DMI node itself was readable (not the machine-id fallback).
/// Elsewhere: judged from the values.
fn live_binding(product_uuid: Option<&str>, machine_id: &str) -> BindingStrength {
    if cfg!(target_os = "macos") {
        return if product_uuid.is_some() {
            BindingStrength::Dmi
        } else {
            BindingStrength::MachineIdOnly
        };
    }
    #[cfg(target_os = "linux")]
    if !platform::dmi_readable() {
        return BindingStrength::MachineIdOnly;
    }
    BindingStrength::from_values(product_uuid, machine_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_product_uuid_is_dmi() {
        let f = HostFactors::new(Some("4c4c4544-0000".into()), "mid-1", "aa:bb", "1000");
        assert_eq!(f.binding_strength(), BindingStrength::Dmi);
    }

    #[test]
    fn missing_product_uuid_is_machine_id_only() {
        let f = HostFactors::new(None, "mid-1", "aa:bb", "1000");
        assert_eq!(f.binding_strength(), BindingStrength::MachineIdOnly);
    }

    #[test]
    fn linux_fallback_shape_is_machine_id_only() {
        // What product_uuid() returns on Linux without DMI: the machine id.
        let f = HostFactors::new(Some("ABCDEF01".into()), "abcdef01", "aa:bb", "1000");
        assert_eq!(f.binding_strength(), BindingStrength::MachineIdOnly);
        let g = HostFactors::new(Some(" mid-1 ".into()), "mid-1", "aa:bb", "1000");
        assert_eq!(g.binding_strength(), BindingStrength::MachineIdOnly);
    }

    #[test]
    fn strength_does_not_change_the_seal() {
        // The fallback-shaped host still seals under DmiV2 and opens; the
        // strength report is informational only.
        let weak = HostFactors::new(Some("mid-1".into()), "mid-1", "aa:bb", "1000");
        assert_eq!(weak.binding_strength(), BindingStrength::MachineIdOnly);
        let seal = crate::MachineSeal::default_label();
        let blob = seal.seal_with(&weak, b"pt").unwrap();
        assert_eq!(seal.unseal_with(&weak, &blob).unwrap(), b"pt");
        // Same bytes as a host whose DMI happens to equal that value: the
        // strength is not part of the key.
        let other = HostFactors::new(Some("mid-1".into()), "mid-1", "aa:bb", "1000");
        assert_eq!(seal.unseal_with(&other, &blob).unwrap(), b"pt");
    }

    #[test]
    fn debug_shows_strength_not_values() {
        let f = HostFactors::new(Some("secret-uuid".into()), "secret-mid", "aa:bb", "1000");
        let d = format!("{f:?}");
        assert!(d.contains("Dmi"));
        assert!(!d.contains("secret"));
    }
}
