/// Staged candidate-config for one VRF entry.
///
/// Mirrors `BridgeConfig` / `VxlanConfig` — a `delete` flag on top of
/// the per-VRF leaves so the commit step can tell adds apart from
/// deletes. The `name` itself is the list key and lives in the
/// containing `BTreeMap`'s key, not here.
///
/// First iteration carries no payload other than `delete` because the
/// VRF schema only has the `name` key today; per-AF route-target
/// import/export is configured against the same VRF name but routed
/// through a different builder.
#[derive(Default, Debug, Clone)]
pub struct VrfConfig {
    pub delete: bool,
}
