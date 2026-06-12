# Delta run — topic_flatpak_kfd_device (plus sibling re-confirmation)

A scoped component-tier run for one new topic, not a full fan-out. Scope: the
foundation substrate (the shared prepare: staff_u mapping, sudo umask, enforcing
reboot, the four foundation roles) plus the new `topic_flatpak_kfd_device`, with
`topic_flatpak_audio_sandbox` re-run as the structural sibling of the same bug
class to confirm its carried green against the current tree.

The infrastructure was re-bootstrapped from an empty provider project
(`bootstrap_infra.sh`, `bake_base_snapshot.sh`; base image id 396701135) and was
fully torn down after the run on operator request (`teardown.sh`; the provider
project verified empty).

## Matrix

| Topic | Result |
|---|---|
| `topic_flatpak_kfd_device` | PASS (create, prepare, converge, idempotence, verify staff_t + sysadm_t, destroy) |
| `topic_flatpak_audio_sandbox` | PASS (carried green re-confirmed) |

## Observations — topic_flatpak_kfd_device on a cloud node

The cloud node (cpx21, no AMD GPU) exercises the node-absent branch by design:

- Preflight reported the `/dev/kfd`-absent informational note and applied the
  CIL module pre-emptively; the post-load `sesearch` assertion confirmed the
  allow surface.
- Verify, `staff_t` pass: package checks OK; policy-store checks SKIP (needs
  `sysadm_t`); `kfd_stat_from_staff_t` SKIP with the `/dev/kfd not present`
  disposition — the ENOENT-vs-EACCES discrimination on the `LC_ALL=C stat`
  error text resolved correctly on a node without the device node.
- Verify, `sysadm_t` pass: `module_installed` OK, `rule_present` OK
  (`staff_t × hsa_device_t : chr_file getattr`); `kfd_stat_from_staff_t` SKIP
  (`needs staff_t` — a `sysadm_t` read proves nothing).
- Idempotence: successful (the converge re-run reported zero changes).

The functional-positive branch (an existing `/dev/kfd`, the `stat` succeeding
from `staff_t` only with the module loaded, and a `dri`-holding Flatpak
application launching) is not reachable on cloud hardware; it is covered by the
HW-gap classification and was confirmed on real AMD hardware out of band.
