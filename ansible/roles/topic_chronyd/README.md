<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_chronyd

## Purpose

Topic role that hardens the `chronyd.service` NTS-client time daemon on a Fedora 44 or later host. The role deploys three shipping artefacts: two drop-in files under `/etc/systemd/system/chronyd.service.d/` (a topic-owned hardening drop-in that adds the four directives the F44 stock vendor unit does not already ship — capability bounding-set reduction for the four `CAP_NET_*` capabilities, `ProcSubset=pid`, `UMask=0027`, `SystemCallArchitectures=native` — and an isolated `NoNewPrivileges=yes` layer) and one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that grants the `init_t → chronyd_t : process2 nnp_transition` rule the NNP layer depends on.

The role does **not** layer a topic-side `SystemCallFilter=`, `MemoryDenyWriteExecute=`, `RestrictAddressFamilies=`, `RestrictNamespaces=`, `LockPersonality=`, `Protect*=`, `Private*=`, or `DeviceAllow=` directive: the F44 stock vendor unit is best-in-class hardened and already carries the broader sandbox layer. The role does not modify `/etc/sysconfig/chronyd` (the chrony-internal seccomp filter is upstream-managed operator-policy outside this role) and does not interact with `/etc/chrony.conf` content (the NTS-client-only assumption is a boundary marker, not a configuration target). The full topic end-state, the verify discipline, and the two-stage rollback posture are documented in `docs/reference/topics/chronyd.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_chronyd_dropin_dir` | `/etc/systemd/system/chronyd.service.d` | Drop-in directory for the unit. |
| `topic_chronyd_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_chronyd_required_packages` | `[chrony]` | Required package; preflight asserts presence. |
| `topic_chronyd_expected_forbidden_caps` | `[cap_net_admin, cap_net_bind_service, cap_net_broadcast, cap_net_raw]` | Capabilities asserted as absent in the resolved `CapabilityBoundingSet=`. |
| `topic_chronyd_expected_selinux_domain` | `chronyd_t` | Expected SELinux domain of the running daemon. |
| `topic_chronyd_expected_procsubset` | `pid` | Expected `ProcSubset=`. |
| `topic_chronyd_expected_umask` | `0027` | Expected `UMask=` (verify normalises decimal `23` form to octal). |
| `topic_chronyd_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_chronyd_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_chronyd_cil_module_name` | `nnp_chronyd` | CIL module name without extension. |
| `topic_chronyd_cil_priority` | `400` | CIL load priority. |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` query, the CIL install, the `restorecon` handler, the AVC-clean read, and the live SELinux-domain read all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the role's modify stage and in `verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_chronyd` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The two drop-ins and the CIL source are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon`, `daemon-reload`, and `restart chronyd` handlers are wired through the `topic_chronyd dropin changed` notification name and fire only on a drop-in file change.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the CIL module is installed before the NNP drop-in is dropped in.
- The live-state probe (`MainPID` read, SELinux-domain read, AVC count, post-deploy `chronyc tracking`, post-deploy port-123-bind state) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The two-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
