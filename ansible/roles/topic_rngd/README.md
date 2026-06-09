<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_rngd

## Purpose

Topic role that hardens the `rngd.service` hardware-RNG entropy-gathering daemon on a Fedora 44 or later host. The role deploys four shipping artefacts: three drop-in files under `/etc/systemd/system/rngd.service.d/` (a namespace-default baseline drop-in, an isolated `NoNewPrivileges=yes` layer, and a process-internal kernel-restriction drop-in that carries the multi-stage privilege-drop carve-out — three additive `SystemCallFilter=` lines for the set-id family plus `capset`/`capget`, plus a two-line `CapabilityBoundingSet=` for the `/dev/hwrng` open and the privilege-drop permits) and one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that grants the `init_t → rngd_t : process2 nnp_transition` rule the NNP layer depends on.

The role does **not** modify `/etc/sysconfig/rngd` (the `-D daemon:daemon` privilege-drop instruction and the entropy-source disable list are operator-policy outside this role) and does not interact with the kernel `hw_random` driver layer or the `rdrand` CPU instruction availability. The full topic end-state, the verify discipline, and the three-stage rollback posture are documented in `docs/reference/topics/rngd.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_rngd_dropin_dir` | `/etc/systemd/system/rngd.service.d` | Drop-in directory for the unit. |
| `topic_rngd_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_rngd_required_packages` | `[rng-tools]` | Required package; preflight asserts presence. |
| `topic_rngd_cil_module_name` | `nnp_rngd` | CIL module name without extension. |
| `topic_rngd_cil_priority` | `400` | CIL load priority. |
| `topic_rngd_binary_path` | `/usr/bin/rngd` | Daemon binary path checked by `matchpathcon`. |
| `topic_rngd_expected_fcontext` | `rngd_exec_t` | Expected fcontext mapping for the binary; preflight fail-fasts on `bin_t`. |
| `topic_rngd_expected_selinux_domain` | `rngd_t` | Expected SELinux domain of the running daemon. |
| `topic_rngd_expected_uid` / `_gid` | `2` / `2` | Expected post-privilege-drop steady-state UID/GID. |
| `topic_rngd_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_rngd_expected_mdwe` | `yes` | Expected `MemoryDenyWriteExecute=`. |
| `topic_rngd_expected_protect_system` | `full` | Expected `ProtectSystem=`. |
| `topic_rngd_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_rngd_expected_caps_sorted` | `[cap_setgid, cap_setuid, cap_sys_admin]` | Expected `CapabilityBoundingSet=` lowercase, alphabetically sorted. |
| `topic_rngd_expected_raf_source_order` | `[AF_UNIX, AF_NETLINK]` | Expected `RestrictAddressFamilies=` source-order. |
| `topic_rngd_expected_scf_length_min` | `1500` | Conservative lower bound on resolved `SystemCallFilter=` length. |
| `topic_rngd_expected_scf_anchor_tokens` | `[setgroups, setuid, capset, epoll_wait, recvfrom]` | Substring anchors asserted in resolved `SystemCallFilter=`. |
| `topic_rngd_expected_init_source_tokens` | `[hwrng, rdrand, jitter]` | Entropy-source set; verify smoketest asserts `>= 1` initialized. |
| `topic_rngd_entropy_avail_path` | `/proc/sys/kernel/random/entropy_avail` | Kernel entropy-pool snapshot path. |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` query, the CIL install handler, the `restorecon` handler, the AVC-clean read, the SECCOMP-clean read, and the live SELinux-domain read all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean and SECCOMP-clean assertions in the role's modify stage and in `verify.sh` consume the audit pipeline that Layer 3 provisions.

## Tags

- `topic_rngd` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The three drop-ins and the CIL source are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon`, `daemon-reload`, and `restart rngd` handlers are wired through the `topic_rngd dropin changed` notification name and fire only on a drop-in file change.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the CIL module is installed before the NNP drop-in is dropped in.
- The live-state probe (MainPID read, SELinux-domain read, live UID/GID read, AVC count, SECCOMP count, post-deploy entropy_avail) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The three-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
