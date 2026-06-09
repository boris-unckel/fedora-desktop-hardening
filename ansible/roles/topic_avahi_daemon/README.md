<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_avahi_daemon

## Purpose

Topic role that hardens the multicast-DNS responder `avahi-daemon.service` on a Fedora 44 or later host. The role deploys three shipping artefacts: two drop-in files under `/etc/systemd/system/avahi-daemon.service.d/` (a topic-owned hardening drop-in that adds twenty-three directives the F44 stock vendor unit does not ship — the full `Protect*=`/`Restrict*=`/`Private*=`/`SystemCall*=`/`CapabilityBoundingSet=`/`UMask=` set documented in the topic Reference — and an isolated `NoNewPrivileges=yes` layer) and one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that grants the `init_t → avahi_t : process2 nnp_transition` rule the NNP layer depends on.

The role does **not** layer a topic-side `User=` or `Group=` directive, does **not** add `PrivateUsers=`, `DeviceAllow=`, `NoExecPaths=`, `ExecPaths=`, or any further `Restrict*=`/`Protect*=` directive beyond the twenty-three above, does **not** modify `/etc/avahi/avahi-daemon.conf` (operator-policy outside this role; the daemon-internal drop and chroot configuration is upstream-controlled), and does **not** modify `/etc/avahi/services/` (mDNS service-publishing is operator-policy). The full topic end-state, the verify discipline, the two-class mDNS smoketest, and the two-stage rollback posture are documented in `docs/reference/topics/avahi-daemon.md`.

A restart of `avahi-daemon.service` interrupts mDNS service publishing and discovery on the host; established LAN peers' caches expire over the daemon's normal TTL window after the restart, and the role's `restart avahi-daemon` handler is the documented apply path on a host where a brief mDNS interruption is acceptable, with the alternative being to apply the role and reboot.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_avahi_daemon_dropin_dir` | `/etc/systemd/system/avahi-daemon.service.d` | Drop-in directory for the unit. |
| `topic_avahi_daemon_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_avahi_daemon_required_packages` | `[avahi]` | Required package; preflight asserts presence. |
| `topic_avahi_daemon_cil_module_name` | `nnp_avahi_daemon` | CIL module name without extension. |
| `topic_avahi_daemon_cil_priority` | `400` | CIL load priority. |
| `topic_avahi_daemon_expected_selinux_domain` | `avahi_t` | Expected SELinux domain of the running daemon. |
| `topic_avahi_daemon_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_avahi_daemon_expected_protect_system` | `strict` | Expected `ProtectSystem=`. |
| `topic_avahi_daemon_expected_protect_home` | `yes` | Expected `ProtectHome=`. |
| `topic_avahi_daemon_expected_protect_kernel_tunables` | `yes` | Expected `ProtectKernelTunables=`. |
| `topic_avahi_daemon_expected_protect_kernel_modules` | `yes` | Expected `ProtectKernelModules=`. |
| `topic_avahi_daemon_expected_protect_kernel_logs` | `yes` | Expected `ProtectKernelLogs=`. |
| `topic_avahi_daemon_expected_protect_control_groups` | `yes` | Expected `ProtectControlGroups=`. |
| `topic_avahi_daemon_expected_protect_clock` | `yes` | Expected `ProtectClock=`. |
| `topic_avahi_daemon_expected_protect_hostname` | `yes` | Expected `ProtectHostname=`. |
| `topic_avahi_daemon_expected_protect_proc` | `invisible` | Expected `ProtectProc=`. |
| `topic_avahi_daemon_expected_procsubset` | `pid` | Expected `ProcSubset=`. |
| `topic_avahi_daemon_expected_private_tmp` | `yes` | Expected `PrivateTmp=`. |
| `topic_avahi_daemon_expected_private_devices` | `yes` | Expected `PrivateDevices=`. |
| `topic_avahi_daemon_expected_read_write_paths_substring` | `/run/avahi-daemon` | Expected substring in `ReadWritePaths=`. |
| `topic_avahi_daemon_expected_restrict_address_families` | `[AF_INET, AF_INET6, AF_UNIX, AF_NETLINK]` | Expected exact set in `RestrictAddressFamilies=`. |
| `topic_avahi_daemon_expected_restrict_namespaces` | `yes` | Expected `RestrictNamespaces=`. |
| `topic_avahi_daemon_expected_restrict_realtime` | `yes` | Expected `RestrictRealtime=`. |
| `topic_avahi_daemon_expected_restrict_suid_sgid` | `yes` | Expected `RestrictSUIDSGID=`. |
| `topic_avahi_daemon_expected_lock_personality` | `yes` | Expected `LockPersonality=`. |
| `topic_avahi_daemon_expected_mdwe` | `yes` | Expected `MemoryDenyWriteExecute=`. |
| `topic_avahi_daemon_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_avahi_daemon_expected_syscall_filter_substrings` | `[@system-service, chown, fchown, lchown, chroot]` | Expected substrings in `SystemCallFilter=`. |
| `topic_avahi_daemon_expected_cap_bounding_set` | `[CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_SETUID, CAP_SETGID, CAP_SYS_CHROOT]` | Expected exact set in `CapabilityBoundingSet=`. |
| `topic_avahi_daemon_expected_umask` | `0027` | Expected `UMask=` (decimal `23` accepted). |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` query, the CIL install, the `restorecon` handler, the AVC-clean read, and the live SELinux-domain read all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the role's modify stage and in `verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_avahi_daemon` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The two drop-ins and the CIL source are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon`, `daemon-reload`, and `restart avahi-daemon` handlers are wired through the `topic_avahi_daemon dropin changed` notification name and fire only on a drop-in file change.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the CIL module is installed before the NNP drop-in is dropped in.
- The live-state probe (`MainPID` read, SELinux-domain read, AVC count, post-deploy mDNS multicast-join count, post-deploy `avahi-resolve-host-name` roundtrip) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The two-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
