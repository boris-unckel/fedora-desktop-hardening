<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_cups

## Purpose

Topic role that hardens the print scheduler `cups.service` on a Fedora 44 or later host. The role deploys three shipping artefacts: two drop-in files under `/etc/systemd/system/cups.service.d/` (a topic-owned hardening drop-in that adds seven directives the F44 stock vendor unit does not ship — `ProtectClock=`, `ProtectKernelLogs=`, `ProtectKernelModules=`, `ProtectControlGroups=`, `SystemCallArchitectures=native`, `MemoryDenyWriteExecute=`, `RestrictNamespaces=` — and an isolated `NoNewPrivileges=yes` layer) and one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that grants four `process2 nnp_transition` rules: the boot-time `init_t → cupsd_t` rule and three inter-domain helper-spawn rules covering `cupsd_t → cupsd_lpd_t`, `cupsd_t → cupsd_config_t`, and `cupsd_t → cups_pdf_t`.

The role does **not** layer a topic-side `User=` or `Group=` directive (cupsd's privilege model is daemon-internal and upstream-controlled), does **not** add `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `PrivateDevices=`, `RestrictAddressFamilies=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `LockPersonality=`, `SystemCallFilter=`, `CapabilityBoundingSet=`, `UMask=`, `ProtectKernelTunables=`, `ProtectHostname=`, `ProtectProc=`, `ProcSubset=`, or `ReadWritePaths=`, does **not** modify `/etc/cups/cupsd.conf` (operator-policy outside this role; the daemon's listen and access configuration is upstream-controlled), and does **not** modify `/etc/cups/cups-files.conf`, `/etc/cups/printers.conf`, or `/etc/cups/classes.conf`. The full topic end-state, the verify discipline, the three drift-class print smoketests, and the two-stage rollback posture are documented in `docs/reference/topics/cups.md`.

A restart of `cups.service` interrupts in-flight print jobs and printer-discovery on the host; queued jobs survive the restart in the spool, but jobs in active transmission to a printer are aborted and must be re-submitted, and the role's `restart cups` handler is the documented apply path on a host where a brief interruption of active print transmission is acceptable, with the alternative being to apply the role and reboot.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_cups_dropin_dir` | `/etc/systemd/system/cups.service.d` | Drop-in directory for the unit. |
| `topic_cups_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_cups_required_packages` | `[cups]` | Required package; preflight asserts presence. |
| `topic_cups_cil_module_name` | `nnp_cups` | CIL module name without extension. |
| `topic_cups_cil_priority` | `400` | CIL load priority. |
| `topic_cups_expected_selinux_domain` | `cupsd_t` | Expected SELinux domain of the running daemon. |
| `topic_cups_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_cups_expected_protect_clock` | `yes` | Expected `ProtectClock=`. |
| `topic_cups_expected_protect_kernel_logs` | `yes` | Expected `ProtectKernelLogs=`. |
| `topic_cups_expected_protect_kernel_modules` | `yes` | Expected `ProtectKernelModules=`. |
| `topic_cups_expected_protect_control_groups` | `yes` | Expected `ProtectControlGroups=`. |
| `topic_cups_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_cups_expected_mdwe` | `yes` | Expected `MemoryDenyWriteExecute=`. |
| `topic_cups_expected_restrict_namespaces` | `yes` | Expected `RestrictNamespaces=`. |
| `topic_cups_helper_subdomains` | `[cupsd_lpd_t, cupsd_config_t, cups_pdf_t]` | Helper subdomains the CIL module covers under the inter-domain `nnp_transition` class. |
| `topic_cups_expected_listen_substrings` | `[127.0.0.1:631, [::1]:631]` | Substrings either of which must appear in `ss -ltn 'sport = 631'` output. |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` queries (main domain plus three helper subdomains), the CIL install, the `restorecon` handler, the AVC-clean read, the live SELinux-domain read, and the four positive-rule presence checks in `verify.sh` all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the role's modify stage and in `verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_cups` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The two drop-ins and the CIL source are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon`, `daemon-reload`, and `restart cups` handlers are wired through the `topic_cups dropin changed` notification name and fire only on a drop-in file change.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the CIL module is installed before the NNP drop-in is dropped in.
- The live-state probe (`MainPID` read, SELinux-domain read, AVC count, post-deploy `lpstat`/`ss`/`lpinfo` snapshots) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The two-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
