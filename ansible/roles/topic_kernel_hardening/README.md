<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_kernel_hardening

## Purpose

Topic role that configures host-global kernel, module, bootloader, and core-dump policy on a Fedora 44 or later host. The role deploys five shipping artefacts: a sysctl drop-in at `/etc/sysctl.d/99-hardening.conf`, a modprobe drop-in at `/etc/modprobe.d/hardening.conf`, a PAM-limits drop-in at `/etc/security/limits.d/90-nocore.conf`, a systemd-coredump drop-in at `/etc/systemd/coredump.conf.d/disable.conf`, and a bootloader argument set applied via `grubby --update-kernel=ALL --args="…"` and persisted in the BLS entries under `/boot/loader/entries/`. The role owns no systemd service unit and ships no SELinux CIL module.

The bootloader argument set is activated only by reboot; the role applies the argument set, prompts the operator with a `pause:` task that displays the byte-exact reboot rationale, and continues only after operator confirmation. Apply-on-running-kernel is structurally unavailable for the bootloader argument subset.

The role does **not** configure `kernel.modules_disabled=1` (deliberately excluded — would break runtime module hot-plug, GPU-driver reload, and `akmods` rebuild), `kernel.unprivileged_bpf_disabled=1` (Fedora 44 already ships `=2` by upstream default), `kernel.unprivileged_userns_clone` (does not exist on F44 kernels), the kernel `lockdown=` mode (operator-policy bound to Secure Boot posture), USB-storage module blacklisting (operator-policy bound to host hardware), or the firmware-side IOMMU enable flags (BIOS- and microarchitecture-bound). The full topic end-state, the verify discipline, and the single-stage rollback posture are documented in `docs/reference/topics/kernel-hardening.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_kernel_hardening_sysctl_dir` | `/etc/sysctl.d` | Sysctl drop-in directory. |
| `topic_kernel_hardening_modprobe_dir` | `/etc/modprobe.d` | Modprobe drop-in directory. |
| `topic_kernel_hardening_limits_dir` | `/etc/security/limits.d` | PAM-limits drop-in directory. |
| `topic_kernel_hardening_coredump_dir` | `/etc/systemd/coredump.conf.d` | Systemd-coredump drop-in directory. |
| `topic_kernel_hardening_strict_interfaces` | `[]` | Operator-populated list of interfaces that need a per-interface strict-mode + martian-logging stanza appended to `99-hardening.conf`. The `all`/`default` tables are not sufficient on existing interfaces because the kernel evaluates `rp_filter` as `max(all, iface)` and `log_martians` is per-interface only. |
| `topic_kernel_hardening_cmdline_args` | `slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on` | Bootloader argument set applied via `grubby --update-kernel=ALL --args`. |
| `topic_kernel_hardening_expected_cmdline_substrings` | five-element list | Substrings asserted in `/proc/cmdline` and `grubby --info=ALL`. |
| `topic_kernel_hardening_blacklisted_modules` | thirteen-element list | Modules neutralised by `install <mod> /bin/true` in `hardening.conf`. |
| `topic_kernel_hardening_expected_sysctl_keys` | nineteen key/value pairs | Sysctl Soll values asserted by `verify.sh`. |
| `topic_kernel_hardening_selinux_restricted_keys` | five-element list | Sysctl keys that are SELinux-restricted on read; per-key readback uses the role-switched form, and `staff_t` invocations report `SKIP`. |
| `topic_kernel_hardening_expected_file_modes` | four-entry mapping | Mode/owner/group/seltype per shipping artefact. |
| `topic_kernel_hardening_expected_nocore_hard` | `0` | `RLIMIT_CORE` hard cap asserted in `90-nocore.conf`. |
| `topic_kernel_hardening_expected_nocore_soft` | `0` | `RLIMIT_CORE` soft cap asserted in `90-nocore.conf`. |
| `topic_kernel_hardening_expected_coredump_storage` | `none` | `Storage=` asserted in merged `coredump.conf`. |
| `topic_kernel_hardening_expected_coredump_processsizemax` | `0` | `ProcessSizeMax=` asserted in merged `coredump.conf`. |
| `topic_kernel_hardening_expected_ulimit_core` | `0` | `ulimit -c` asserted from a fresh login shell. |

The byte-exact bodies of `99-hardening.conf`, `hardening.conf`, `90-nocore.conf`, and `disable.conf` are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under host-global `/etc/` directories. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1 — **structural**) — the four shipping configuration directories carry SELinux dir-types whose stock targeted-policy permissions deny `add_name`/`write` from the `staff_sudo_t` source domain, and five of the configured sysctl keys are SELinux-restricted at the runtime apply path. Every drop-in push, every `sysctl --system` invocation, every `grubby` invocation, and every `systemctl daemon-reload` invocation transit through `sudo -r sysadm_r -t sysadm_t`. Plain `sudo` (without the `-r sysadm_r -t sysadm_t` flag pair) fails on directory write, and the per-key sysctl apply fails silently on the SELinux-restricted subset.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the verify discipline targets `sysctl_t` and `modules_conf_t` against `staff_sudo_t` source-domain hits — the canonical signal that an operator attempted a topic-side write or apply step from plain `sudo` instead of the role-switched form.

The role ships **no** CIL module and has **no** dependency on `foundation_selinux_cil_bootstrap`. Presence of `foundation_selinux_cil_bootstrap` in `meta/main.yml` would itself be drift against the published end-state.

## Tags

- `topic_kernel_hardening` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, sysctl reload, daemon-reload, restorecon, grubby cmdline apply, reboot prompt.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The four configuration drop-ins are pushed verbatim from `files/`.
- The `apply sysctl` handler fires only on a change to `99-hardening.conf` (or to the per-interface block when `topic_kernel_hardening_strict_interfaces` is non-empty).
- The `daemon-reload coredump` handler fires only on a change to `disable.conf`.
- The `restorecon kernel-hardening` handler fires on any drop-in change and is a no-op on a correctly installed file.
- The `grubby --update-kernel=ALL --args` apply is gated on a `changed_when:` shape that returns `changed=False` when every expected substring is already present in `/proc/cmdline`. Unconditional re-apply on every Ansible run is drift; the gate is the idempotence enforcement.
- The bootloader argument set is activated only by reboot. The role's final `pause:` task displays the byte-exact reboot rationale; the operator confirms by pressing ENTER (verify will report the cmdline-related checks as drift until reboot) or interrupts the play to reboot before verification.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. Drift detected by verify is reported, not silently corrected. The single-stage rollback sequence is operator-driven and documented in the topic Reference.
- On a correctly applied host that has been rebooted after deploy, `--check` reports zero changes. Stated as a claim, not a guarantee.
