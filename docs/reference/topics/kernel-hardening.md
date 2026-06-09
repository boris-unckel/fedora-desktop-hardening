<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Kernel hardening

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

kernel-hardening configures host-global kernel, module, bootloader, and core-dump policy through static configuration drop-ins and a bootloader argument set; the topic owns no systemd service unit and ships no SELinux CIL module.

The end-state ships five artefacts on a Fedora 44 or later host: a sysctl drop-in at `/etc/sysctl.d/99-hardening.conf` for kernel- and network-stack tunables, a modprobe drop-in at `/etc/modprobe.d/hardening.conf` for the `install <mod> /bin/true` neutralisation of low-utility kernel modules, a PAM-limits drop-in at `/etc/security/limits.d/90-nocore.conf` for the per-process core-dump rlimit, a systemd-coredump drop-in at `/etc/systemd/coredump.conf.d/disable.conf` for system-wide core-dump discard, and a bootloader argument set applied via `grubby --update-kernel=ALL --args="…"` and persisted in the BLS entries under `/boot/loader/entries/`. The topic also ships the apply discipline (which artefacts take effect immediately, which require reboot, which require new login), the verify discipline (per-key sysctl readback, per-module `lsmod` absence, `/proc/cmdline` substring match, merged `coredump.conf` assertion, PAM-limit `ulimit -c` assertion), the per-interface caveat for the network-stack subset, and the single-stage rollback posture.

This topic does **not** cover the operator-policy choice of `kernel.modules_disabled=1` (deliberately excluded — would freeze the running kernel's module table and break GPU-driver reload, hot-plug device-class kernel-module load, and `akmods` rebuild), the operator-policy choice of `kernel.unprivileged_bpf_disabled=1` (Fedora 44 already ships `=2` upstream, which is stricter), the `kernel.unprivileged_userns_clone` sysctl (does not exist on Fedora 44 kernels — removed upstream as a build-time constant rather than a runtime tunable), the kernel `lockdown=` mode (operator-policy bound to Secure Boot posture), USB-storage module blacklisting (operator-policy bound to whether the host has a USB Card Reader or other unavoidable USB-storage class device), the firmware-side IOMMU enable flags (BIOS- and microarchitecture-bound), per-host network-interface override files for arbitrary interface naming (templated by the role variable `topic_kernel_hardening_strict_interfaces`, not part of the byte-exact `99-hardening.conf` body), or any further bootloader argument beyond the five-flag set documented under §"Bootloader argument set".

## End-state configuration

The role pushes four configuration drop-ins to host-global locations and applies one bootloader argument set via `grubby`. The drop-ins each carry their own SELinux dir-type (`system_conf_t`, `modules_conf_t`, the canonical configuration types for `/etc/security/limits.d/` and `/etc/systemd/coredump.conf.d/`), and each is written with mode `0644 root:root`. The bootloader argument set has no on-disk artefact under role control; `grubby` modifies the package-managed BLS entries in place.

### `/etc/sysctl.d/99-hardening.conf`

End-state body:

```ini
# Kernel address-space and trace surface
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1
kernel.sysrq = 0

# Network stack — anti-spoofing and ICMP-redirect surface
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Filesystem and core-dump surface
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2

# TTY line-discipline auto-load
dev.tty.ldisc_autoload = 0

# BPF JIT constant-blinding (anti JIT-spraying)
net.core.bpf_jit_harden = 2
```

The five comment headers in the body partition the keys into five effect-class groups; the role's `files/99-hardening.conf` artefact carries the headers verbatim so a `cat` of the deployed file reads as a single self-explanatory document.

The kernel-surface group restricts the disclosure surface of in-kernel addresses and traceability. `kernel.kptr_restrict=2` redacts kernel-pointer values in `/proc` reads regardless of the reading process's capability set, which removes the trivial KASLR-defeat primitive `cat /proc/kallsyms`. `kernel.dmesg_restrict=1` makes the kernel ring buffer privileged-only, which removes the kernel-log read primitive used by exploits to grep for kernel addresses or boot-time secrets. `kernel.yama.ptrace_scope=1` restricts `ptrace(2)` to direct child processes, which prevents an attacker-controlled unprivileged process from attaching to a sibling process under the same user to exfiltrate memory. `kernel.kexec_load_disabled=1` permanently disables `kexec_load(2)`/`kexec_file_load(2)` for the lifetime of the running kernel, which removes the kernel-replacement primitive an attacker would otherwise use to bypass Secure Boot or Lockdown. `kernel.sysrq=0` disables the magic-SysRq key combinations entirely, which removes a local-keyboard escalation surface on a desktop host.

The network-stack group reduces the IP-stack's trust in untrusted-side packet contents. The `rp_filter=1` setting on the `all` and `default` tables enables strict reverse-path filtering, which causes the kernel to drop packets whose source address is not reachable through the inbound interface (a baseline anti-spoofing measure on a single-homed host). Disabling `accept_redirects` on both IPv4 and IPv6, on both the `all` and `default` tables, prevents an attacker on the local segment from injecting ICMP-redirect routes into the kernel's routing cache. Disabling `send_redirects` removes the host's ability to advertise alternative routes to its neighbours, which a desktop host has no legitimate reason to do. Enabling `log_martians` causes the kernel to log packets whose source address contradicts the routing table, which surfaces accidental misconfigurations and active spoofing attempts in the kernel ring buffer.

The filesystem and core-dump group hardens two pre-execve filesystem behaviours and one core-dump policy bit. `fs.suid_dumpable=0` disables core-dump generation for SUID and SGID processes entirely, which closes a credential-exfiltration path through a coredump triggered against a privileged binary. `fs.protected_fifos=2` and `fs.protected_regular=2` block FIFO and regular-file follow-through `open(2)` in world-writable sticky directories (`/tmp`, `/var/tmp`) when the file is owned by neither the opener nor the directory owner, which closes a class of symlink-style swap attacks against shared-tmp consumers.

The TTY group disables an obscure auto-loading path. `dev.tty.ldisc_autoload=0` requires `CAP_SYS_MODULE` for an unprivileged process to trigger the load of an arbitrary line-discipline kernel module via the `TIOCSETD` ioctl, which removes a documented local-attack surface against drivers shipped but not loaded by default.

The BPF JIT group enables constant-blinding in the BPF JIT compiler. `net.core.bpf_jit_harden=2` rewrites BPF program constants at JIT time so an attacker cannot embed a chosen byte sequence in the JIT-emitted code, which raises the cost of JIT-spraying primitives that target the BPF JIT's executable mappings.

**Per-interface caveat.** `net.ipv4.conf.all.rp_filter` and `net.ipv4.conf.default.rp_filter` do not on their own enforce strict reverse-path filtering on existing interfaces: the kernel evaluates `max(all, <iface>)`, so an interface with a sysctl-table value of `2` (loose mode) overrides the `all`-table value of `1` (strict mode) and the effective per-interface mode is loose. `net.ipv4.conf.all.log_martians = 1` does not on its own enable martian logging on existing interfaces because the key is per-interface only. `net.ipv4.conf.all.accept_redirects = 0` and `net.ipv4.conf.all.send_redirects = 0` are evaluated as logical AND between the `all`-table and the per-interface tables, so the `all`-table value of `0` is sufficient to deny the redirect operation regardless of the per-interface table. To enforce strict mode and martian-logging on a host's existing interfaces the role's modify stage emits a per-interface stanza for every operator-named interface in the role variable `topic_kernel_hardening_strict_interfaces`; the default is the empty list, in which case no per-interface stanza is emitted and only the `all`/`default` tables are configured.

**Out-of-scope sysctl keys.** `kernel.modules_disabled=1` is **not** configured: enabling the key freezes the running kernel's module table and prevents subsequent `modprobe`, `rmmod`, or `dracut --regenerate-all` invocations, which breaks GPU-driver reload, hot-plug device-class kernel-module load, and per-kernel `akmods` rebuild — the topic does not validate the host's runtime workload against these constraints. `kernel.unprivileged_bpf_disabled=1` is **not** configured because Fedora 44 ships `=2` (stricter than `=1`) by upstream default; the topic relies on the upstream baseline rather than restating it. `kernel.unprivileged_userns_clone` is **not** configured because the runtime sysctl does not exist on Fedora 44 kernels (removed upstream as a build-time constant rather than a runtime tunable). USB-storage module blacklisting via `install usb-storage /bin/true` in the modprobe drop-in is **not** part of the topic — operator hosts with USB Card Readers, external storage, or USB-installer-creation workflows would lose those classes, and the topic does not validate the host's runtime workload against these constraints.

### `/etc/modprobe.d/hardening.conf`

End-state body:

```text
# Filesystems with low utility and historic CVE surface (CIS profile)
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true

# Network protocols not used on a desktop host
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true

# FireWire — DMA attack surface; no FireWire hardware on the host
install firewire-core /bin/true
install firewire-ohci /bin/true
install firewire-sbp2 /bin/true
```

The drop-in uses the `install <mod> /bin/true` directive, not `blacklist <mod>`. The `blacklist` directive prevents only kernel-side autoload (modalias-driven probe at hardware-discovery time); an explicit `modprobe <mod>` invocation by an operator or unprivileged process bypasses the blacklist. The `install <mod> /bin/true` form replaces the module's load command with the no-op `/bin/true`, which makes both autoload and explicit invocation succeed silently without inserting the module — `modprobe <mod>` returns exit `0`, but `lsmod | grep <mod>` remains empty.

The thirteen modules cover three classes. The first six are filesystems with historic CVE surface and minimal real-world utility on a Fedora desktop (the CIS-profile baseline list). The next four are network protocols (DCCP, SCTP, RDS, TIPC) not used by a desktop networking stack. The last three are the FireWire stack; FireWire's controller-side DMA exposure was historically a direct-memory-attack vector against unencrypted physical-memory address ranges, and the topic disables the stack on hosts without FireWire hardware. The role does not ship a fourth class (USB-storage, Bluetooth, NFC, etc.); see the out-of-scope sysctl keys paragraph above for the USB-storage rationale.

`install <mod> /bin/true` rules block subsequent autoload and `modprobe` invocations only; modules that were already loaded into the running kernel at apply time remain loaded until the next reboot, until an explicit `rmmod` invocation, or until the operator runs `dracut --force` and reboots.

### Bootloader argument set

End-state argument set, applied via:

```bash
sudo -r sysadm_r -t sysadm_t grubby --update-kernel=ALL \
  --args="slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on"
```

The five flags target the kernel's slab allocator, page allocator, and per-syscall stack. `slab_nomerge` keeps slab caches with the same object size in separate caches rather than merging them, which raises the cost of cross-cache type-confusion exploits. `init_on_alloc=1` zeroes pages on allocation, which kills uninitialised-memory-disclosure classes. `init_on_free=1` zeroes pages on free, which kills use-after-free read-disclosure classes. `page_alloc.shuffle=1` randomises the page-allocator free-list order, which raises the cost of heap-spraying primitives. `randomize_kstack_offset=on` randomises the per-syscall kernel-stack offset by a small amount, which raises the cost of stack-based ROP and kernel-payload primitives.

The role applies the argument set to **all** installed kernel BLS entries (`grubby --update-kernel=ALL`), which both modifies every existing entry under `/boot/loader/entries/` in place and updates the BLS-template default for newly-installed kernels. The verify discipline asserts the substring presence in `/proc/cmdline` for the running kernel and asserts the substring presence in `grubby --info=ALL` output for every installed kernel entry. A new kernel installed by `dnf upgrade` after the role is applied inherits the argument set from the BLS template; no per-upgrade re-apply is required. The `memtest86+x64.efi` entry and the rescue-kernel entry receive the argument set in the `grubby --info=ALL` output but are not Linux-kernel boot paths in the same sense (the rescue entry does honour the arguments at boot; the memtest entry ignores Linux kernel arguments entirely).

### Core-dump disable — two-file artefact set

Core dumps disclose process heap content (passwords, keys, tokens) into operator-readable storage. The topic disables core-dump persistence at three layers: a sysctl key (`fs.suid_dumpable=0`, part of `99-hardening.conf` above), a PAM-limits drop-in, and a systemd-coredump drop-in.

`/etc/security/limits.d/90-nocore.conf`:

```text
*               hard    core            0
*               soft    core            0
```

The PAM-limits drop-in zeroes the per-process core-dump rlimit (`RLIMIT_CORE`) for every user at next login. PAM-limits apply at session establishment (the PAM stack pulls them via `pam_limits.so`); existing logged-in sessions retain whatever rlimit they were created with. A reboot resets every session and is the authoritative apply path.

`/etc/systemd/coredump.conf.d/disable.conf`:

```ini
[Coredump]
Storage=none
ProcessSizeMax=0
```

The systemd-coredump drop-in disables the on-disk coredump persistence path. `Storage=none` discards every received core stream rather than writing it under `/var/lib/systemd/coredump/`, and `ProcessSizeMax=0` caps the maximum dumpable size to zero so even the in-flight piped delivery to `systemd-coredump@.service` produces no payload. The drop-in takes effect after `systemctl daemon-reload`; existing in-flight coredumps captured before the reload would still land on disk under the old policy, but the boot-time apply makes the new policy authoritative across the whole runtime after the next reboot.

The merged effective policy is verified via:

```bash
sudo -r sysadm_r -t sysadm_t systemd-analyze cat-config systemd/coredump.conf
```

The merged output must contain `Storage=none` and `ProcessSizeMax=0` with the topic-owned drop-in as the latest source.

### File modes

All four shipping configuration files are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK; the explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md). The bootloader argument set has no on-disk artefact under role control — the `grubby` invocation modifies `/boot/loader/entries/<machine-id>-<kernel>.conf` files that are package-managed by `kernel-core` and therefore mode/ownership-managed by the package. The role's preflight stage runs `matchpathcon` against each shipping path and asserts the result resolves to the expected SELinux type as a fail-fast gate before the install task runs. A `restorecon` handler is wired as defence-in-depth; it fires on file change but is a no-op on a correctly installed file.

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/sysctl.d/99-hardening.conf` | `0644` | `root:root` | `system_conf_t` |
| `/etc/modprobe.d/hardening.conf` | `0644` | `root:root` | `modules_conf_t` |
| `/etc/security/limits.d/90-nocore.conf` | `0644` | `root:root` | `etc_t` |
| `/etc/systemd/coredump.conf.d/disable.conf` | `0644` | `root:root` | `systemd_conf_t` |
| (BLS bootloader entries — package-managed) | `0600` | `root:root` | `boot_t` |

### Apply discipline

The five artefacts have heterogeneous apply semantics. The table below names the apply path and the time at which each artefact takes effect.

| Artefact | Apply path | Takes effect |
|---|---|---|
| `/etc/sysctl.d/99-hardening.conf` | `sudo -r sysadm_r -t sysadm_t sysctl --system` (interactive) and `systemd-sysctl.service` (boot) | Immediately after the interactive apply for the non-restricted keys; restricted keys (see below) require the role-switched apply path. Persists across reboot via the boot-time apply. |
| `/etc/modprobe.d/hardening.conf` | Read by `modprobe` and the kernel autoload path on every invocation | Immediately for subsequent `modprobe` invocations and autoload events. Modules already loaded at apply time persist until reboot or explicit `rmmod`. |
| `/etc/security/limits.d/90-nocore.conf` | Read by `pam_limits.so` at session establishment | At next login for new sessions. Existing sessions retain their original rlimit until logout. Reboot is the authoritative apply path. |
| `/etc/systemd/coredump.conf.d/disable.conf` | `systemctl daemon-reload` after install | After the daemon-reload for new core captures; in-flight captures during the reload window may still land on disk under the old policy. Reboot is the authoritative apply path. |
| Bootloader argument set | `grubby --update-kernel=ALL --args="…"` | At next reboot. The currently-running kernel does not pick up the changed cmdline. |

Three of the five artefacts (sysctl drop-in, PAM-limits drop-in, coredump drop-in) take effect at apply time for new operations and at reboot for full system coverage. The modprobe drop-in takes effect immediately for new module-load attempts; modules loaded into the running kernel at apply time persist until reboot. The bootloader argument set takes effect only at the next reboot. A reboot is therefore the authoritative apply path for this topic; the role's `tasks/main.yml` ends with an Ansible `pause:` task that prompts the operator for a reboot, with text matching the byte-exact apply-path caveat below.

The four shipping configuration directories (`/etc/sysctl.d/`, `/etc/modprobe.d/`, `/etc/security/limits.d/`, `/etc/systemd/coredump.conf.d/`) carry SELinux dir-types whose stock targeted-policy permissions deny `add_name`/`write` from the `staff_sudo_t` source domain. Plain `sudo cp -a …` and `sudo tee … > /etc/<dir>/<file>` fail with `Permission denied` at directory level, before any file-level mode or UMASK consideration applies. Five of the sysctl keys this topic configures (`kernel.kptr_restrict`, `net.core.bpf_jit_harden`, `fs.protected_fifos`, `fs.protected_regular`, `dev.tty.ldisc_autoload`) are SELinux-restricted at the runtime apply path: interactive `sudo sysctl --system` from `staff_sudo_t` reports `permission denied on key …` for each restricted key while leaving the running-kernel value unchanged. The boot-time apply via `systemd-sysctl.service` is unaffected because `systemd-sysctl.service` runs under `init_t`. The interactive apply path therefore requires the `sudo -r sysadm_r -t sysadm_t` role-switch documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md) for both the file-write step and the `sysctl --system` reload step; `grubby --update-kernel=ALL` follows the same role-switch reflex for symmetry even though `grubby` itself only requires `CAP_SYS_ADMIN`.

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_kernel_hardening/files/probe.sh
```

The probe reports state without judging it. It enumerates the byte-exact bodies of the four shipping configuration files (one `cat` per file for diff against the role's expected form), the running-kernel `cat /proc/cmdline` (substring match against the five-flag set), the per-BLS-entry argument set via `sudo -r sysadm_r -t sysadm_t grubby --info=ALL` (`sysadm_t`-gated; `SKIP` from `staff_t`), the per-key sysctl readback via `sudo -r sysadm_r -t sysadm_t sysctl <key>` for each of the nineteen keys (one call per key — five of the keys are SELinux-restricted on read and report `SKIP needs sysadm_t` from `staff_t`, the remaining fourteen read directly), `lsmod | grep <module>` for each of the thirteen blacklisted modules (presence is drift), `systemd-analyze cat-config systemd/coredump.conf` (informational; merged-output dump), `ulimit -c` for the current shell (PAM-limits effect on the current login session), `stat -c '%n %a %U %G %C' <path>` for each of the four shipping artefacts, and `matchpathcon <path>` for each of the four shipping artefacts. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_kernel_hardening/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| Per-key sysctl readback | nineteen key/value pairs matching the byte-exact `99-hardening.conf` body; five SELinux-restricted keys (`kernel.kptr_restrict`, `net.core.bpf_jit_harden`, `fs.protected_fifos`, `fs.protected_regular`, `dev.tty.ldisc_autoload`) read via `sudo -r sysadm_r -t sysadm_t sysctl <key>` (the role-switched form is the canonical readback path because the keys are SELinux-restricted on read as well as on write). From a `staff_t` shell, the five restricted keys report `SKIP needs sysadm_t` and the remaining fourteen read directly. |
| `lsmod` blacklisted-module absence | thirteen module names absent from the running-kernel module list; presence of any one is drift. |
| `/proc/cmdline` substring match | five substrings matching the byte-exact bootloader argument set; absence of any one is drift. |
| `grubby --info=ALL` substring match | each substring present on every Linux-kernel BLS entry; `sysadm_t`-gated, `SKIP` from `staff_t`. |
| `90-nocore.conf` body | two lines matching `^\*\s+(hard\|soft)\s+core\s+0\s*$`; both lines required. |
| `coredump.conf` merged effective | `Storage=none` and `ProcessSizeMax=0` in the merged output of `systemd-analyze cat-config systemd/coredump.conf`. |
| `ulimit -c` | `0` from a fresh login shell (the verify script does not assert against the current invoking shell because PAM-limits applied at session establishment, not at sysctl-style runtime apply). |
| File modes | four `<path>:0644:root:root:<seltype>` triplets matching the table under §"File modes". |

The verify script does **not** assert `EXPECTED_NNP`, `EXPECTED_PROTECT_*`, `EXPECTED_PRIVATE_*`, `EXPECTED_RESTRICT_*`, `EXPECTED_LOCK_PERSONALITY`, `EXPECTED_MDWE`, `EXPECTED_SYSCALL_FILTER_*`, `EXPECTED_CAP_BOUNDING_SET`, `EXPECTED_RESTRICT_ADDRESS_FAMILIES`, `EXPECTED_MAIN_PID`, `EXPECTED_DOMAIN`, or `EXPECTED_TIMER_*` keys — kernel-hardening owns no service unit, so none of these directive families apply. There is no liveness check (no `[ -d /proc/$pid ]`, no `kill -0`, no `MainPID` assertion). There is no `EXPECTED_CIL_MODULE`, `EXPECTED_CIL_ALLOW_RULES`, or `sesearch` rule-presence assertion — the role ships no CIL module. Presence of any of these `EXPECTED_*` constants in `verify.sh` is drift against the present end-state.

### AVC posture

On a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(sysctl_t|modules_conf_t|coredump_etc_t)' \
  | grep -E 'staff_sudo_t|staff_t'
```

The verify script runs this filter and treats any hit as drift. The filter targets the canonical signal that an operator attempted a topic-side write or apply step from plain `sudo` instead of the role-switched form. The four-tool diagnosis loop that operators use when an AVC hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

### Functional smoketest

The post-deploy smoketest exercises one path per artefact:

```bash
sudo -r sysadm_r -t sysadm_t sysctl --system
sudo modprobe dccp && lsmod | grep -w '^dccp'
cat /proc/cmdline
bash -lc 'ulimit -c'
sudo -r sysadm_r -t sysadm_t systemd-analyze cat-config systemd/coredump.conf
```

`sysctl --system` returns exit `0` with no `permission denied` in stderr. `modprobe dccp` returns exit `0`; `lsmod | grep -w '^dccp'` is empty (the `install /bin/true` rule consumed the invocation without inserting the module). `cat /proc/cmdline` contains `slab_nomerge` and `init_on_alloc=1`. `bash -lc 'ulimit -c'` from a fresh login shell returns `0` (PAM-limits applied at session establishment). The merged `coredump.conf` dump contains `Storage=none` and `ProcessSizeMax=0`. The smoketest is functional, not a hardening assertion; it catches regressions where one of the five artefacts would silently fail to apply (the canonical case is a directory-write `Permission denied` from `staff_sudo_t` that the operator missed in the install logs, leaving the file on disk with the wrong content or absent).

### Pre-hardening recon

Before deploying the five-artefact profile, the operator runs:

```bash
cat /proc/cmdline
sudo -r sysadm_r -t sysadm_t grubby --info=DEFAULT
sudo -r sysadm_r -t sysadm_t sysctl -a 2>/dev/null \
  | grep -E '^(kernel\.kptr_restrict|kernel\.dmesg_restrict|kernel\.yama|kernel\.kexec_load_disabled|kernel\.sysrq|kernel\.unprivileged_bpf_disabled|net\.ipv4\.conf\.(all|default)\.(rp_filter|accept_redirects|send_redirects|log_martians)|net\.ipv6\.conf\.(all|default)\.accept_redirects|fs\.suid_dumpable|fs\.protected_(fifos|regular|hardlinks|symlinks)|dev\.tty\.ldisc_autoload|net\.core\.bpf_jit_harden) ='
lsmod | head -30
cat /etc/security/limits.d/*.conf 2>/dev/null
cat /etc/systemd/coredump.conf.d/*.conf 2>/dev/null
```

On a stock Fedora 44 host without the topic applied, `cat /proc/cmdline` shows the BLS-default arguments without the five-flag set; `grubby --info=DEFAULT` confirms the same; the sysctl recon shows the upstream baseline (`randomize_va_space=2`, `perf_event_paranoid=2`, `unprivileged_bpf_disabled=2`, `dmesg_restrict=1`, `fs.protected_*=1`, `tcp_syncookies=1`, `suid_dumpable=2`); `lsmod` does not list any of the thirteen blacklisted modules unless an operator workflow already loaded one (in which case the role's apply will not unload it); and the limits and coredump directories are typically empty of operator drop-ins. The role's preflight stage runs the same recon and reports the outcome non-fatally.

### Idempotence and rollback

The role's modify stage is idempotent. The four configuration files are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `apply sysctl` handler fires only on a change to the sysctl drop-in. The `daemon-reload coredump` handler fires only on a change to the coredump drop-in. The `restorecon kernel-hardening` handler fires on any drop-in change and runs `restorecon -v` against the four shipping paths. The bootloader argument set is applied via the Ansible `command:` module gated on a `changed_when` shape that returns `changed=False` when the substring is already present in `/proc/cmdline`; unconditional re-apply on every Ansible run is drift. On a correctly applied host, `--check` reports zero changes after the first apply. Stated as a claim, not a guarantee.

The bootloader argument set is activated only by reboot; the role applies the argument set, prompts the operator with a `pause:` task that displays the byte-exact reboot rationale, and continues only after operator confirmation. Apply-on-running-kernel is structurally unavailable for the bootloader argument subset.

The rollback is single-stage:

```bash
sudo -r sysadm_r -t sysadm_t rm -f \
  /etc/sysctl.d/99-hardening.conf \
  /etc/modprobe.d/hardening.conf \
  /etc/security/limits.d/90-nocore.conf \
  /etc/systemd/coredump.conf.d/disable.conf
sudo -r sysadm_r -t sysadm_t grubby --update-kernel=ALL \
  --remove-args="slab_nomerge init_on_alloc init_on_free page_alloc.shuffle randomize_kstack_offset"
sudo -r sysadm_r -t sysadm_t systemctl daemon-reload
sudo -r sysadm_r -t sysadm_t sysctl --system
```

The rollback removes all four configuration drop-ins, strips the bootloader argument set from every BLS entry, reloads the systemd unit cache (so the coredump drop-in's removal takes effect), and re-applies the sysctl baseline (so the kernel-side runtime values revert to Fedora-default for the keys the topic configured). A reboot is required for the bootloader argument set to fully revert and for the running kernel to clear the still-loaded already-mitigated state (the slab and page-allocator randomization decisions made at boot time persist in the running kernel until reboot regardless of cmdline rollback).

kernel-hardening is **not** a topic that risks boot failure under normal apply: the sysctl drop-in is loaded by `systemd-sysctl.service` after early boot is past the failure-classifying milestone, and the bootloader argument set has been validated against Fedora 44 desktop and laptop hardware classes (see the smoketest above). The recovery how-to is the operator's path through the unlikely failure mode rather than a likely outcome.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

None. kernel-hardening configures host-global kernel, module, bootloader, and core-dump policy without a service unit and without a SELinux CIL module, so the daemon-oriented Pattern articles in this tree do not apply.
