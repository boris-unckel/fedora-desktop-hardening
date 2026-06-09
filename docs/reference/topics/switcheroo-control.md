<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# switcheroo-control

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state of `switcheroo-control.service` on a Fedora 44 or later host whose graphics configuration is single-GPU or non-switchable multi-GPU. The end-state is **service-disable**: the unit is `disabled`, the unit is `inactive(dead)`, and the symlink `/etc/systemd/system/graphical.target.wants/switcheroo-control.service` is absent. The topic ships **no** drop-in INI file under `/etc/systemd/system/switcheroo-control.service.d/`, **no** SELinux CIL module, **no** `Protect*` family, **no** `SystemCallFilter=`, **no** `CapabilityBoundingSet=` reduction, and **no** namespace-default baseline. The hardening surface is the absence of the running daemon. The applicability gate (single-GPU or non-switchable multi-GPU only), the hybrid-GPU detection preflight, the single canonical `systemctl disable --now` modify action, the three-fact end-state, the verify discipline, and the single-stage rollback are documented below. The topic does **not** cover the `switcheroo-control` D-Bus interface (`net.hadess.SwitcherooControl`) method and signal definitions, the desktop-session integration that consumes the interface (GNOME Shell's "Launch on Discrete GPU" menu and the equivalent in KDE Plasma), the kernel `vga_switcheroo` interface, the `DRI_PRIME` and `__NV_PRIME_RENDER_OFFLOAD` user-facing offload paths, NVIDIA Optimus and AMD switchable-graphics platform-vendor specifics, the `mask` operator-policy alternative to `disable`, the `dnf remove switcheroo-control` package-removal alternative, or the `systemd-analyze security` numeric score model. Package retention (`switcheroo-control` remains installed) is the deliberate choice; `dnf remove` would couple the rollback path to a `dnf install` step that re-fetches the package across the network and is therefore out of scope.

## End-state configuration

The end-state combines no shipping artefacts. There is no drop-in INI file, no CIL module, and no on-disk configuration file written by this topic. Subsections below describe the service identity, the load-bearing structural property that distinguishes this topic from every other Topic-tier article in this tree, the applicability gate that fail-fasts on hybrid-GPU hosts, the single canonical modify action, the three-fact end-state observed after the action runs, and the artefact-shape negatives that follow from the service-disable shape.

### Service identity

The unit `switcheroo-control.service` is shipped by the `switcheroo-control` package. The stock vendor file at `/usr/lib/systemd/system/switcheroo-control.service` ships the directives this topic does not modify. The daemon binary is installed at `/usr/libexec/switcheroo-control`. On a Fedora 44 host with a stock-enabled vendor unit, the daemon publishes the system-bus name `net.hadess.SwitcherooControl` and exposes that interface to desktop sessions (GNOME Shell, KDE Plasma) for hybrid-GPU detection and GPU-tagged child-process launching.

| Property | Value |
|---|---|
| Unit | `switcheroo-control.service` |
| Type | `dbus` |
| BusName | `net.hadess.SwitcherooControl` |
| ExecStart | `/usr/libexec/switcheroo-control` |
| User / group | `root:root` |
| SELinux runtime domain | `switcheroo_control_t` |
| Vendor `[Install]` | `WantedBy=graphical.target` |

Stock targeted policy on Fedora 44 ships the runtime domain `switcheroo_control_t`, the executable file context `switcheroo_control_exec_t` (mapped onto `/usr/libexec/switcheroo-control`), and the unit-file context `switcheroo_control_unit_file_t`. The role does not interact with any of these types because the daemon is not running in the end-state. The vendor `[Install]` section's `WantedBy=graphical.target` is the upstream-default that places `/etc/systemd/system/graphical.target.wants/switcheroo-control.service` as a symlink at first-package-install or first-`enable`. The `switcheroo-control` package additionally ships the D-Bus service activation file `/usr/share/dbus-1/system-services/net.hadess.SwitcherooControl.service` and the system-bus policy file `/usr/share/dbus-1/system.d/switcheroo-control.conf`; both remain on disk in the end-state and are not modified.

### Topic shape — service-disable

This topic occupies a structurally different shape than every other Topic-tier article in this tree. The hardening surface is the absence of the running daemon. With the unit disabled and inactive, the daemon's process never initialises, no D-Bus name registration occurs on the system bus, the SELinux runtime domain `switcheroo_control_t` is never instantiated, and the unit's exposure surface is reduced to zero. Every downstream subsection — the applicability gate, the modify-stage action, the three-fact end-state, the verify discipline, the artefact-shape negatives, the idempotence claim, and the rollback posture — is framed by this single load-bearing structural property. There is no drop-in INI body to enumerate, no CIL allow rule to load, no `SystemCallFilter=` allow-list or subtractive group to assert, and no `CapabilityBoundingSet=` reduction to verify. The rest of this article is consequently terser than the sibling Topic articles.

### Applicability

The topic applies only to hosts whose GPU configuration is **single-GPU** or **non-switchable multi-GPU**. Examples of applicable configurations:

- A desktop or workstation with one display controller (Intel iGPU, AMD APU, AMD discrete, NVIDIA discrete) and no second display controller of any class.
- A workstation with two discrete GPUs of the same vendor that share no vga_switcheroo handler (typical of professional rendering and scientific-computing setups where each GPU is independently driven).
- A server-class host with no display controller at all (headless).

The topic does **not** apply to hosts in any of the following classes:

- Hybrid-GPU laptops with NVIDIA Optimus (Intel iGPU plus NVIDIA dGPU).
- Hybrid-GPU laptops with AMD switchable graphics (AMD iGPU plus AMD dGPU, or AMD iGPU plus NVIDIA dGPU).
- Workstations with a vga_switcheroo-capable PCIe topology.
- Any host where a desktop session uses GPU-tagged child-process launching through the daemon's interface (for example, GNOME Shell's "Launch on Discrete GPU" menu integration or the KDE Plasma equivalent).

On an inapplicable host the daemon is required for normal desktop operation, and the role's preflight stage fail-fasts with an actionable error message. The detection signal that distinguishes the two host classes is reproduced under §"Verification" → §"Hybrid-GPU detection".

### Modify-stage action

The role's modify stage runs one canonical action under the role-switch escalation pattern documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md):

```bash
sudo -r sysadm_r -t sysadm_t systemctl disable --now switcheroo-control.service
```

The `--now` flag combines `disable` (remove the `WantedBy=graphical.target` symlink) and `stop` (terminate the running daemon) in a single systemd transaction. The Ansible role uses `ansible.builtin.systemd_service` with `enabled: false` and `state: stopped`; the module abstracts the two-flag behaviour and is idempotent on a host already in the end-state.

### End-state facts

The end-state is observed as three independent on-disk facts. The verify discipline asserts each independently; drift on any single fact is `FAIL`.

- **Unit-enable state.** `systemctl is-enabled switcheroo-control.service` returns `disabled`. `systemctl show -p UnitFileState --value switcheroo-control.service` returns `disabled`. The unit is not `masked`; `mask` is a stronger guarantee that prevents any future `enable` and is a separate operator-policy decision outside the scope of this topic.
- **Unit-active state.** `systemctl is-active switcheroo-control.service` returns `inactive`. The per-property reads return `ActiveState=inactive`, `SubState=dead`, `Result=success`, and `MainPID=0`.
- **Symlink absence.** The path `/etc/systemd/system/graphical.target.wants/switcheroo-control.service` does not exist. `stat` on the path returns `No such file or directory`. The `systemctl disable --now` transaction removes the symlink as a side effect of the `disable` step; the role does not run a separate `ansible.builtin.file: state: absent` task against the symlink.

### Artefact-shape negatives

The topic ships no on-disk configuration artefact. The list below states the artefact-shape negatives as positive design claims:

- **No** `/etc/systemd/system/switcheroo-control.service.d/` directory is created. The drop-in directory has no role-owned content to receive; with the daemon never running, there is no process whose properties a drop-in could constrain.
- **No** `99-hardening.conf`, `99-nnp.conf`, or `99-process-restrict.conf` drop-in is shipped. The directives those drop-ins would carry on a sibling Topic act on a running daemon's process; this topic has no running daemon to act on.
- **No** topic-owned CIL module (no `nnp_switcheroo_control.cil` or any other) is shipped. The kernel's NoNewPrivileges-transition constraint applies to a live `execve(2)`; with the unit disabled and inactive, no such `execve(2)` occurs and the constraint is never evaluated.
- **No** `restorecon` invocation is required. The role writes no file under `/etc/`; there is no on-disk artefact whose SELinux label needs correcting.
- **No** `semodule -X 400 -i` is invoked. The priority-400 publish path under `/usr/local/share/selinux/` is not exercised by this role; the Foundation Layer 2 dependency is consequently absent from `meta/main.yml`.

### File modes

This topic ships no configuration files. The role's modify stage removes the `/etc/systemd/system/graphical.target.wants/switcheroo-control.service` symlink as a side effect of `systemctl disable`; the symlink's mode and ownership in the pre-disable state are not configured by this role and are upstream-controlled.

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; the AVC-clean check that needs `sysadm_t` is reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side check transits through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Hybrid-GPU detection

The applicability gate uses PCI enumeration as the upstream-canonical signal. A host with two or more PCI display or 3D controllers is treated as hybrid-GPU and is structurally inapplicable for this topic; the verify exits `2` (invocation error) with the GPU enumeration as the abort reason. A host with exactly one such controller is the canonical single-GPU class. A host with zero such controllers is the headless class; the daemon is unnecessary, and the end-state is admissible.

The detection block, runnable from a `staff_t` shell without escalation:

```bash
gpu_count=$(( $(lspci -d ::0300 -mm | wc -l) + $(lspci -d ::0302 -mm | wc -l) ))
if [[ "${gpu_count}" -ge 2 ]]; then
  printf 'switcheroo-control: hybrid-GPU detected (%s devices); topic does not apply\n' "${gpu_count}" >&2
  exit 1
fi
```

`lspci -d ::0300` enumerates VGA-compatible display controllers (PCI class `0300`); `lspci -d ::0302` enumerates 3D controllers (PCI class `0302`), the class to which discrete GPUs in hybrid configurations typically present when the iGPU is the primary VGA device. The combined count is the hybrid-GPU indicator. The verify script runs the detection **before** any state assertion; an exit-2 outcome is a structural-applicability negative, not drift, and is reported as such.

### Probe

```bash
bash ansible/roles/topic_switcheroo_control/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`switcheroo-control` and the installed version), the hybrid-GPU detection block (`gpu_count` plus the lspci enumeration as captured text), the unit-enable state (`systemctl is-enabled`), the unit-active state (`systemctl is-active`), and the per-property reads via one `systemctl show -p <PROP> --value` call per property (never multi-property, because multi-property output ordering is not stable across systemd versions): `ActiveState`, `SubState`, `Result`, `MainPID`, `LoadState`, `UnitFileState`. It also reports the result of `stat /etc/systemd/system/graphical.target.wants/switcheroo-control.service` as `present` or `absent` symbolically, and tails the journal for the unit since boot (`journalctl -u switcheroo-control.service --since boot --no-pager | tail -20`). On a correctly applied host the journal carries no entries since boot for the unit. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_switcheroo_control/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted for the `sysadm_t`-gated AVC check), `1` on drift, and `2` on invocation error or hybrid-GPU detection. The expected set:

| Property | Expected value |
|---|---|
| `UnitFileState` | `disabled` |
| `ActiveState` | `inactive` |
| `SubState` | `dead` |
| `Result` | `success` |
| `MainPID` | `0` |
| Symlink at `/etc/systemd/system/graphical.target.wants/switcheroo-control.service` | absent |
| `gpu_count` (display-plus-3D PCI controllers) | `0` or `1` |

The script does **not** define `EXPECTED_NNP`, `EXPECTED_PROTECT_*`, `EXPECTED_PRIVATE_*`, `EXPECTED_RESTRICT_*`, `EXPECTED_LOCK_PERSONALITY`, `EXPECTED_MDWE`, `EXPECTED_SYSCALL_FILTER_*`, `EXPECTED_CAP_BOUNDING_SET`, `EXPECTED_RUNTIME_DOMAIN`, `EXPECTED_UID`, or `EXPECTED_GID`. With `MainPID=0` there is no live process to read from `/proc/<MainPID>/attr/current` or `/proc/<MainPID>/status`; the live-process probes are omitted as structurally inapplicable rather than reported as `SKIP`. The script also omits a `[ -d /proc/${main_pid} ]` liveness check for the same reason — no PID exists to probe.

The hybrid-GPU detection runs before any state assertion. On a hybrid-GPU host the script exits `2` with an actionable error message; the exit-2 path is a structural-applicability negative, not drift. On an applicable host where any single end-state fact disagrees with the hardcoded value, the script exits `1` and reports the failing fact.

### AVC posture

On a correctly applied host, the role-switched query

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot \
  | grep -E '(switcheroo|switcheroo_control_t|switcheroo_control_exec_t)'
```

returns zero hits across the boot. With the unit never starting, the SELinux runtime domain `switcheroo_control_t` is never instantiated and the kernel's policy evaluation never references it. The AVC-clean assertion is a structural tautology on an applied host but is run anyway as a regression detector against an enable-by-accident path — for example, a future package update that re-creates the `WantedBy=graphical.target` symlink at install-time, or an operator action that runs `systemctl enable switcheroo-control.service` outside this role's purview. Any non-empty result indicates the unit started during this boot and is drift requiring investigation. The four-tool diagnosis loop that operators use when a hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

The role's modify stage is idempotent. `ansible.builtin.systemd_service` with `enabled: false` and `state: stopped` reports `changed=false` on a host already in the end-state. The role ships no `ansible.builtin.copy` task, no `ansible.builtin.template` task, and no `ansible.builtin.lineinfile` task; there are no configuration artefacts to push and no byte-for-byte content to converge. The role ships no handler — there is no `daemon-reload`, no `restart`, and no `restorecon` to fire. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

The rollback posture is single-stage. The role's documented rollback action is:

```bash
sudo -r sysadm_r -t sysadm_t systemctl enable --now switcheroo-control.service
```

The `--now` flag re-creates the `/etc/systemd/system/graphical.target.wants/switcheroo-control.service` symlink (`enable`) and starts the daemon (`start`) in a single systemd transaction. The boot-failure risk for this topic is structurally zero — disabling a unit cannot brick the boot path; the rollback is tested by re-enabling the unit and confirming the daemon comes up under its stock SELinux runtime domain `switcheroo_control_t`. The recovery how-to is referenced via the standard banner below for tree consistency, even though this topic's failure modes do not include a boot failure.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

This topic does not cross-link any pattern article. The service-disable end-state does not exercise the kernel NoNewPrivileges-transition constraint, the systemd `SystemCallFilter` privilege-drop sequence, the systemd `PrivateMounts` implicit-enable, the systemd `ReadWritePaths` runtime race, the cross-user liveness-probe trap, or any other cross-cutting hardening pattern documented in this tree. With the unit disabled and inactive, none of the kernel, systemd, or SELinux mechanisms that those patterns describe are reachable.
