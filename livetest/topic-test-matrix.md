<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Topic test matrix

This matrix maps each role to its cloud testability, the key observable its
`verify.sh` checks, and a proposed product-risk priority. It feeds the system-tier
topic subset and the regression-selection rule defined in [the test concept](test-concept.md).

The cloud-testability classification is derived from each role's shipped `verify.sh`:
what unit or subject it inspects, whether that subject can exist on a stock headless
virtual machine, and whether the checks read kernel and policy state (headless) or a
live user session (substrate-dependent). The product-risk priorities are the suite's
adopted risk model, with the reasoning recorded in the closing section.

## How to read this matrix

### Cloud-testability codes

- **Full** — the shipped `verify.sh` applies and passes on a stock headless virtual
  machine, and its effectiveness checks exercise a real path (a daemon answers, a
  round-trip succeeds, a negative test denies).
- **Full (presence)** — the shipped `verify.sh` passes headless, but its checks confirm
  control-presence only: the policy module is loaded, the allow rule is present, and the
  audit store carries no denial of the relevant class since boot. The last check is
  vacuously green until the protected path is actually exercised, which the session tier
  does. These rows pass the component scenario but do not yet prove effectiveness.
- **Session** — the shipped `verify.sh` has checks that require a running user session
  to pass at all: a `systemctl --user` unit, the runtime domain of a launched
  application, or a document-portal token count. These need the headless session
  substrate and belong to the phased session-effectiveness tier.
- **HW-gap** — the shipped `verify.sh` inspects a unit whose existence depends on
  hardware a virtual machine does not provide: a sound device, an ATA SMART device, a
  graphical framebuffer, or Intel thermal sensors. Control-presence of the drop-ins is
  still readable through `systemctl cat`, but the unit may be inactive, so the liveness
  and effectiveness checks do not pass unmodified.

### Priority codes

Priorities follow risk-based testing, combining likelihood of a hardening-induced
defect with the blast radius of that defect.

- **P1** — whole-host or lifeline blast radius. A misconfiguration can break boot or
  remove the network the harness depends on. Run first and always in the system tier;
  these are the topics for which the out-of-band console exists.
- **P2** — service-level blast radius. The topic carries a custom SELinux transition,
  an internal privilege drop, or a namespace trap, but a defect degrades one service
  rather than the host.
- **P3** — post-login or configuration-only. The control is reversible from `sysadm_t`
  with no boot risk.

### Boot-failure class

A topic is in the boot-failure class when it applies `NoNewPrivileges` to an
init-time service whose target domain needs a custom `nnp_transition` allow, or when it
changes the kernel command line. Eleven topics ship an `nnp_*.cil` module plus
`dbus-broker`, and `kernel_hardening` changes the command line. The P1 subset is the
part of that class with whole-host impact. See
[NNP and SELinux transition trap](../docs/explanation/nnp-selinux-transition-trap.md).

## Coverage summary

| Cloud-testability | Count | Topics |
|---|---|---|
| Full | 15 | headless component scenario passes with real effectiveness |
| Full (presence) | 4 | headless component scenario passes; effectiveness deferred to session tier |
| Session | 4 | needs the headless session substrate |
| HW-gap | 4 | needs hardware a virtual machine lacks |

Nineteen of twenty-seven topics are meaningfully verifiable on a stock headless virtual
machine (Full plus Full-presence). Four need the session substrate, and four need real
hardware. The four Foundation layers are all Full and are a prerequisite for every
scenario.

As of the 2026-08 full run all nineteen pass, and twenty-two of them run in the cumulative
system tier — `topic_staff_wayland_memfd` is component-tested but held out of the system
tier because it needs a Wayland session. A row missing from this table is not a neutral
omission: `topic_flatpak_kfd_device` was absent here from its creation until that run, so
it was never assigned a tier and never entered the cumulative converge.

## Foundation layers

The four Foundation roles are applied in fixed order before any topic and are verified
in both the `staff_t` and `sysadm_t` contexts, as the bootstrap path does. All four are
Full. A change to any Foundation role triggers the system tier under the
regression-selection rule, because every topic depends on the Foundation.

| Layer | Role | Key verify criterion |
|---|---|---|
| 0 | `foundation_umask` | `login.defs` UMASK 027, HOME_MODE 0700, pam_umask, live login umask |
| 1 | `foundation_sudo_roles` | `id -Z` is `staff_u:staff_r:staff_t`; `staff_extras.cil` loaded |
| 2 | `foundation_selinux_cil_bootstrap` | Enforcing; publish dir present and labeled; `semodule` callable under role switch |
| 3 | `foundation_audit_logging_baseline` | audit and journald active; persistent journal present and labeled |

## Matrix

### Cloud-full

| Topic | Hardens | Key verify criterion | Priority |
|---|---|---|---|
| `topic_auditd` | audit daemon, namespace + NNP | `auditd_t`; NNP; `nnp_auditd.cil`; auditctl enabled; AVC-clean | P1 |
| `topic_cups` | print daemon, namespace + NNP | `cupsd_t`; NNP; `nnp_cups.cil`; listen 631; lpstat works | P1 |
| `topic_dbus_broker` | system D-Bus broker | `system_dbusd_t`; NNP; `nnp_dbus_broker.cil`; dbus-send round-trip | P1 |
| `topic_kernel_hardening` | sysctl, module blacklist, coredump | sysctl keys; modules blacklisted; command line (reboot-gated); coredump off | P1 |
| `topic_network_manager` | network daemon, namespace + NNP | `NetworkManager_t`; NNP; address families; `nnp_network_manager.cil`; nmcli connectivity | P1 |
| `topic_integrity_monitoring` | four-check integrity model | `aide_t` via the nested unit; single timer active and enabled; scope inversion marker; scope-reduced AIDE database; three acceptance lists; hash rule for the acceptance directory; second start serialises; `aide_extras.cil` | P2 |
| `topic_avahi_daemon` | mDNS daemon, namespace + NNP | `avahi_t`; NNP and MDWE; full Protect* set; mDNS resolve round-trip | P2 |
| `topic_chronyd` | time daemon, namespace + NNP | `chronyd_t`; NNP; chronyc tracking; port-123 bind absence (negative) | P2 |
| `topic_cron` | cron daemon + job domain | `crond_t`; NNP; cron job spawns into `system_cronjob_t` (inter-domain) | P2 |
| `topic_rngd` | entropy daemon, privilege drop | `rngd_t`; NNP; syscall filter; entropy available; journal uid-drop; seccomp-clean | P2 |
| `topic_tuned` | tuning daemon, namespace | `tuned_t`; Protect* set; tuned-adm active; fcontext canonical or premerge | P2 |
| `topic_udisks2` | disk daemon, namespace + caps | `devicekit_disk_t`; NNP; PrivateMounts=no; `cap_sys_rawio`; syscall filter | P2 |
| `topic_flatpak_collection_id` | flatpak remote collection-id | per-remote collection-id present; zero non-fatal-fetch warnings | P3 |
| `topic_python_pip_user_tree` | pip user tree + PEP-668 marker | EXTERNALLY-MANAGED marker triplet; no orphan user trees; no user-local pip | P3 |
| `topic_switcheroo_control` | GPU-switch daemon gate | hybrid-GPU applicability gate; on a single-GPU host asserts the unit disabled | P3 |

### Cloud-full (presence-only)

These pass the headless component scenario, but their effectiveness is proven only when
the session tier exercises the protected path; until then the audit-backlog check is
vacuously green.

| Topic | Hardens | Key verify criterion | Priority |
|---|---|---|---|
| `topic_flatpak_audio_sandbox` | flatpak audio sandbox policy | `flatpak_audio_sandbox.cil` loaded; allow rule present; AVC-class-clean | P3 |
| `topic_flatpak_oci_pull_dbus` | flatpak OCI-pull D-Bus policy | `flatpak_oci_pull_dbus.cil` loaded; allow rule present; AVC-class-clean | P3 |
| `topic_staff_wayland_memfd` | Wayland memfd policy | `staff_wayland_memfd.cil` loaded; map and write rules present; AVC-class-clean | P3 |
| `topic_flatpak_kfd_device` | AMD compute-device access for the flatpak bwrap sandbox | `flatpak_kfd_device.cil` loaded; `staff_t x hsa_device_t : chr_file getattr` present; AVC-class-clean. The functional branch needs an AMD GPU and is a real HW-gap, confirmed out-of-band on hardware | P3 |

### Session-dependent

| Topic | Hardens | Key verify criterion | Priority |
|---|---|---|---|
| `topic_flatpak_portal_cache` | document-portal token cache | xdg-document-portal user service alive; FUSE by-app and persistent-document counts | P3 |
| `topic_keepassxc` | KeePassXC sub-domain isolation | three CIL modules; custom types and type-transitions; database-label sweep; `runtime_domain` needs the app | P3 |
| `topic_mozilla_firefox` | Firefox flatpak confinement | rpm absent; flatpak ref and overrides; `runtime_domain` and portal need the session | P3 |
| `topic_mozilla_thunderbird` | Thunderbird flatpak confinement | rpm absent; flatpak ref and overrides; `runtime_domain` and portal need the session | P3 |

### Hardware-gap

| Topic | Hardens | Key verify criterion | Priority |
|---|---|---|---|
| `topic_plymouth` | boot-splash, namespace + NNP | `nnp_plymouth.cil`; NNP; quit-wait anchor; ReadWritePaths substrings (graphical boot) | P1 |
| `topic_alsa_state` | ALSA-state daemon, namespace + NNP | `alsa_t`; NNP; live `comm` is `alsactl`; state file present (needs a sound device) | P2 |
| `topic_smartd` | SMART daemon, caps + NNP | `fsdaemon_t`; NNP; `cap_sys_rawio`; SATA SMART; the unit may be inactive on a VM | P2 |
| `topic_thermald` | thermal daemon, namespace + NNP | `thermald_t`; NNP; active state per a DPTF-dependent expected-state model (Intel sensors) | P2 |

## Hardware-gap topics — what is and is not covered

For these four topics, control-presence is readable headless through `systemctl cat`
and the policy store, but the daemon may not run on a virtual machine, so liveness and
functional effectiveness do not pass unmodified.

- `topic_plymouth` is an early-boot service. On a headless instance it runs in text or
  details mode rather than rendering a framebuffer splash. It is ranked P1 despite the
  hardware gap because a `NoNewPrivileges` defect on an early-boot init service can stall
  boot; the drop-in and CIL presence are the part that carries the boot risk and that is
  testable. The runtime-path checks relate to
  [the ReadWritePaths runtime race](../docs/explanation/readwritepaths-runtime-race.md).
- `topic_alsa_state` needs a sound device for `alsa-state.service` to run and write its
  state file. A harness mitigation is to load the `snd-dummy` module so the unit has a
  device; without it the unit is inactive and the liveness check does not pass.
- `topic_smartd` monitors ATA SMART over an `SG_IO` pass-through; virtio and NVMe cloud
  disks do not expose SATA SMART, so `smartd` may exit for lack of devices. The granted
  `cap_sys_rawio` is the control-presence observable and is testable; the SMART function
  is not. See [SMART and CAP_SYS_RAWIO](../docs/explanation/storage-smart-rawio.md).
- `topic_thermald` needs Intel thermal sensors. Its `verify.sh` carries a
  DPTF-dependent expected-state model, so on a sensorless instance it asserts the
  inactive or unknown state rather than failing outright; effectiveness against real
  thermal events is not covered.

`topic_udisks2` is listed as Full because its `verify.sh` checks the daemon-hardening
surface, which runs on a virtual machine. The removable-media mount function and SATA
SMART that the daemon also performs are a hardware gap, but they are outside the verify
scope. The PrivateMounts override relates to
[the implicit PrivateMounts trap](../docs/explanation/private-mounts-implicit.md).

## Session-dependent topics and presence-only effectiveness

The four Session topics and the three Full-presence topics are the work of the phased
session-effectiveness tier described in [the test concept](test-concept.md). The tier
brings up a headless session substrate as the `staff_u` user and exercises the
protected paths:

- For the four Full-presence topics, it launches the application or triggers the D-Bus
  flow so the allow rule is actually traversed, turning the vacuously-green
  audit-backlog check into a real effectiveness check.
- For `topic_keepassxc`, `topic_mozilla_firefox`, and `topic_mozilla_thunderbird`, it
  launches the application so `runtime_domain` and the portal-permission checks have a
  live process to read. The KeePassXC sub-domain isolation depends on
  [helper-spawn inheritance](../docs/explanation/app-subdomain-helper-spawn-inheritance.md).
- For `topic_flatpak_portal_cache`, it establishes the user session so
  `systemctl --user`, the portal service, and the FUSE document mount are addressable.

## Product-risk ranks

The P1, P2, and P3 assignments in this matrix are the suite's adopted risk model. The
reasoning is recorded above per class, and the most consequential calls are:

- `topic_dbus_broker` and `topic_network_manager` at P1 because a defect removes the
  system bus or the network the harness connects over.
- `topic_auditd`, `topic_cups`, and `topic_plymouth` at P1 on the documented evidence
  that a `NoNewPrivileges` defect on these init-time services can break boot, even where
  the service itself is not whole-host critical.
- `topic_kernel_hardening` at P1 because a command-line or module-blacklist defect
  carries boot risk that a sysctl change does not.

The remaining daemon topics sit at P2 and the post-login and configuration topics at P3.
These ranks drive the system-tier run order and the regression-selection blast radius.
