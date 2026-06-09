<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# NNP and SELinux transition trap

## The trap

A `NoNewPrivileges=yes` directive in a service drop-in (or vendor unit) prevents a system-init-time service from booting on hosts where stock SELinux policy lacks the `init_t → <svc>_t : process2 nnp_transition` allow rule. The kernel checks the NNP-transition constraint **before** the service `ExecStart=` runs: if the source domain (here `init_t`) is forbidden from transitioning to the target domain (here `<svc>_t`) under the `no_new_privs` invariant, the `execve(2)` is denied. From systemd's perspective the unit fails to activate; from the operator's perspective, the service that was running before the drop-in is now offline at next boot. For login-critical services (D-Bus brokers, polkit, the display manager), the failure cascades into a non-interactive system, and the only recovery path is a rescue-image chroot.

The trap is not a configuration error. The drop-in is syntactically valid, `systemd-analyze verify` passes silently, and `systemctl restart <svc>` after the drop-in deploy may even succeed because the running daemon has already inherited its current process credentials. The next-boot `init_t → <svc>_t` `execve(2)` is the moment the constraint fires.

## Why it happens

SELinux carries per-domain rules for the `process2 / nnp_transition` permission. The kernel's `security_bprm_set_creds` path checks the source-target-class-permission tuple under `no_new_privs`, and a missing allow rule denies the transition. Stock targeted policy on Fedora ships the rule for a curated set of daemon domains; the upstream `selinux-policy` repository merges the rule per service through individual pull requests over time. Domains outside the curated set lack the rule by default. There is no single document that enumerates "domains whose NNP transition is allowed" — the truth lives in the policy module shipped with the running `selinux-policy` package and is enumerable only via `sesearch`.

The class is structural rather than incidental. `NoNewPrivileges=yes` was a Fedora hardening recommendation before the corresponding policy rules were complete, and the order in which rules are added is per service. New custom domains (site-local services) and old domains that no upstream PR has covered yet sit on the wrong side of the gap until their rule is added.

## How to detect it

Two pre-deploy checks plus one boot-time signal cover the class.

The pre-deploy check confirms the rule's presence:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t <svc>_t \
  -c process2 -p nnp_transition
```

On a stock-allowed domain the output is one allow line of the form `allow init_t <svc>_t:process2 { nnp_transition };`. On an affected domain the output is empty. The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension.

A secondary pre-deploy check confirms that the local SELinux policy distinguishes the target domain. Some daemons share a domain across several units (for example, multiple filesystem-helper daemons under `fsdaemon_t`); the per-domain check captures the right granularity:

```bash
sudo -r sysadm_r -t sysadm_t seinfo --type | grep -wE '<svc>_t'
```

The boot-time signal, when the trap fires, is an AVC audit record of the form:

```text
type=AVC msg=... avc:  denied  { nnp_transition } for
  scontext=system_u:system_r:init_t:s0
  tcontext=system_u:system_r:<svc>_t:s0
  tclass=process2
```

The record is captured by `auditd`. If the trap took down `auditd` itself — for example, on a host where `auditd` carries a hardening drop-in with `NoNewPrivileges=yes` and shares the gap — or the host failed to boot, the record is reachable only from a rescue-image `ausearch` against the host's `/var/log/audit/audit.log`.

## How to mitigate it

Two mitigation paths exist.

The **safe path** is to not deploy `NoNewPrivileges=yes`. The directive is one of several hardening directives a drop-in may carry; dropping it leaves the rest of the profile (Protect* family, capability bounding sets, syscall filters, address-family restrictions) in effect. The trade-off is a small reduction in the daemon's hardening posture; the alternative is the boot-failure that the trap produces.

The **clean path** is a custom CIL module that adds the missing rule:

```cil
(allow init_t <svc>_t (process2 (nnp_transition)))
```

Loaded at priority 400 via `semodule -X 400 -i <svc>_nnp.cil` from a `sysadm_r/sysadm_t` role-switch. Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The module survives `selinux-policy` package updates; an operator re-checks via `audit2why` after a major `selinux-policy` bump to confirm the upstream has not added the rule itself, in which case the local module can be removed via `semodule -X 400 -r <svc>_nnp`.

**Sequencing rule.** The CIL module must be loaded **before** the NNP drop-in is deployed. A deploy that pushes the drop-in first and the CIL module second leaves a window where a service restart — manual, package-triggered, or system reboot — hits the trap. Topic roles that ship both an NNP drop-in and the matching CIL extension flush handlers between the CIL install and the drop-in push to enforce the ordering deterministically.

**Scope rule.** The trap applies to **system-init-time services** — services whose `ExecStart=` runs under PID 1's transition into the daemon domain. User-application sandboxing (Flatpak, browser containers, post-login custom services) does not exhibit the trap, because those processes do not transit `init_t`. The risk is bounded by this scope: hardening user-application domains carries no boot-failure exposure under this class, and a misconfigured user-domain CIL module can be removed from a working session via `semodule -X 400 -r`.

Edge cases the mitigation does not cover:

- A drop-in that combines `NoNewPrivileges=yes` with `User=` (a user-domain service) escapes the `init_t → <svc>_t` path; the kernel checks a different transition rule. The mitigation form is the same in shape, but the source domain is not `init_t`, so the CIL module's `allow` clause names a different source.
- A daemon that spawns short-lived helper processes through `execve(2)` (cron jobs, mount helpers, hook scripts) inherits the parent's `no_new_privs` bit. If the helper's target domain also lacks the allow rule, the helper fails. The inter-domain transition variant is its own trap shape; see [NNP inter-domain transition](nnp-interdomain-transition.md).

## See also

- [SELinux custom CIL bootstrap](../reference/foundation/selinux-cil-bootstrap.md) — The Foundation layer that provisions the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` mechanism this mitigation rides on.
- [PrivateMounts implicit enable](./private-mounts-implicit.md) — A different silent-failure trap in the systemd hardening neighborhood; the symptom is a missing mount in the host namespace rather than a denied `execve(2)`, but both classes share the property that `systemd-analyze verify` and a same-boot `systemctl restart` do not surface them.
- [UMASK and daemon readability](./umask-and-daemon-readability.md) — Another silent boundary trap where a daemon starts but does not function as intended; the diagnostic posture (per-property reads, AVC and journal correlation) is similar.
