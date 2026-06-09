<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# NNP inter-domain transition

## The trap

A daemon under `NoNewPrivileges=yes` boots cleanly, runs cleanly, and serves its primary workload cleanly — until it spawns a helper that triggers a SELinux type-transition into a second domain. At that moment the kernel checks the `process2 nnp_transition` permission between the daemon's domain and the helper's target domain. If the rule is missing, `execve(2)` is denied: the helper never starts, and the dependent code path on the daemon stalls or returns an error. The daemon itself stays up; the unit is `active`; `systemd-analyze verify` is silent; the same-boot `systemctl restart` succeeds because the running daemon already has its credentials and never re-execs the helper.

The class is the inter-domain sibling of the boot-time `init_t → service_t` NNP-transition trap. The boot-time variant fires the moment PID 1 spawns the daemon under the no-new-privs invariant; the failure is loud, immediate, and unmistakeable — the unit fails to activate and a login-critical service can take the whole host down. The inter-domain variant fires the first time the daemon spawns the affected helper. If the helper sits on a rarely-exercised code path — a configuration helper that runs only on a `reload` request, a queue-flush helper that runs only when the queue overflows, a format-conversion helper that runs only for one specific input type — the trap may sleep for hours, days, or weeks after the apply before the dependent path is exercised and the failure surfaces. By the time the operator sees a stalled job or an empty result, the connection between the recent hardening change and the current symptom is no longer obvious.

## Why it happens

`NoNewPrivileges=yes` sets the kernel's `no_new_privs` bit on the daemon process. The bit is inherited across `fork(2)` and across `execve(2)`; every descendant of the daemon process carries it. The bit is sticky: once set, it cannot be cleared by an unprivileged process, and it constrains every subsequent `execve(2)` in the same process tree.

SELinux carries the `process2 nnp_transition` permission as a per-source-domain, per-target-domain rule in the policy. The kernel's `security_bprm_set_creds` path checks the permission on every `execve(2)` that performs a type-transition under `no_new_privs`. The check is symmetric in shape between the boot-time and the inter-domain cases — the same kernel code path, the same permission bit, the same denial outcome — but the source domain differs:

- **Boot-time variant.** PID 1 (`init_t`) spawns the daemon binary with executable label `<svc>_exec_t`. Stock policy carries a `type_transition init_t <svc>_exec_t : process <svc>_t;`. Under `no_new_privs`, the kernel checks `allow init_t <svc>_t : process2 nnp_transition`. Missing rule → boot fails.
- **Inter-domain variant.** The daemon (running under `<svc>_t`, with `no_new_privs` already set) spawns a helper binary with executable label `<helper>_exec_t`. Stock policy carries a `type_transition <svc>_t <helper>_exec_t : process <helper>_t;`. Under the inherited `no_new_privs`, the kernel checks `allow <svc>_t <helper>_t : process2 nnp_transition`. Missing rule → helper fails.

Stock targeted policy on Fedora ships the `process2 nnp_transition` rule per source-target pair through individual upstream pull requests over time. Coverage is per-pair, not blanket: a daemon may have its `init_t → <svc>_t` rule covered (so the boot-time variant does not apply) while one of its helper-spawn pairs `<svc>_t → <helper>_t` lacks the rule. There is no single document that enumerates "domain pairs whose NNP transition is allowed" — the truth lives in the `selinux-policy` module shipped with the running package and is enumerable only via `sesearch`.

The class is structural rather than incidental. Multi-stage daemons that decompose work into helper subdomains — an LPD-protocol helper, a configuration parser, a format-conversion backend, a queue-flush worker — each have their own type-transition rule, and each rule needs its own `process2 nnp_transition` allow when the daemon runs under `NoNewPrivileges=yes`. New helper subdomains added by an upstream `selinux-policy` revision require the rule to be added in the same release; an out-of-band site-local CIL extension that names the daemon's main domain only does not cover the new helper.

## How to detect it

Three observable signals, in order of how reliably they appear on an affected host.

The first signal is the AVC audit record. When the trap fires, `auditd` records:

```text
type=AVC msg=... avc:  denied  { nnp_transition } for
  scontext=system_u:system_r:<svc>_t:s0
  tcontext=system_u:system_r:<helper>_t:s0
  tclass=process2
```

Note the `scontext` is the daemon's own domain, not `init_t`. The `tcontext` names the helper subdomain. The `tclass=process2` and `denied { nnp_transition }` pair is the unambiguous fingerprint of the class. The boot-time variant produces the same fingerprint with `scontext=...:init_t:s0`; the inter-domain variant has any non-`init_t` source domain.

The second signal is a functional regression on the dependent code path. The affected helper does not run, so the operator-visible outcome is:

- A request that requires the helper returns an error or stalls indefinitely.
- A queue that requires the helper drains nothing.
- A format conversion that requires the helper produces an empty result.
- The daemon's own log records the helper-spawn failure, typically as `execve: Operation not permitted` or `child process exited with status 13`.

The functional regression alone is not specific enough to identify the class — many failure modes produce a similar shape — but coupled with the AVC fingerprint above, the class is unambiguous.

The third signal is a pre-deploy enumeration of the helper-spawn pairs that the daemon's policy declares. The targeted policy can be queried for every type-transition rule whose source is the daemon's domain:

```bash
sudo -r sysadm_r -t sysadm_t \
  sesearch -T -s <svc>_t -c process
```

Each line of output names a `(source, executable_type, target)` triple; the `target` is a candidate helper subdomain. For each triple, the operator confirms the `process2 nnp_transition` rule's presence with:

```bash
sudo -r sysadm_r -t sysadm_t \
  sesearch -A -s <svc>_t -t <target> -c process2 -p nnp_transition
```

A non-empty return is the rule. An empty return is the gap. The enumeration is exhaustive over the policy at the time of the query but does not catch helpers that are not declared as type-transitions (a helper invoked under the daemon's own domain, with no transition, is not subject to the trap and does not need a rule).

```text
$ sudo -r sysadm_r -t sysadm_t sesearch -T -s <svc>_t -c process
type_transition <svc>_t <helper_a>_exec_t : process <helper_a>_t;
type_transition <svc>_t <helper_b>_exec_t : process <helper_b>_t;
type_transition <svc>_t <helper_c>_exec_t : process <helper_c>_t;
$ for h in <helper_a>_t <helper_b>_t <helper_c>_t; do
    sudo -r sysadm_r -t sysadm_t sesearch -A -s <svc>_t -t "$h" \
      -c process2 -p nnp_transition
  done
allow <svc>_t <helper_a>_t : process2 nnp_transition;
(empty)
allow <svc>_t <helper_c>_t : process2 nnp_transition;
```

The empty middle output identifies `<svc>_t → <helper_b>_t` as the gap. A site-local CIL extension that adds the missing rule closes the trap.

## How to mitigate it

The clean mitigation is a custom CIL module that adds an allow rule for every helper-spawn pair the daemon's policy declares, regardless of whether the operator's enumeration confirms each pair as missing or already covered. Stock-policy coverage of one or more pairs is harmless on a same-priority site-local extension: the kernel evaluates the union of all loaded rules, and a duplicate allow is a no-op.

```cil
(allow <svc>_t <helper_a>_t (process2 (nnp_transition)))
(allow <svc>_t <helper_b>_t (process2 (nnp_transition)))
(allow <svc>_t <helper_c>_t (process2 (nnp_transition)))
```

The module is loaded at priority 400 via `semodule -X 400 -i <svc>_nnp.cil` from a `sysadm_r/sysadm_t` role-switch. Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The module survives `selinux-policy` package updates; an operator re-checks via `audit2why` after a major `selinux-policy` bump to confirm the upstream has not added the rules itself, in which case the local module can be removed via `semodule -X 400 -r <svc>_nnp`.

**Defensive coverage rule.** A topic role that ships an NNP drop-in for a multi-helper daemon ships allow rules for **every** helper-spawn pair declared in the daemon's policy, not only the pairs the operator's pre-test enumerates as missing. Two reasons. First, an upstream `selinux-policy` revision may add a new helper subdomain that the role's pre-test does not enumerate; the defensive rule covers it from day one rather than requiring a topic re-deploy after an upstream policy update. Second, a stock-policy revision that **removes** a previously-covered pair (rare but possible) does not silently reintroduce the trap because the site-local rule already covers it.

**Sequencing rule.** The CIL module must be loaded **before** the NNP drop-in is deployed. The same sequencing applies to the boot-time variant; the inter-domain variant inherits it because the helper-spawn sites are exercised after the daemon starts under `NoNewPrivileges=yes`. A deploy that pushes the drop-in first and the CIL module second leaves a window where the first helper-spawn after the apply hits the trap. Topic roles that ship both an NNP drop-in and the matching CIL extension flush handlers between the CIL install and the drop-in push to enforce the ordering deterministically.

**Diagnosis-first discipline.** A delayed-manifestation failure days or weeks after the apply is easy to misattribute to an unrelated change. The diagnostic posture is: when a helper-dependent code path fails on a host carrying recent NNP hardening, run `ausearch -m AVC -ts boot | grep nnp_transition` first, before reaching for any other root cause. If the AVC fingerprint is present, the class is identified and the mitigation is the CIL extension above. If the AVC fingerprint is absent, the failure is unrelated to the NNP-transition class.

Edge cases the mitigation does not cover:

- A helper whose target domain is not declared as a type-transition from the daemon's source domain (the helper inherits the daemon's own domain instead of transitioning) is not subject to the trap; the helper runs under `<svc>_t` and the kernel does not evaluate `process2 nnp_transition`. No allow rule is needed and the policy enumeration above does not list the helper.
- A helper invoked through `bwrap`, `runuser`, `su`, or another wrapper that re-establishes credentials is subject to the wrapper's own policy rules rather than to the daemon-helper pair. The mitigation form is the same in shape, but the source domain in the CIL allow names the wrapper's domain rather than the daemon's.
- A daemon under `NoNewPrivileges=yes` plus `User=` (a user-domain service) escapes the kernel-NNP-transition path through `init_t` and runs in a user-domain transition pattern from the start. The inter-domain class still applies, but the source domain in the AVC and in the mitigation is the user domain rather than `<svc>_t`.

## See also

- [NNP and SELinux transition trap](./nnp-selinux-transition-trap.md) — The boot-time sibling class. Same kernel mechanism (`process2 nnp_transition`), same mitigation shape (priority-400 site-local CIL extension), but the source domain is `init_t` and the failure manifests at boot rather than at first helper-spawn. Topic roles that ship NNP drop-ins for multi-helper daemons typically need both classes' allow rules in the same CIL module.
- [SELinux custom CIL bootstrap](../reference/foundation/selinux-cil-bootstrap.md) — The Foundation layer that provisions the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` mechanism this mitigation rides on.
- [Audit and logging baseline](../reference/foundation/audit-logging-baseline.md) — The audit pipeline that records the `process2 nnp_transition` AVC fingerprint described above; the four-tool diagnosis loop documented there is the canonical operator workflow for confirming the class on an affected host.
