<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# GnuPG pinentry D-Bus session-bus surface

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents two narrowly-scoped gaps in the stock SELinux targeted policy on Fedora 44 that affect the GnuPG signing pipeline when the operator login is mapped to the confined SELinux user `staff_u` and the desktop ships `pinentry-gnome3` (from the `pinentry` package family) together with `gcr3` for the GNOME Keyring `SystemPrompter` integration. The deliverable is a single topic-owned CIL module loaded at priority 400 carrying exactly two `(allow ...)` rules; one rule keeps the GUI passphrase prompt operational, the other closes a dontaudit-suppressed lazy-spawn process-inheritance triple. The end-state ships **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/gnupg/`, **no** polkit rule, **no** sudoers fragment, **no** desktop-entry override, **no** new SELinux type, **no** new SELinux attribute binding, **no** file-context mapping, and **no** `restorecon` invocation; the artefact-shape negatives are stated here once because they are load-bearing for the role's idempotence claim and for the rollback posture.

This topic does **not** cover the GnuPG configuration model (`~/.gnupg/gpg.conf`, `~/.gnupg/gpg-agent.conf` beyond the `pinentry-program` selection line, key-store layout, key-generation workflows), signing-policy decisions at the version-control layer (the `git` `commit.gpgsign` and `tag.gpgsign` settings, signed-tag policy), the `gcr-prompter` D-Bus interface specification (`org.gnome.keyring.SystemPrompter` methods, signals, properties), the `pinentry-curses` / `-tty` / `-qt` / `-gtk2` alternatives (operator on those backends is out of scope), the `staff_u` user-mapping deployment decision (the prerequisite Foundation layer owns this), the `gpg-agent` cache-time tuning (`default-cache-ttl`, `max-cache-ttl`), the pinentry-cache integration with GNOME Keyring, the `domain_can_mmap_files` SELinux boolean (orthogonal — no relation to the two allow rules in this topic), and the `systemd-analyze security` numeric score model (this topic ships no systemd service unit and the score model does not apply).

## End-state configuration

The end-state ships exactly one operator-installed file: a CIL source under `/root/`. The source is loaded into the system's targeted-policy module store at priority 400 via `semodule -X 400 -i`. The two allow rules in the source patch two pre-existing stock-policy gaps; both source types (`gpg_pinentry_t`, `gpg_t`) and both target types (`session_dbusd_tmp_t`, `gpg_agent_t`) are stock-policy types shipped by the targeted policy on Fedora 44 and are not declared by this module.

### Topic identity

The pipeline under hardening is the chain a desktop operator triggers when running an interactive signing operation such as `gpg --clearsign`, `gpg --decrypt`, or a signed-commit invocation at the version-control layer. The operator's interactive shell (`staff_t` under the `staff_u` user-mapping) invokes `gpg`, which lazy-spawns `gpg-agent` via a SELinux domain-transition (`gpg_t → gpg_agent_t`); `gpg-agent` in turn execs the configured pinentry helper (`/usr/bin/pinentry-gnome3` per the operator's `~/.gnupg/gpg-agent.conf` `pinentry-program` line), which transitions to `gpg_pinentry_t` and renders the passphrase prompt for the active desktop session.

The end-state depends on three stock packages on Fedora 44: `gnupg2` (provides `/usr/bin/gpg`, `/usr/bin/gpg-agent`, `/usr/bin/gpgconf` — the SELinux types `gpg_t` and `gpg_agent_t` are bound to these binaries by stock-policy file_contexts), `pinentry-gnome3` (provides `/usr/bin/pinentry-gnome3`, the GUI helper bound to `gpg_pinentry_t` via stock-policy file_contexts), and `gcr3` (provides the `gcr-prompter` D-Bus service that `pinentry-gnome3` 1.3.x delegates to via the `org.gnome.keyring.SystemPrompter` interface). The topic does not require an additional package install; the role's preflight asserts the three packages are present and aborts fail-fast on any missing entry. The topic is out of scope on hosts using `pinentry-curses`, `pinentry-tty`, `pinentry-qt`, or `pinentry-gtk2` as the configured pinentry helper — those backends do not delegate to `gcr-prompter` over the per-user session bus and do not exercise the functional gap; an operator on those backends does not need this topic, and the role's preflight detects the disposition and exits with a clear message.

### Topic shape — two-rule stock-policy gap-patch

This topic occupies a structurally different shape than the system-services topics in this tree. The end-state is **not** "a daemon runs in a hardened domain". The end-state is a single CIL module loaded at priority 400 that contains exactly two `(allow ...)` rules — one functional, one audit-cosmetic — and patches two pre-existing stock-policy gaps without declaring any new SELinux types, without binding any new attributes, without shipping a systemd unit or drop-in, without altering file labels, and without restarting any service. Every downstream subsection is framed by this structural fact: the modify stage is one `semodule -X 400 -i` call, the verify discipline asserts the two allow surfaces are present in the loaded policy, and the rollback action is one `semodule -X 400 -r` call.

### Functional rule

The first allow rule patches the gap that breaks the GUI passphrase prompt under `staff_u`-mapped logins. With `pinentry-gnome3` 1.3.x (paired with `gcr3` 3.41.x or later), the helper no longer renders the passphrase UI directly via GTK; it delegates to `gcr-prompter` over the per-user D-Bus session bus by calling the `org.gnome.keyring.SystemPrompter` interface. The `libdbus` async worker thread (`comm="pool-0"`) opens the per-user session-bus socket at `/run/user/${uid}/bus` (SELinux type `session_dbusd_tmp_t`) in read-write mode. Stock targeted policy on Fedora 44 ships **no** allow on `gpg_pinentry_t × session_dbusd_tmp_t : sock_file write` for the `staff_u → staff_r → staff_t` user-mapping path. The open returns `EACCES`; the helper aborts the D-Bus path silently and falls back to a curses-based passphrase prompt on the controlling TTY of the calling `gpg` process. The functional symptom is invisible in the GUI: there is no error dialog, no error in the user journal beyond the SELinux AVC itself, and the only operator-visible signal is the unexpected curses prompt on the terminal that issued the signing operation.

### Audit-cosmetic rule

The second allow rule patches the audit-cosmetic gap that fires on every lazy spawn of `gpg-agent` from a `staff_u`-mapped `gpg` invocation. When `gpg` (running under `gpg_t`) execs `gpg-agent`, the kernel performs a SELinux domain-transition `gpg_t → gpg_agent_t` and evaluates three process-inheritance permissions: `noatsecure` (whether to clear the `AT_SECURE` auxiliary-vector bit, which controls glibc's `__libc_enable_secure` sanitizer for `LD_*`/`NLSPATH`/etc. — `DISPLAY` and `DBUS_SESSION_BUS_ADDRESS` are **not** on glibc's sanitizer list, so the agent spawns and connects to the operator's session bus regardless of this permission), `rlimitinh` (resource-limit inheritance across the transition), and `siginh` (signal-handler and signal-mask inheritance). Stock targeted policy on Fedora 44 marks the triple as `dontaudit` for the `staff_u → staff_r → staff_t → gpg_t → gpg_agent_t` chain, so the records are silent under the default `semodule -B` build state and visible only when the operator runs `semodule -DB` to rebuild the policy with dontaudit suppressions disabled. The functional impact of leaving the triple as a denial is zero: the agent-spawn pathway works either way; the rule purely closes the diagnostic noise that an operator running a `semodule -DB` audit pass would otherwise see.

### Custom CIL module

Path: `/root/gnupg_pinentry_dbus.cil`. Loaded at priority 400 via `semodule -X 400 -i /root/gnupg_pinentry_dbus.cil`.

```cil
;; gnupg_pinentry_dbus.cil — patches two stock-policy gaps on Fedora 44
;; that affect the GnuPG signing pipeline under staff_u user-mapping.
;;
;; Rule 1 (functional): pinentry-gnome3 1.3.x delegates the passphrase
;; prompt to gcr-prompter over the per-user D-Bus session bus
;; (org.gnome.keyring.SystemPrompter). Stock policy lacks the write
;; allow on the session-bus socket for gpg_pinentry_t under staff_u,
;; so the helper falls back to a curses prompt on the calling TTY.
(allow gpg_pinentry_t session_dbusd_tmp_t (sock_file (write)))
;;
;; Rule 2 (audit-cosmetic): the gpg → gpg-agent domain-transition
;; triple { noatsecure rlimitinh siginh } is dontaudit-suppressed in
;; stock policy. Functionally benign; the explicit allow closes the
;; diagnostic noise visible under `semodule -DB`.
(allow gpg_t gpg_agent_t (process (noatsecure rlimitinh siginh)))
```

The module body declares no `(type ...)`, no `(typeattributeset ...)`, no `(roletype ...)`, no `(typetransition ...)`, and no `(typepermissive ...)`. The `transition` permission of class `process` between `gpg_t` and `gpg_agent_t` is **already** allowed by stock policy and is intentionally not re-stated in the module — the merged display from `sesearch -A -s gpg_t -t gpg_agent_t -c process` after the module loads consequently shows a single line of the form `allow gpg_t gpg_agent_t:process { noatsecure rlimitinh siginh transition };`, where `transition` is contributed by stock and the other three are contributed by this module.

### Custom CIL deploy

The modify-stage action sequence runs in this order:

1. Pre-test that the two allow surfaces are absent in the currently loaded policy: `sesearch -A -s gpg_pinentry_t -t session_dbusd_tmp_t -c sock_file -p write` returns empty, and `sesearch -A -s gpg_t -t gpg_agent_t -c process -p noatsecure` (and the same call repeated with `-p rlimitinh` and `-p siginh`) each return empty. The role aborts as a no-op (return code reported to the operator, not as a failure) when both allow surfaces are already present in the loaded policy, on the assumption that a future stock-policy update has shipped the equivalent grants and the workaround is no longer required.
2. If the module `gnupg_pinentry_dbus` is already installed at priority 400, copy the previously installed CIL source from `/var/lib/selinux/targeted/active/modules/400/gnupg_pinentry_dbus/cil` to `/root/gnupg_pinentry_dbus.cil.pre-reinstall` as a re-install audit anchor.
3. Write the CIL source at `/root/gnupg_pinentry_dbus.cil` with explicit `0644 root:root`.
4. `semodule -X 400 -i /root/gnupg_pinentry_dbus.cil`.
5. Post-load re-probe: the four `sesearch` calls of step 1 must now each return a non-empty result.

The role does **not** call `restorecon` (no file labels are altered), does **not** call `semanage fcontext` (no file-context mappings are added), does **not** restart `gpg-agent`, and does **not** restart any system service. SELinux access checks evaluate the loaded policy on each system call, so a running `gpg-agent` picks up the new allow rules without restart and the operator does not need to invoke `gpgconf --kill gpg-agent` after the deploy — the next signing operation observes the new policy automatically. No host reboot is required.

The `staff_u → sysadm_r → sysadm_t` role-switch surface that the SELinux toolchain transits through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md). The priority-400 publish path the CIL module rides on is documented in [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md).

### File modes

This topic ships exactly one operator-installed file:

| Path | Mode | Owner:Group | SELinux type |
|---|---|---|---|
| `/root/gnupg_pinentry_dbus.cil` | `0644` | `root:root` | (host-default for `/root/`, typically `admin_home_t`) |

The explicit `0644` is required because the operator UMASK 0027 would otherwise produce `0640`, and a re-run of the role from a `staff_sudo_t` context (plain `sudo` from a `staff_u`-mapped login that forgot the role-switch) would fail to read the source. The reflex is documented in [UMASK 0027](../foundation/umask.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both run from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_gnupg_pinentry_dbus/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`rpm -q gnupg2 pinentry pinentry-gnome3 gcr3`), the operator-configured pinentry helper (`grep -E '^pinentry-program' /home/<user>/.gnupg/gpg-agent.conf`), the operator's runtime SELinux context via `id -Z` (the canonical applicability anchor — `staff_u:staff_r:staff_t` is the matching mapping), the priority-400 module slot via `semodule -lfull | grep -wE '^[ ]*400.*gnupg_pinentry_dbus`, the functional-rule allow surface via `sesearch -A -s gpg_pinentry_t -t session_dbusd_tmp_t -c sock_file -p write`, the audit-cosmetic-rule allow surface via `sesearch -A -s gpg_t -t gpg_agent_t -c process` filtered for the three permissions `noatsecure`, `rlimitinh`, `siginh`, and the AVC stream since boot via `ausearch -m AVC,USER_AVC -ts boot` filtered for `gpg_pinentry_t.*session_dbusd_tmp_t`. The `semodule`, `sesearch`, and `ausearch` queries are gated behind a `sysadm_t` domain check and reported as `SKIP needs sysadm_t` from a `staff_t` shell. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_gnupg_pinentry_dbus/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `gnupg_pinentry_dbus` module installed at priority 400 | `yes` |
| Functional allow `gpg_pinentry_t × session_dbusd_tmp_t : sock_file write` present | `yes` |
| Audit-cosmetic allow `gpg_t × gpg_agent_t : process noatsecure` present | `yes` |
| Audit-cosmetic allow `gpg_t × gpg_agent_t : process rlimitinh` present | `yes` |
| Audit-cosmetic allow `gpg_t × gpg_agent_t : process siginh` present | `yes` |
| Functional-class AVC denials since boot | `0` |

Liveness probes are not part of the canonical Soll/Ist comparison; the policy-store reads are sufficient. Where any liveness inspection is needed, the verify uses the `[[ -d /proc/${pid} ]]` form rather than `kill -0`, because `kill -0` against a foreign-uid PID from a `staff_t` shell returns `EPERM` rather than `ESRCH` and would misreport a live process as dead. The verify does not invoke a `semodule -DB` dontaudit-bypass sandwich. The audit-cosmetic class is asserted only via `sesearch` of the loaded policy (the three triple permissions visible). An operator who wants to confirm the dontaudit triple no longer fires under bypass runs the manual sandwich `semodule -DB && gpgconf --kill gpg-agent && gpg --clearsign … && ausearch … && semodule -B` out-of-band; the verify does not trigger this path because `semodule -DB` is a heavyweight policy-rebuild side effect (a full policy reload plus an audit-log volume spike) that does not belong in an unattended verify run.

### AVC posture

The AVC posture has two parts. On a soaked, `staff_u`-mapped host that has issued at least one interactive signing operation since boot **without** the workaround applied, the audit stream carries one or more `denied  { write }` records of class `gpg_pinentry_t × session_dbusd_tmp_t : sock_file`, each with `comm="pool-0"` (the `libdbus` async worker thread name) and `tcontext` resolving to the per-user session-bus socket under `/run/user/${uid}/`. These are the records the functional rule closes. On the same workload with the workaround applied, the same filter returns an empty result. The audit-cosmetic class produces no records under the default `semodule -B` build state regardless of whether the explicit allow is loaded or not (stock dontaudit-suppression hides the records); the audit-cosmetic-class verification is `sesearch`-based against the loaded policy, not `ausearch`-based against the audit stream.

Drift signals on an applied host: any fresh `denied  { write }` record of class `gpg_pinentry_t × session_dbusd_tmp_t : sock_file` indicates the functional rule has been rolled back or a stock-policy update has shipped a `neverallow` that pre-empts the priority-400 grant; either case is operator-investigation. A surge in `denied` records of any other class involving `gpg_pinentry_t`, `gpg_t`, or `gpg_agent_t` is **not** drift caused by this topic and is investigated independently — most commonly a `pinentry-gnome3` upstream version bump that introduces a new D-Bus interaction not covered by the functional rule.

The four-tool diagnosis loop (`ausearch`, `audit2why`, `audit2allow`, `sealert`) for the AVC stream is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

The role's modify stage is idempotent. The CIL source is pushed via `ansible.builtin.copy` from the role's `files/` directory and converges on byte-for-byte content match. The `semodule -X 400 -i` install task is wrapped in a `creates: /var/lib/selinux/targeted/active/modules/400/gnupg_pinentry_dbus/cil` guard, so a re-run on a host already carrying the module reports `changed=false`. The role runs no `restorecon`, no `semanage fcontext`, no `systemctl restart`, and no handler. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

Recovery is a single-stage rollback. The byte-exact form:

```bash
sudo -r sysadm_r -t sysadm_t semodule -X 400 -r gnupg_pinentry_dbus
```

Post-rollback, `sesearch -A -s gpg_pinentry_t -t session_dbusd_tmp_t -c sock_file -p write` returns empty and `sesearch -A -s gpg_t -t gpg_agent_t -c process` returns the stock-only `transition` line. The module slot at `/var/lib/selinux/targeted/active/modules/400/gnupg_pinentry_dbus/` is removed. The CIL source at `/root/gnupg_pinentry_dbus.cil` is **not** removed by `semodule -r` (it is the operator's source artefact, not part of the module slot); operators who want to also remove the source file do so explicitly with `rm -f /root/gnupg_pinentry_dbus.cil`. Boot-failure risk for this topic is structurally zero — the two allow rules grant access on user-process-side D-Bus sock-file writes and on a user-process-side domain-transition triple; neither surface is reachable from `init_t` and neither rule introduces an `nnp_transition` constraint or a `mount_t` namespace effect.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

This topic does not cross-link any pattern article. The two allow rules patch narrowly-scoped gaps on user-process-side SELinux types (`gpg_pinentry_t`, `gpg_t`) and do not exercise the kernel NoNewPrivileges-transition constraint, the systemd `SystemCallFilter` privilege-drop sequence, the systemd `PrivateMounts` implicit-enable, the systemd `ReadWritePaths` runtime race, the cross-user liveness-probe trap, or any other cross-cutting hardening pattern documented in this tree. The deploy ships no systemd unit, no drop-in, no file-label change, and introduces no new SELinux type — the priority-400 module mechanism described in the Foundation layer carries the entire deploy.
