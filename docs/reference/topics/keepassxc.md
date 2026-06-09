<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# keepassxc

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Application identity

KeePassXC is a desktop password manager packaged on Fedora 44 or later as the `keepassxc` package. The stock package ships three binaries on every install: `/usr/bin/keepassxc` (the GUI entrypoint), `/usr/bin/keepassxc-cli` (the headless command-line tool), and `/usr/bin/keepassxc-proxy` (the browser-extension Native-Messaging bridge). The deploy profile in this topic relabels all three binaries unconditionally; an operator who does not configure the browser-extension integration still receives the proxy binary's relabel for completeness, since the stock fcontext anchor is path-based and not gated on actual use of the proxy.

The application stores its per-user configuration under `~/.config/keepassxc/` (label `config_home_t`) and its disk cache under `~/.cache/keepassxc/` (label `cache_home_t`). Database files live at an operator-chosen path under the user's home directory; the topic-owned fcontext anchor is the regex `/home/<user>/keepass(/.*)?\.kdbx(\.backup)?`, which matches both the canonical `*.kdbx` form and the auto-saved `*.kdbx.backup` form at any depth under the operator-chosen `keepass/` directory.

The plugin tree under `/usr/lib64/keepassxc/`, the desktop entry under `/usr/share/applications/`, the icon set under `/usr/share/icons/hicolor/`, and the man pages under `/usr/share/man/man1/` are part of the stock package layout but are not relabeled by this topic. The `keepassxc` package depends on `pcsc-lite` and `pcsc-lite-ccid` via the SONAME `libpcsclite.so.1` (eager `DT_NEEDED` on the GUI binary); the runtime connect to `/run/pcscd/pcscd.comm` is lazy and is only exercised when an operator configures a YubiKey-backed Challenge-Response key, which is out of scope here. The implication for stock-package retention is that `dnf remove pcsc-lite` is blocked by the SONAME dependency on `keepassxc`; operators considering a removal pass on smartcard packages must keep the SONAME provider in place as long as `keepassxc` is installed.

## Scope

This topic documents the KeePassXC user-application sub-domain plus file-type-cut surface. The end-state ships three custom SELinux types (`keepassxc_t`, `keepassxc_exec_t`, `keepassxc_db_t`) across **three** topic-owned CIL modules loaded at priority 400, four `semanage fcontext` declarations (three binaries plus one database-tree regex), and a four-target `restorecon` scope. The three CIL modules are deliberately separate so each can be loaded or rolled back on its own:

- `keepassxc_extras` declares the sub-domain, the entrypoint transition, the role bindings, and the database-access surface — including the enforced file-type cut.
- `keepassxc_dbtype_autotrans` carries a single `type_transition` that keeps the database label stable across the application's atomic save.
- `keepassxc_spawn_isolation` carries a `type_transition` plus two allows that keep the sub-domain from leaking into helper processes the application launches.

The end-state ships **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/keepassxc/`, **no** polkit rule, **no** sudoers fragment, and **no** desktop-entry override; the artefact-shape negatives are stated here once because they are load-bearing for the role's idempotence claim and for the rollback posture.

The runtime domain `keepassxc_t` runs in a permissive discovery posture: a `typepermissive` declaration logs denials sourced from the domain without enforcing them, so the application stays functional while its required allow surface is enumerated. A later operator-policy lockdown that removes the `typepermissive` declaration and replaces the discovery posture with an explicit per-cluster allow-set is recognised as a follow-up but is **not** in scope here. The file-type cut described under §"Topic shape" is fully enforced from the moment the modules load, regardless of the `typepermissive` flag.

The operator-chosen database directory is treated as a crypto-material vault with the database-file regex as the only topic-owned label. Other crypto-material under the same directory (`*.pfx`, `*.pem`, `*.gpg`, SSH key backups, TOTP exports) is not relabeled by this topic and remains `user_home_t`; an operator who wants those files behind the same enforced cut extends the fcontext regex as operator-policy outside this topic. The role does **not** create the database directory if absent (a missing directory is a fail-fast on deploy: the operator's first action is to migrate the database into the directory). The role does **not** modify file modes on the database files; mode management is operator-controlled.

This topic does **not** cover the YubiKey Challenge-Response integration via `pcsc-lite` (the daemon connect path is lazy and out of scope), the KeePassXC browser-extension Native-Messaging integration, the database file-format internals, the Auto-Type X11/Wayland fallback discipline, the secret-service DBus integration with GNOME Keyring or KWallet, the `keepassxc-cli` headless backup workflow, the adjacent crypto-material file types under the same database directory, the deferred lockdown body, the `domain_can_mmap_files` SELinux boolean and its acceptance rationale, or the `systemd-analyze security` numeric score model (the application has no systemd service unit; the score model does not apply).

## Topic shape

This topic occupies a structurally different shape than the system-services topics in this tree. The end-state is **not** "the daemon runs in a hardened domain" — there is no daemon; the application is user-launched per session. The end-state is a custom runtime sub-domain plus an enforced data-file cut, held coherent by two companion transition rules. Four structural facts carry the design.

**Sub-domain entry.** A custom SELinux runtime domain `keepassxc_t` is entered automatically when the user launches any of the three binaries from a `staff_t` or `sysadm_t` shell, via a `typetransition` keyed on the `keepassxc_exec_t` entrypoint label. The domain's attribute stem is deliberately narrow — `domain`, `userdomain`, `unpriv_userdomain`, with the `staff_usertype` attribute **omitted** — so the sub-domain does not silently inherit the full `staff_t` allow surface; the explicit database-access rules are its grant. A `(typepermissive keepassxc_t)` declaration places the domain in a discovery posture: any AVC fired with the domain as **source** is logged `permissive=1` and not enforced.

**Enforced file-type cut.** A custom file-type `keepassxc_db_t` is mapped onto the database files via `semanage fcontext`. The type is anchored to the `file_type` attribute **only** — explicitly **not** to `user_home_type` and **not** to `non_security_file_type`. As a consequence, no stock allow rule matches `staff_t × keepassxc_db_t × file × *`, and any read or write attempt from an unconfined `staff_t` shell hits an enforced denial regardless of the runtime domain's permissive flag. The sub-domain's permissive flag does not weaken the cut: `permissive=1` only affects records whose `scontext` is the permissive type (`keepassxc_t`); it has no effect on records whose `scontext` is `staff_t` and whose `tcontext` is `keepassxc_db_t`. The cut is therefore enforced from the moment the modules load, while the runtime domain itself stays in a discovery posture.

**Label durability across atomic save.** KeePassXC saves a database update by writing a temporary file in the database directory and then `rename(2)`-ing it onto the target path. The temporary file inherits `user_home_t` from its parent directory, and `rename(2)` does not trigger an fcontext relabel — so static fcontext plus `restorecon` alone would let a saved database silently revert to `user_home_t` and lose the cut. A `(typetransition keepassxc_t user_home_t file keepassxc_db_t)` closes that: every file `keepassxc_t` creates in a `user_home_t` directory receives `keepassxc_db_t`. This dynamic relabel is the complement to the static fcontext labeling, which covers only files at rest.

**Domain containment of helper spawns.** When `keepassxc_t` executes a helper binary — for example, opening a stored entry URL launches the browser through `/usr/bin/flatpak`, which execs `bwrap` and the browser binary — the spawned process tree would inherit `keepassxc_t`. Combined with the label-durability rule above, that is a hazard: a helper running as `keepassxc_t` creates files across `user_home_t` directories (a browser profile tree), and the `type_transition` would relabel every one of them `keepassxc_db_t` — a cross-tree mislabel cascade. A `(typetransition keepassxc_t bin_t process staff_t)` keeps the sub-domain scoped to KeePassXC itself: any `bin_t` exec from `keepassxc_t` transitions back to `staff_t`, so the helper chain runs entirely under `staff_t` and the label-durability rule does not fire for the files those helpers create. The label-durability rule and the spawn-containment rule are coupled by design — the first makes the mislabel possible, the second prevents it — which is why both ship as part of the canonical end-state.

## End-state configuration

The end-state ships three CIL sources under `/root/`, four `semanage fcontext` declarations, and a four-target `restorecon` scope. The three CIL sources are the only operator-installed files. No drop-in, no unit, no configuration file under `/etc/`. Pre-deploy the binaries carry the stock `bin_t` label and database files carry `user_home_t`; post-deploy the binaries carry `keepassxc_exec_t` and database files carry `keepassxc_db_t`.

### Custom CIL modules

Three separate CIL modules load at priority 400, each from its own source under `/root/`. They are kept apart so each can be loaded or rolled back on its own; the type identifiers a module references are resolved at link time across all priority-400 modules in the store.

#### keepassxc_extras

Path: `/root/keepassxc_extras.cil`. Declares the three custom types, the role bindings, the entrypoint transition, and the database-access surface.

```cil
(type keepassxc_t)
(type keepassxc_exec_t)
(type keepassxc_db_t)

(typepermissive keepassxc_t)

(typeattributeset domain (keepassxc_t))
(typeattributeset userdomain (keepassxc_t))
(typeattributeset unpriv_userdomain (keepassxc_t))
(typeattributeset exec_type (keepassxc_exec_t))
(typeattributeset file_type (keepassxc_exec_t))
(typeattributeset file_type (keepassxc_db_t))

(roletype staff_r keepassxc_t)
(roletype sysadm_r keepassxc_t)

(typetransition staff_t keepassxc_exec_t process keepassxc_t)
(typetransition sysadm_t keepassxc_exec_t process keepassxc_t)

(allow staff_t keepassxc_t (process (transition)))
(allow staff_t keepassxc_exec_t (file (execute getattr open read map ioctl lock execute_no_trans)))
(allow keepassxc_t keepassxc_exec_t (file (entrypoint execute getattr open read map ioctl lock)))
(allow sysadm_t keepassxc_t (process (transition)))
(allow sysadm_t keepassxc_exec_t (file (execute getattr open read map ioctl lock execute_no_trans)))
(allow sysadm_t keepassxc_exec_t (file (relabelfrom relabelto)))

(allow keepassxc_t keepassxc_db_t (file (read write open getattr setattr lock create unlink rename ioctl append link watch)))
(allow keepassxc_t keepassxc_db_t (dir (read write open getattr search add_name remove_name)))
(allow sysadm_t keepassxc_db_t (file (read write getattr setattr open ioctl lock create unlink rename relabelfrom relabelto)))
(allow sysadm_t keepassxc_db_t (dir (read write getattr search open add_name remove_name relabelfrom relabelto)))
```

#### keepassxc_dbtype_autotrans

Path: `/root/keepassxc_dbtype_autotrans.cil`. A single `type_transition` so that any file `keepassxc_t` creates in a `user_home_t` directory receives `keepassxc_db_t` — the dynamic relabel that survives the application's write-temp-then-`rename(2)` save (see §"Topic shape").

```cil
(typetransition keepassxc_t user_home_t file keepassxc_db_t)
```

#### keepassxc_spawn_isolation

Path: `/root/keepassxc_spawn_isolation.cil`. A `type_transition` that kicks any `bin_t` exec from `keepassxc_t` back to `staff_t`, plus the two allows that kick-back requires, so a helper the application launches (a browser through `flatpak`/`bwrap`, `xdg-open`, and similar) does not inherit `keepassxc_t` (see §"Topic shape").

```cil
(typetransition keepassxc_t bin_t process staff_t)
(allow keepassxc_t bin_t (file (execute)))
(allow keepassxc_t staff_t (process (transition rlimitinh siginh noatsecure)))
```

Stock targeted policy on Fedora 44 ships none of the three custom types, and the role's preflight asserts that `seinfo -t` returns empty for all three before installing the modules. The runtime domain is bound to `staff_r` and `sysadm_r` via `roletype`; spawn from either role transits into `keepassxc_t` automatically through the two entrypoint `typetransition` rules. The attribute stem of `keepassxc_t` is `domain`, `userdomain`, `unpriv_userdomain` — `staff_usertype` is omitted, so the domain does not inherit the broad `staff_t` allow surface and relies on the explicit rules instead. The `keepassxc_db_t` type carries **only** the `file_type` attribute — no `user_home_type`, no `non_security_file_type` — which is the structural choice that makes `staff_t × keepassxc_db_t : file *` a stock-policy miss-path.

Within `keepassxc_extras`, the spawn-cluster allow rules cover the transition from `staff_t` and `sysadm_t` into `keepassxc_t`, the entrypoint exec on `keepassxc_exec_t`, and the `sysadm_t` relabel grant on the entrypoint label that lets a `restorecon` invocation from the admin pathway relabel the binaries. The two `keepassxc_t × keepassxc_db_t` rules cover the file-class read/write surface — including `watch` for the application's inotify watch on its own database — and the dir-class search-and-list surface the application needs to open and update its database; the database directory itself remains `user_home_t`. The two `sysadm_t × keepassxc_db_t` rules cover the admin pathway: a backup task under `sudo -r sysadm_r -t sysadm_t` can read, write, relabel, and rename the database files.

### Custom CIL deploy

The modify-stage action sequence runs in this order:

1. Pre-test that no `keepassxc_t`, `keepassxc_exec_t`, or `keepassxc_db_t` type exists in stock policy (`seinfo -t | grep -wE 'keepassxc_t|keepassxc_exec_t|keepassxc_db_t'` returns empty); the role aborts with a clear message if any of the three names already exists, since collision with a future stock-policy delivery requires manifest revision.
2. Pre-flight assertion that the operator-chosen database directory exists.
3. Write the three CIL sources under `/root/` with explicit `0644 root:root`.
4. Load the three modules: `semodule -X 400 -i /root/keepassxc_extras.cil /root/keepassxc_dbtype_autotrans.cil /root/keepassxc_spawn_isolation.cil`. `keepassxc_extras` must be present in the same transaction or earlier, because the two companion modules reference `keepassxc_t`, `keepassxc_db_t`, and `bin_t`; SELinux resolves those references at link time across all priority-400 modules in the store.
5. Four `semanage fcontext -a` calls (or `-m` on idempotent re-run).
6. Three single-file `restorecon -v` calls plus one recursive `restorecon -Rv` over the database directory.

The role does **not** load a kernel module, does **not** edit `/etc/selinux/config`, does **not** toggle a SELinux boolean, and does **not** invoke `setsebool`. There is no host reboot and no role-side service restart — the application is user-launched per session and the new SELinux runtime domain takes effect for **new** processes via the typetransition rule. Existing keepassxc processes started before the deploy continue under their pre-deploy domain (typically `staff_t`). The operator restarts the keepassxc GUI and any running `keepassxc-cli` invocation to pick up the new domain.

The `staff_u → sysadm_r → sysadm_t` role-switch surface that the SELinux toolchain transits through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md). The priority-400 publish path the CIL module rides on is documented in [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md).

### fcontext mappings

```bash
semanage fcontext -a -t keepassxc_exec_t '/usr/bin/keepassxc'
semanage fcontext -a -t keepassxc_exec_t '/usr/bin/keepassxc-cli'
semanage fcontext -a -t keepassxc_exec_t '/usr/bin/keepassxc-proxy'
semanage fcontext -a -t keepassxc_db_t '/home/<user>/keepass(/.*)?\.kdbx(\.backup)?'
```

The role's idempotence reflex falls back to `semanage fcontext -m -t …` when `semanage fcontext -l` shows the rule is already present; a clean re-run on a host already in the end-state therefore reports `changed=false` from `community.general.sefcontext`. The database regex is anchored to the operator-chosen `/home/<user>/keepass/` directory; an operator whose database lives at a different path edits the role variable `topic_keepassxc_database_dir` in `defaults/main.yml` accordingly. The regex matches both the canonical `*.kdbx` form and the auto-saved `*.kdbx.backup` form, and matches at any depth under the directory.

### restorecon scope

Three single-file `restorecon -v` invocations on the binaries plus one recursive `restorecon -Rv` over the operator-chosen database directory. The expected before-and-after labels:

| Path | Before | After |
|---|---|---|
| `/usr/bin/keepassxc` | `bin_t` | `keepassxc_exec_t` |
| `/usr/bin/keepassxc-cli` | `bin_t` | `keepassxc_exec_t` |
| `/usr/bin/keepassxc-proxy` | `bin_t` | `keepassxc_exec_t` |
| `/home/<user>/keepass/*.kdbx{,.backup}` | `user_home_t` | `keepassxc_db_t` |

Files under the operator-chosen `keepass/` directory that do not match the regex (for example, an Aegis-TOTP export under `keepass/aegis/`) are not relabeled and remain `user_home_t`.

`restorecon` labels the database files already present at deploy time. Files the application writes afterwards keep `keepassxc_db_t` through the `keepassxc_dbtype_autotrans` `type_transition`, because the write-temp-then-`rename(2)` save would otherwise strip the label back to `user_home_t` (see §"Topic shape"). The static fcontext set and the dynamic transition are complementary: the former covers files at rest, the latter covers files the application creates.

### Database directory hygiene

The operator-chosen database directory is treated as a crypto-material vault with the database-file regex as the only topic-owned label. Other crypto-material under the same directory (`*.pfx`, `*.pem`, `*.gpg`, SSH key backups, TOTP exports) is not relabeled by this topic and remains `user_home_t`. An operator who wants those files behind the same enforced cut extends the fcontext regex as operator-policy outside this topic. The role does not create the database directory if absent (a missing directory is a fail-fast on deploy). The role does not modify file modes on the database files; mode management is operator-controlled.

### File modes

The three operator-installed files are the CIL sources under `/root/`:

| Path | Mode | Owner:Group | SELinux type |
|---|---|---|---|
| `/root/keepassxc_extras.cil` | `0644` | `root:root` | (host-default for `/root/`) |
| `/root/keepassxc_dbtype_autotrans.cil` | `0644` | `root:root` | (host-default for `/root/`) |
| `/root/keepassxc_spawn_isolation.cil` | `0644` | `root:root` | (host-default for `/root/`) |

The explicit `0644` on each source is required because the operator UMASK 0027 would otherwise produce `0640`, and a re-run of the role from a `staff_sudo_t` context (plain `sudo` from a `staff_u`-mapped login that forgot the role-switch) would fail to read the source. The reflex is documented in [UMASK 0027](../foundation/umask.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both run from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_keepassxc/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`rpm -q keepassxc`), the SELinux contexts of the three binaries (`ls -laZ`), the SELinux contexts of the database directory and any `*.kdbx` glob entries under it, the live runtime domain of any active `keepassxc` GUI process via `cat /proc/${pid}/attr/current` (using the `[ -d /proc/${pid} ]` liveness pattern, never `kill -0`), the presence of the three custom types via `seinfo -t | grep -wE 'keepassxc_t|keepassxc_exec_t|keepassxc_db_t'`, the three loaded modules at priority 400 via `semodule -lfull | grep -w keepassxc`, the typepermissive marker via `semanage permissive -l | grep -w keepassxc_t`, the two companion `type_transition` rules via `sesearch -T -s keepassxc_t -t user_home_t -c file` and `sesearch -T -s keepassxc_t -t bin_t -c process`, a sweep for `keepassxc_db_t`-labeled files outside the operator-chosen database directory (expected: none), the four fcontext entries via `semanage fcontext -l`, and the AVC posture context via `sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot | grep -E '(keepassxc|keepassxc_t|keepassxc_exec_t|keepassxc_db_t)'`. The `seinfo`, `semodule`, `semanage permissive`, `sesearch`, `semanage fcontext`, and `ausearch` queries are gated behind a `sysadm_t` domain check and reported as `SKIP needs sysadm_t` from a `staff_t` shell. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_keepassxc/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `keepassxc_t` present | yes |
| `keepassxc_exec_t` present | yes |
| `keepassxc_db_t` present | yes |
| `keepassxc_extras` loaded at priority 400 | yes |
| `keepassxc_dbtype_autotrans` loaded at priority 400 | yes |
| `keepassxc_spawn_isolation` loaded at priority 400 | yes |
| `type_transition keepassxc_t user_home_t:file` → `keepassxc_db_t` | present |
| `type_transition keepassxc_t bin_t:process` → `staff_t` | present |
| `typepermissive keepassxc_t` | yes (the deploy-state marker; an operator-policy lockdown would set this expectation to `no` via the role variable) |
| fcontext for the three binaries | `keepassxc_exec_t` |
| fcontext for the database regex | `keepassxc_db_t` |
| `keepassxc_db_t`-labeled files outside the database directory | 0 |
| live runtime domain of a running GUI process | substring `keepassxc_t` in `/proc/${pid}/attr/current` |

Liveness is checked through `[[ -d /proc/${pid} ]]`. From a `staff_t` shell, `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the directory-existence form is ownership-independent. The runtime-domain assertion checks for the substring `keepassxc_t` rather than full-string equality across the host-specific MCS range.

The verify performs a leverage-proof read against the canonical database file from the verify script's own context and asserts the expected outcome:

- When invoked from `staff_t` (the canonical user-shell verify path), the read must return `Permission denied`. A successful read is `FAIL`. The verify treats the expected denial as a positive end-state assertion: a `staff_t`-shelled operator cannot read the database, and the AVC stream carries a fresh `permissive=0` record of class `staff_t × keepassxc_db_t : file read` whose timestamp matches the verify-trigger.
- When invoked from `sysadm_t` (the admin/backup verify path), the read must succeed (the CIL allow `sysadm_t × keepassxc_db_t : file read` is in scope). A `Permission denied` here is `FAIL`.

A successful leverage-proof confirms the `staff_t × keepassxc_db_t` enforced cut is in place; this is the operationally meaningful drift detector. The verify also asserts that the three custom types are present, that all three modules are loaded at priority 400, that the two companion `type_transition` rules are present, that the typepermissive marker matches the configured expectation, that the four fcontext entries map to the expected types, and that no `keepassxc_db_t`-labeled file exists outside the operator-chosen database directory. The last assertion is the containment check: a `keepassxc_db_t` file under, say, a browser profile tree means a helper spawn inherited `keepassxc_t` and the `keepassxc_dbtype_autotrans` transition fired across an unrelated tree — the failure the `keepassxc_spawn_isolation` module exists to prevent.

### AVC posture

The AVC posture has two parts. The expected stream from the runtime domain itself is `permissive=1` records sourced from `keepassxc_t` during normal application use; common targets include `cache_home_t` (Qt icon cache, DBus session marshalling), `config_home_t` (input-method socket file watcher), `dri_device_t` (Mesa/Wayland render-node access via `/dev/dri/renderD128`), `syslogd_var_run_t` (systemd-journald datagram socket), `kernel_t` (unix datagram sendto for journald), and `session_dbusd_tmp_t` (DBus session-bus connection). These six target classes form the typical permissive cluster set under the deploy state described here; they are workflow-discovery records and not drift.

The leverage-proof denial is a fresh `permissive=0` record of class `staff_t × keepassxc_db_t : file read` whenever the verify probe deliberately triggers the cut. This record is the operationally meaningful drift detector: an absent record on an applied host means the enforcement is not in place.

Drift signals: any `permissive=0` record sourced from `keepassxc_t` (the deploy state expects `permissive=1` records from this source domain only); any `permissive=0` record of class `staff_t × keepassxc_db_t : file read` whose timestamp predates the verify-probe trigger (an unintended leverage trigger from the operator's interactive shell, indicating workflow drift); a sudden absence of `permissive=1` records sourced from `keepassxc_t` over a workflow-active session, suggesting the typetransition is not firing — typical root cause is a `dnf reinstall keepassxc` that re-laid the binaries with the stock `bin_t` label and was not followed by a `restorecon` pass over `/usr/bin/keepassxc{,-cli,-proxy}`.

A distinct drift class belongs to the spawn-containment transition: `keepassxc_db_t`-labeled files appearing outside the operator-chosen database directory — typically across a browser profile tree. That signals the `keepassxc_spawn_isolation` module is absent or unloaded, so a helper the application launched inherited `keepassxc_t` and the `keepassxc_dbtype_autotrans` transition relabeled every file that helper created. The signal is the sweep in the probe and verify, not an AVC: under the permissive discovery posture the helper's file creates do not raise enforced denials. Recovery is to restore the module, then `restorecon` the affected tree back to its stock labels.

The four-tool diagnosis loop (`ausearch`, `audit2why`, `audit2allow`, `sealert`) for the AVC stream is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

The role's modify stage is idempotent. The three CIL sources are pushed via `ansible.builtin.copy` from the role's `files/` directory and each converges on byte-for-byte content match; a `semodule -X 400 -i` install runs only on a CIL-source change. The four fcontext entries are added via `community.general.sefcontext` with `state: present` and are idempotent on a host already in the end-state. The `restorecon` step fires only on an fcontext-entry change; a re-run over already-correctly-labeled paths reports no relabel. The CIL load is sequenced before the fcontext additions so the custom types exist when `restorecon` resolves them. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

Recovery removes the three modules and the four fcontext entries, then relabels back to stock. The byte-exact form:

```bash
sudo -r sysadm_r -t sysadm_t bash -c '
  semanage fcontext -d "/usr/bin/keepassxc" || true
  semanage fcontext -d "/usr/bin/keepassxc-cli" || true
  semanage fcontext -d "/usr/bin/keepassxc-proxy" || true
  semanage fcontext -d "/home/<user>/keepass(/.*)?\.kdbx(\.backup)?" || true
  restorecon -v /usr/bin/keepassxc /usr/bin/keepassxc-cli /usr/bin/keepassxc-proxy
  restorecon -Rv /home/<user>/keepass
  semodule -X 400 -r keepassxc_spawn_isolation keepassxc_dbtype_autotrans keepassxc_extras
'
```

The companion modules are removed before `keepassxc_extras`: both reference its types (`keepassxc_t`, `keepassxc_db_t`), and a policy rebuild that dropped `keepassxc_extras` while a referencing module stayed loaded would fail on the unresolved type. Post-rollback, the binaries return to `bin_t`, the database files return to `user_home_t`, and `seinfo -t` returns empty for the three custom names. Boot-failure risk for this topic is structurally zero — a custom CIL module loaded at priority 400 cannot block the boot path because `init_t` has no dependency on `keepassxc_t`; the worst case is that `staff_t` cannot read the database (the leverage), which is the intended end-state and is not a boot failure.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

This topic instantiates a broader trap class: a custom user-application sub-domain paired with a `file_type`-only anchor on the application's data files, plus a dynamic relabel that holds that anchor across atomic saves. The dynamic relabel carries a coupled hazard — a sub-domain that leaks into the helpers the application launches will relabel files across unrelated home-directory trees — which the spawn-containment transition closes. Why both halves must ship together, and how the `file_type`-only anchor produces an enforced cut that the sub-domain's own permissive flag cannot weaken, is covered in [Application sub-domains and the helper-spawn inheritance trap](../../explanation/app-subdomain-helper-spawn-inheritance.md). No existing system-services pattern in this tree intersects this user-application surface; those patterns describe daemon traps with fundamentally different mechanisms.
