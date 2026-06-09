<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Sudo custom logfile and SELinux labeling

## The trap

A drop-in under `/etc/sudoers.d/` that routes per-command audit output to a custom file via `Defaults!<absolute-path> logfile=/var/log/<wrapper>.log` requires the destination file to carry the SELinux type `sudo_log_t`. The default type for a file under `/var/log/` is `var_log_t`, and stock SELinux targeted policy does not grant the `sudodomain` attribute — the union of `sudo_t`, `staff_sudo_t`, and the other per-role sudo domains — the `create` or `open`-write permissions on `var_log_t:file`. The drop-in parses, the command runs, the audit log silently does not.

The trap is silent in the operationally worst sense. `sudo` emits a single line on stderr — `sudo: unable to open log file …: Permission denied` — and continues. PAM authentication, the `setexec` transition into the target type, and the `execve` of the command are independent of the audit-log open, so the command itself completes with the expected exit code. Operators who watch only `stdout` and the command's exit status see nothing wrong. The audit trail that the drop-in was meant to produce is empty, and remains empty for every subsequent invocation.

## Why it happens

Two policy facts compose. First, sudo's per-command logging opens the audit-log file from the sudo process itself, after PAM authentication and before the role transition into the target type. The open runs in the calling user's sudo domain — `staff_sudo_t` for plain `sudo` from a `staff_u`-confined account, `sudo_t` for the unconfined case, or another per-role variant — not in the post-transition domain that the drop-in's `TYPE=` clause would establish. The `TYPE=` clause governs `execve`, not the audit-log open.

Second, the `sudodomain` attribute is granted only the read-side permission set on `var_log_t`. The relevant `sesearch` excerpt:

```text
$ sesearch -A -s sudodomain -t var_log_t -c file
allow sudodomain var_log_t:file { append getattr ioctl lock };
```

There is no `open`, no `create`, no `write` on `var_log_t:file` for `sudodomain`. The append/getattr/ioctl/lock permissions cover the read-side audit access pattern (a sudo binary that opens an already-existing, correctly-labeled rotated log to append a record). They do not cover the create-and-open-for-write pattern that a custom `logfile=` directive triggers when the file does not yet exist, and they do not cover the open-for-write pattern when the file exists but carries `var_log_t` rather than `sudo_log_t`.

The matching `sudo_log_t` allow rule, by contrast, grants the full create/open/write set:

```text
$ sesearch -A -s sudodomain -t sudo_log_t -c file
allow sudodomain sudo_log_t:file { create open read write append getattr setattr lock ioctl };
```

The fix is therefore not a code change but a label change on the destination path.

## How to detect it

Three observable signals, in order of how reliably they appear:

- The stderr line `sudo: unable to open log file …: Permission denied` from the affected command. This signal is reliable but trivially missed: it appears on stderr only on the failed open, the command continues afterwards, and the operator watching `stdout` does not see it.
- A live AVC under `journalctl -b` with `comm="sudo"`, `scontext` matching the calling sudo domain (`staff_sudo_t` for the `staff_u` case), and `tcontext=...:object_r:var_log_t:s0` for the sudoers-`logfile=` target path. The denial reads `denied { create }` when the file does not yet exist and `denied { open }` (or `denied { write }`) when the file exists at the wrong label.
- A static label mismatch on the file itself: `ls -lZ /var/log/<wrapper>.log` shows `system_u:object_r:var_log_t:s0` rather than `system_u:object_r:sudo_log_t:s0`. This signal is the slowest to surface — the file may not exist yet — but it is the unambiguous root cause when the other two are present.

```text
$ journalctl -b -t audit | grep -E 'sudo.*log file|denied.*var_log_t'
... avc:  denied  { create } for  pid=NNNN comm="sudo" name="<wrapper>.log"
    scontext=...:staff_sudo_t:s0 tcontext=...:var_log_t:s0 tclass=file ...

$ ls -lZ /var/log/<wrapper>.log
-rw-------. 1 root root system_u:object_r:var_log_t:s0 0 ... <wrapper>.log

$ matchpathcon /var/log/<wrapper>.log
/var/log/<wrapper>.log	system_u:object_r:var_log_t:s0
```

The third command shows that the file-context database itself does not yet carry a rule for the path. The mitigation step below adds the rule and applies it.

## How to mitigate it

Add a file-context rule that maps the destination path to `sudo_log_t`, then apply the label. Both commands must run from a domain that is allowed to write the policy store and to relabel an existing file — under the `staff_u` operator confinement, that is `sudo -r sysadm_r -t sysadm_t`:

```bash
sudo -r sysadm_r -t sysadm_t semanage fcontext -a -t sudo_log_t '/var/log/<wrapper>\.log'
sudo -r sysadm_r -t sysadm_t restorecon -Fv /var/log/<wrapper>.log
```

The regex form `'/var/log/<wrapper>\.log'` is the canonical `semanage fcontext` syntax: `semanage` stores it as a regex, the dot is escaped, and the rule is idempotent (re-adding an identical entry is a no-op). The `-F` flag on `restorecon` forces a relabel even when the existing label is non-default, which is exactly the case being fixed. The `-v` flag prints the change for the verify trail.

The relabel must be applied before the first `sudo` invocation that targets the drop-in. If the operator reverses the order — first invocation creates the file at the wrong label, then `restorecon` is run — the first invocation still loses its audit record (the open has already failed and the command has run without a log), and the file may be left as a zero-byte `var_log_t` artifact that the relabel then promotes to `sudo_log_t`. Subsequent invocations log correctly, but the inaugural one is irrecoverable. Add the file-context rule before staging the drop-in, or stage both in a single transaction.

The `iolog_dir=` directive — sudo's I/O logging directory, used when a drop-in sets `Defaults!<cmd> log_output` and points the I/O log at a custom directory — follows the same labeling rule for its target directory pattern. The same `sudodomain` versus `var_log_t` allow gap applies, with `dir` and `file` classes both involved (the I/O log is a directory tree containing per-session log files). The `semanage fcontext` invocation in that case adds a directory regex such as `'/var/log/<wrapper>-iolog(/.*)?'` mapped to `sudo_log_t`, and the `restorecon -RFv` run is recursive.

```cil
;; Conceptual shape of the policy that grants the open-for-write path.
;; Distribution-shipped — not something an operator writes — and shown here
;; only to make the rule visible.
(allow sudodomain sudo_log_t (file (create open read write append
                                    getattr setattr lock ioctl)))
(allow sudodomain sudo_log_t (dir  (search add_name remove_name write
                                    getattr setattr open)))
```

Edge cases the mitigation does not cover:

- A drop-in whose `logfile=` points outside `/var/log/` (for example, into `/srv/audit/` or an operator's home directory). The same `semanage fcontext -a -t sudo_log_t` rule is the fix, but the path may also intersect other policy rules (HOME directories carry `user_home_dir_t` and `user_home_t` recursively, and those have their own access rules). The robust placement for sudo audit data is `/var/log/`; other paths are out of scope here.
- A drop-in that uses `log_output` with the package-default `iolog_dir = /var/log/sudo-io`. The default path is shipped with the correct file-context rule by the `sudo` package, so no relabel is needed. The mitigation applies only when the operator overrides the directory.
- A drop-in whose `logfile=` path is templated by sudo (`%h`, `%u`, `%C` expansions). `semanage fcontext` operates on the resolved path; the operator must enumerate the expanded paths or use a regex that covers them.

## See also

- [staff_u and sudo role transitions](../reference/foundation/sudo-roles.md) — The Foundation layer that establishes the role-confined sudo surface and references this pattern from its `Sudoers configuration` subsection.
- [UMASK and daemon readability](./umask-and-daemon-readability.md) — A different file-mode-and-policy interaction at the operator/daemon boundary; same mental model, different mechanism (DAC mode bits versus SELinux file type).
