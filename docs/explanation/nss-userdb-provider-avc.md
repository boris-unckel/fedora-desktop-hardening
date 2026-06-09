<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# The NSS userdb provider AVC trap

## The trap

A confined consumer that resolves uid and gid identifiers through `getpwuid(3)` or `getgrgid(3)` as part of its normal work — a file-hash tool that resolves owner and group names alongside file content, a backup or audit tool that stats large trees, or any other process domain bearing the `nsswitch_domain` attribute — runs against the `systemd-userdbd` discovery directory at `/run/systemd/userdb/` whose entries include at least one provider socket whose SELinux type does not match the discovery-directory default. The denial fires at the consumer ↔ provider edge and surfaces in two distinct audit shapes depending on the active `selinux-policy` generation: an AVC cluster of the form `tcontext=*_var_run_t tclass=sock_file denied={ write }` carrying a path-anchor below `/run/systemd/userdb/` under one generation, or an AVC cluster of the form `tcontext=*_t tclass=unix_stream_socket denied={ connectto }` on the publisher daemon's own process domain under the next, with no path-anchor available. Both shapes signal the same underlying trap.

The visible symptom is structurally one-sided. AVCs accumulate at a high multiplier per consumer-invocation — one denial per NSS-consuming lookup, multiplied across every file or stat target the consumer touches — while the consumer's own self-diagnostic reports nothing wrong: no error counter increments, no skip-count rises, the journal carries no failure line, and the exit code is `0`. The `libc` NSS layer absorbs the per-socket `EACCES` and transparently falls back to numeric uid and gid resolution; from the consumer's point of view the lookup returned a value, not an error, and the consumer continues. Tool-silence in the presence of a growing AVC backlog is the canonical signature of the trap and reads as confirmation, not as evidence that the consumer is uninvolved.

## Why it happens

Every NSS lookup that resolves a uid or gid through `libc` consults the `systemd-userdbd` discovery directory at `/run/systemd/userdb/`: the directory is enumerated, and the NSS module performs `connect(2)` against every socket entry it finds — which SELinux evaluates as `write` on the target `sock_file` under one selinux-policy generation and as `connectto` on the socket-owner's `unix_stream_socket` under the next. The permission check fires on the client-side `connect(2)`, not on a read against the discovery directory itself: the consumer domain already carries the stock allow `<nsswitch_domain> × systemd_userdbd_var_run_t:sock_file { write }` against the directory default and against its provider sockets when those sockets carry the same default, and the directory-listing step proceeds without denial. The denial appears at the per-socket `connect(2)` against at least one entry whose type is not the directory default. A publisher daemon creates its provider socket by `bind(2)` against an `AF_UNIX` path under `/run/systemd/userdb/`, and SELinux assigns the new socket's type by inheritance from the daemon's own runtime-directory type — for example `xdm_var_run_t` for a display-manager publisher — rather than from the discovery-directory default `systemd_userdbd_var_run_t`, against which the stock allow `<nsswitch_domain> × systemd_userdbd_var_run_t:sock_file { write }` would have applied.

The same mechanism surfaces in two different audit forms across selinux-policy generations — `tclass=sock_file denied={ write }` with a path-anchor under `/run/systemd/userdb/` under one generation, and `tclass=unix_stream_socket denied={ connectto }` on the publisher's process-domain under the next — and the operator must recognize both forms as the same trap class, because the underlying `bind`-time type-inheritance is unchanged. The kernel-side permission check has moved from the sock-file-path layer to the socket-owner's process-domain layer between the two generations, but the consumer is still hitting the publisher's `bind`-inherited type, the stock allow is still scoped to the discovery-directory default, and the gap is still on the same edge of the consumer ↔ publisher relationship. An operator who reads only one of the two audit forms as "the" form of the trap will mis-classify the other when it appears, either after a policy update on the same host or on a sister host running a different `selinux-policy` generation.

The tool-silence-as-confirmation rule follows from where the failure lives in the call stack. The NSS library's contract with the caller is to return a resolved uid or gid; when the lookup against a provider socket fails, the library moves on to the next provider in `nsswitch.conf` and ultimately falls through to the numeric form of the identifier. The consumer sees a successful return value and has no signal that any provider was unreachable. A consumer's empty error log in the face of accumulating AVCs is structural evidence for the trap class, not against it; the trap must not be ruled out on the basis that the consumer's self-diagnostic reports zero errors. Any process domain bearing the `nsswitch_domain` attribute and performing frequent uid or gid resolution is a candidate trap surface — file-hash tools that resolve owner names for hashing, backup or audit tools that stat large trees, and confined daemons that perform NSS-aware logging are the recurring shapes — but the consumer set is not enumerated here, because new tools enter the `nsswitch_domain` attribute over time and an enumeration would falsify the structural boundary. The Pattern asserts the class; the per-consumer instance is the operator's diagnostic concern.

## How to detect it

When an AVC matches `tclass=sock_file denied={ write }` against a `*_var_run_t` type, the operator's first read is the `name=` field and the path's parent directory; a parent of `/run/systemd/userdb/` is the trap signature, and any other parent rules the trap class out and re-opens the file-walk or local-socket-write hypothesis. For the newer audit form, the equivalent signature is a `connectto` denial on a `unix_stream_socket` whose process-side domain is a known publisher daemon, absent any corresponding `sock_file` AVC against the publisher's runtime-directory type. Three signals together identify the trap unambiguously: the path-anchor or process-domain read on the AVC record itself; an enumeration of the discovery directory's per-socket SELinux types from a role with broader `/run` traversal; and a full count of the AVC backlog rather than a truncating view, because the per-invocation multiplier commonly reaches forty or more and a `tail -N` window reports only the most recent fraction of the backlog.

The diagnostic probe enumerates the per-socket types under the discovery directory from an elevated role: `find /run/systemd/userdb -type s -printf '%y %p\n'` and `ls -laZ /run/systemd/userdb/`. The expected baseline is that every entry carries `systemd_userdbd_var_run_t`; any entry whose type ends in `_var_run_t` and differs from the baseline — `xdm_var_run_t` for a display-manager publisher is the canonical example — names the publisher-inherited type that the consumer-side stock allow does not cover. The probe runs from a role with broader `/run` traversal permission than a confined user-shell domain; a `staff_t`-confined login may not carry the directory-traversal permission required to list the discovery directory, and a role transition into `sysadm_t` via `sudo -r sysadm_r -t sysadm_t` is the typical way to obtain it.

```text
$ sudo -r sysadm_r -t sysadm_t ausearch -m avc -ts recent | head -2
type=AVC msg=audit(1700000000.000:1234): avc:  denied  { write } for
  pid=12345 comm="<consumer-comm>" name="<provider-socket-name>"
  dev="tmpfs" ino=1234567
  scontext=system_u:system_r:<consumer-domain>:s0
  tcontext=unconfined_u:object_r:xdm_var_run_t:s0
  tclass=sock_file permissive=0
type=AVC msg=audit(1700000000.000:1235): avc:  denied  { connectto } for
  pid=12345 comm="<consumer-comm>" path="<provider-socket-name>"
  scontext=system_u:system_r:<consumer-domain>:s0
  tcontext=system_u:system_r:xdm_t:s0
  tclass=unix_stream_socket permissive=0

$ sudo -r sysadm_r -t sysadm_t \
    find /run/systemd/userdb -type s -printf '%y %p\n'
s /run/systemd/userdb/io.systemd.DynamicUser
s /run/systemd/userdb/io.systemd.Home
s /run/systemd/userdb/io.systemd.Machine
s /run/systemd/userdb/<provider-socket-name>

$ sudo -r sysadm_r -t sysadm_t ls -laZ /run/systemd/userdb/
srw-rw-rw-. root root system_u:object_r:systemd_userdbd_var_run_t:s0 io.systemd.DynamicUser
srw-rw-rw-. root root system_u:object_r:systemd_userdbd_var_run_t:s0 io.systemd.Home
srw-rw-rw-. root root system_u:object_r:systemd_userdbd_var_run_t:s0 io.systemd.Machine
srw-rw-rw-. root root unconfined_u:object_r:xdm_var_run_t:s0         <provider-socket-name>

$ sudo -r sysadm_r -t sysadm_t \
    ausearch -m avc -ts recent | grep -c 'tcontext=.*xdm_var_run_t'
447
$ sudo -r sysadm_r -t sysadm_t \
    ausearch -m avc -ts recent | grep 'tcontext=.*xdm_var_run_t' | tail -30 | wc -l
30
```

The mismatch between the full count and the trailing-30 view makes the AVC-multiplier hazard visible: the truncating-view habit reports only the most recent fraction of the backlog and leads to systematic under-investment in the fix. The probe must take a full count before any decision about the size of the mitigation lever.

## How to mitigate it

The canonical local mitigation is a custom CIL mini-module at priority 400 scoped to the diagnosed consumer-publisher pair — `(allow <consumer-domain> <publisher-runtime-type> (sock_file (write)))` for the older audit form and `(allow <consumer-domain> <publisher-process-domain> (unix_stream_socket (connectto)))` for the newer one — loaded via `semodule -X 400 -i` from a role with `sysadm_t` semantics. The module names the specific consumer source domain that surfaced the trap and the specific publisher-side type — a runtime-directory type for the older audit form, a process domain for the newer — and nothing else. It does not widen the consumer against `systemd_userdbd_var_run_t` or against the publisher-discovery daemon's process domain `systemd_userdbd_t` — both already carry the stock allow that the discovery-directory default expects — and it does not widen the consumer against any `_var_run_t` type other than the one the probe identified.

```cil
(allow <consumer-domain> <publisher-runtime-type> (sock_file (write)))
(allow <consumer-domain> <publisher-process-domain> (unix_stream_socket (connectto)))
```

The local module is necessary but not sufficient. The upstream fix targets one of two surfaces. The `selinux-policy` surface carries either a `file_contexts` pin that re-anchors `/run/systemd/userdb/.*` to `systemd_userdbd_var_run_t` regardless of the publisher daemon's runtime-directory type, or a `type_transition` rule from the publisher process-domain to `systemd_userdbd_var_run_t` on creation of a `sock_file` under the discovery directory; either form removes the `bind`-time inheritance from the picture. The publisher-daemon surface carries an explicit `setfilecon(3)` call before `bind(2)` that overrides the runtime-directory inheritance and assigns the discovery-directory default to the socket the daemon is about to create. Which surface is tractable depends on each upstream's release cadence and the daemon's maintainership; the Pattern does not prescribe one over the other, and the local mini-module is the bridge in either case.

Consumer-side `dontaudit` is not a mitigation. Silencing the AVC with a `dontaudit` rule against the consumer leaves the underlying `EACCES` in place: the `connect(2)` still fails, the NSS library still falls through to numeric uid and gid resolution, and the consumer's output is materially wrong on its own terms. A file-hash tool that resolves owner and group names as part of its hashing payload produces a different hash when the lookup returns a numeric id than when it returns a named one; the per-file digest changes, the on-disk baseline no longer matches the freshly-computed view, and the report-comparison step that justified the tool's deployment is broken. An audit-report tool that lists numeric ids in place of names breaks correlation against the host's user table. A backup tool that resolves group names to numerics during archive creation produces an archive that does not round-trip across hosts — the names lost in the resolution path are not recoverable from the archive on restore. The mitigation must restore the consumer's ability to complete the NSS lookup against the publisher socket, not suppress the diagnostic for the partial-failure case.

Edge cases the mitigation does not cover:

- A host with several mismatched publishers (for example, an additional non-stock UserDB-provider from a third-party login manager or an enterprise-identity agent): the local mini-module covers one consumer-publisher pair at a time, and a new mismatched provider produces a fresh AVC class that requires a fresh allow. The mitigation does not auto-discover new publisher types; the operator re-runs the publisher-socket-type enumeration after any change to the discovery directory's membership and extends the module per new pair.
- A consumer running without SELinux confinement (`unconfined_t` or a similar broadly-allowed source domain): the trap does not surface, because the consumer's source domain carries broad allows that cover the inherited publisher type. The trap class is bounded to confined consumers, and un-confining the consumer side is not a mitigation — it removes the trap by removing the confinement, which is not a hardening posture and is not what the local mini-module is doing.
- A host whose `nsswitch.conf` does not list a `userdb`-aware service: the NSS lookup path does not enumerate `/run/systemd/userdb/`, no `connect(2)` is attempted against any provider socket, and the trap does not surface. The mitigation does not need to be deployed on such hosts; the operator confirms the trap's applicability by inspecting `nsswitch.conf` before authoring the module.
- A consumer running inside a container or PID/mount namespace whose `/run/systemd/userdb/` view differs from the host's: the trap class can surface or disappear depending on the namespace's mount layout. The local mini-module operates on the host's policy module-store and does not translate into container-internal policy; the canonical mitigation for the in-container case is a container-internal policy module or a namespace-internal NSS configuration that does not enumerate the host's discovery directory.

## See also

- [F44 sbin/bin merge fcontext](./f44-sbin-bin-merge.md) — Both Patterns are stock-targeted-policy regression classes that leave a confined principal silently mis-served by the policy on the affected `selinux-policy` generation: the sbin/bin-merge case rebinds a daemon's exec-type to a path-merged default and leaves the daemon running under `unconfined_service_t` with no operator-visible functional symptom, and this Pattern leaves a publisher-socket's `bind`-inherited type uncovered by the consumer-side stock allow and leaves the consumer's NSS-lookup degraded with no operator-visible symptom in the consumer's own self-diagnostic.
- [The unlabeled_t silent EACCES trap](./unlabeled-t-silent-eacces.md) — Both Patterns are object-side labeling-mismatch trap classes where the running policy does not carry an allow for the actual type that lands on the object — an on-disk xattr naming an undefined type in `unlabeled-t-silent-eacces`, a `bind`-inherited runtime-directory type on a discovery-socket in this Pattern — and both produce a permission boundary the consumer-side did not anticipate, distinguished by where the silence sits (a kernel-side `dontaudit` suppression in the unlabeled case, an NSS-library numeric-fallback transparency in this case).
