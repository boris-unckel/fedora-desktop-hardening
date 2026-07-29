<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# F44 sbin/bin merge fcontext

## The trap

A daemon whose binary used to live at `/usr/sbin/<daemon>` and whose stock SELinux file-context mapping was `/usr/sbin/<daemon> → <daemon>_exec_t` may, after a Fedora 44 host upgrade, run under `unconfined_service_t` instead of its custom domain. The hardening drop-ins on the unit continue to apply: cgroup limits, process-internal kernel restrictions, capability bounding sets, and syscall filters all take effect under PID 1's spawn. SELinux confinement, however, is silently lost. The daemon runs, the unit is `active`, and there is no operator-visible functional symptom — only the SELinux confinement layer is missing.

The trap surfaces as a `ps -eZ | grep <daemon>` showing `unconfined_service_t` where `<daemon>_t` was expected, an empty AVC backlog because `unconfined_service_t` is broadly permitted by design, and a clean `systemd-analyze verify` output. There is no error-log signal, no boot-failure, and no functional regression to point at: the loss is structural and silent.

## Why it happens

Fedora 44 introduced a sbin/bin filesystem merge: `/usr/sbin` is a symlink to `/usr/bin` for the binary tree, and `/usr/sbin/<daemon>` is a compatibility symlink that resolves to `/usr/bin/<daemon>`. In parallel, the `selinux-policy` package on Fedora 44 ships `/etc/selinux/targeted/contexts/files/file_contexts.subs_dist` with a global path-equivalency `/usr/sbin /usr/bin` that resolves any `/usr/sbin/X` lookup to `/usr/bin/X` *before* the `file_contexts` table is consulted.

Stock `file_contexts` entries of the form `/usr/sbin/<daemon> -- system_u:object_r:<daemon>_exec_t:s0` therefore never match: by the time the lookup reaches the table, the path has already been rewritten to `/usr/bin/<daemon>`. The lookup proceeds against the rewritten path; no specific mapping exists at `/usr/bin/<daemon>`, so the binary inherits the generic `bin_t` label that covers the rest of the directory.

The kernel's `init_t → bin_t : process` transition rule does not carry a `type_transition` to a custom daemon domain. When PID 1 calls `execve(2)` on a `bin_t`-labelled binary, the resulting domain falls back to `unconfined_service_t`, which is the default service domain for executables that policy does not classify. The daemon runs, but the per-domain confinement that the policy intended for `<daemon>_t` is bypassed.

The class affects every daemon whose stock `file_contexts` entry was written against the `/usr/sbin/...` form before the sbin/bin merge and has not yet been updated upstream to also list `/usr/bin/<daemon>`. The corresponding upstream tracking issue lives in Bugzilla as `BZ#2463890`; the fix is per-package and propagates through `selinux-policy` minor updates over time.

## How to detect it

Three observable signals, in order of how reliably they appear on an affected host:

- `matchpathcon /usr/bin/<daemon>` returns `system_u:object_r:bin_t:s0` rather than `<daemon>_exec_t`. The command is read-only; from `staff_t` it works without escalation.
- `ls -lZ /usr/bin/<daemon>` shows the on-disk label as `bin_t`.
- `ps -eZ | grep <daemon>` shows the running process under `unconfined_service_t`. AVCs are absent because `unconfined_service_t` is broadly permitted, so an AVC-clean log is consistent with the trap rather than evidence against it.

A scan-discipline that finds all affected daemons on a host walks the stock `file_contexts` for the `/usr/sbin/...` form and compares the expected type against the live label of the rewritten path:

```bash
while IFS=$'\t' read -r path _rest typespec; do
  [ -z "$path" ] && continue
  bin_path="${path#/usr/sbin/}"
  bin_path="/usr/bin/${bin_path}"
  [ -e "$bin_path" ] || continue
  actual=$(ls -lZ "$bin_path" 2>/dev/null \
            | awk '{print $5}' \
            | awk -F: '{print $3}')
  expected_type=$(printf '%s' "$typespec" | awk -F: '{print $3}')
  [ "$expected_type" = "bin_t" ] && continue
  [ "$expected_type" = "$actual" ] && continue
  printf '  %s expected=%s actual=%s\n' "$path" "$expected_type" "$actual"
done < <(grep -E '^/usr/sbin/[^/]+\s+--\s+system_u:object_r:[^[:space:]]+_exec_t' \
           /etc/selinux/targeted/contexts/files/file_contexts \
         | awk -F'\t+' '{print $1"\t"$2"\t"$3}')
```

The scan reports one line per affected daemon. An empty output means no `/usr/sbin/...`-anchored stock mapping has lost its target on this host.

## How to mitigate it

Add a specific fcontext mapping for the `/usr/bin/<daemon>` path under `file_contexts.local`, then run `restorecon` on both the file and the symlink, and restart the unit:

```bash
sudo -r sysadm_r -t sysadm_t \
  semanage fcontext -a -t <daemon>_exec_t /usr/bin/<daemon>
sudo -r sysadm_r -t sysadm_t \
  restorecon -v /usr/bin/<daemon> /usr/sbin/<daemon>
sudo systemctl restart <daemon>.service
```

The `semanage fcontext -a` form writes the mapping into `file_contexts.local`, which is consulted before `file_contexts.subs_dist` rewrites the path. The mapping survives `selinux-policy` package updates and is removable via `semanage fcontext -d /usr/bin/<daemon>` once the upstream policy ships the fix. Re-running the same `semanage fcontext -a` exits non-zero in some `policycoreutils` versions with a "fcontext already exists" diagnostic; idempotent automation should treat that as success or use `community.general.sefcontext`, which handles the diagnostic internally.

```yaml
- name: F44 fcontext mapping
  community.general.sefcontext:
    target: /usr/bin/<daemon>
    setype: <daemon>_exec_t
    state: present
  become: true
  become_flags: "-r sysadm_r -t sysadm_t"
```

**Anti-pattern.** The reverse-equivalency form `semanage fcontext -a -e /usr/sbin/<daemon> /usr/bin/<daemon>` does **not** work. The stock `/usr/sbin → /usr/bin` equivalency in `file_contexts.subs_dist` makes any reverse mapping circular: `restorecon` on `/usr/sbin/<daemon>` is rewritten to `/usr/bin/<daemon>`, the equivalency entry resolves back to `/usr/sbin/<daemon>`, and the lookup either loops or no-ops. The binary keeps the `bin_t` label and the daemon keeps running unconfined. Operators who follow the reverse-equivalency intuition from earlier Fedora releases see a clean `semanage` exit and a clean `restorecon` exit, then find the daemon unchanged on the next inspection.

Edge cases the mitigation does not cover:

- A daemon whose binary tree was already at `/usr/bin/<daemon>` before the merge is not affected; the stock mapping was already correct.
- A daemon whose stock `file_contexts` entry was written with a wildcard (`/usr/(s)?bin/<daemon>` or similar) is not affected; the wildcard form already covers both paths.
- A site-local fcontext entry that predates the merge and uses the `/usr/sbin/...` form is ineffective for the same reason as the stock entries; the same `semanage fcontext -a -t <type> /usr/bin/<daemon>` mitigation applies.
- When upstream `selinux-policy` adds the `/usr/bin/<daemon>` mapping in a minor update, the site-local entry can be removed via `semanage fcontext -d /usr/bin/<daemon>`. Tracking the upstream fix is a per-policy-update operator-policy concern outside this pattern.

## See also

- [SELinux custom CIL bootstrap](../reference/foundation/selinux-cil-bootstrap.md) — The Foundation layer that provisions the priority-400 publish path used for the related class of policy extensions; the fcontext mitigation here writes into `file_contexts.local` rather than into a CIL module, but the operator role-switch surface is the same.
- [UMASK and daemon readability](./umask-and-daemon-readability.md) — Another silent-failure trap at a filesystem-and-policy boundary that also produces a clean AVC log; the symptom shapes are different but the diagnostic posture is similar.
- [Drop-in files and SELinux context inheritance](./dropin-selinux-context-inheritance.md) — The same path-equivalency table and the same `--` file-type qualifier, applied to configuration files rather than to executables. Relevant when reasoning about which of two paths a rule actually governs: an entry qualified with `--` never matches the compatibility symlink, only the regular file.
