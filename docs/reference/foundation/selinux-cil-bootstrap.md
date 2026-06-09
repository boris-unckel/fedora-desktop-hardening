<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# SELinux custom CIL bootstrap

## Role in the hardening model

This Foundation layer establishes the **loader contract** for custom SELinux policy modules written in the Common Intermediate Language (CIL). It documents the priority convention, the source-file location and mode discipline, the install/list/remove/rebuild commands, the role-switch and module-store access label, the idempotence semantics of repeated installs, and the recovery paths available when a custom module misbehaves. The layer does not document the contents of any specific custom module: each Foundation or Topic role that ships a CIL module documents its rules in its own Reference, and any cross-cutting trap that motivates a class of modules (for example, the systemd `NoNewPrivileges` × stock-policy interaction that motivates transition-grant modules) is documented separately as an Explanation.

This Foundation layer is a prerequisite for: every Foundation layer above it that ships a custom CIL module (the next layer up, the audit-and-logging baseline, ships none directly but consumes the loader for AVC remediation), every Topic role that ships a custom CIL module to grow `staff_t`'s confined surface or to allow a system-init-time service its missing transition, and every operator-facing How-to that documents on-host policy-module inspection. It depends on Layer 0 (UMASK 0027) for the file-mode discipline that turns operator-authored source CIL files into root-owned, world-readable artifacts under `/usr/local/share/selinux/`, and on Layer 1 (`staff_u` and sudo role transitions) for the `sysadm_t` escalation that every policy-store mutation requires.

## End-state configuration

The end-state spans four orthogonal concerns: the priority and source-file convention that turns a CIL file into a loadable module, the canonical install and list and remove commands and the role-switch they require, the on-disk module-store layout and the editing discipline that keeps in-place edits recoverable, and the recovery paths that apply when a custom module misbehaves at runtime.

### Module priority and the source-file convention

SELinux policy modules carry an integer priority in the range `[1, 999]`. Distribution-shipped modules from `selinux-policy-targeted` are loaded at priority 100. Local-custom additions use **priority 400** by convention. The priority-400 slot is the canonical choice across SELinux documentation and Fedora's own custom-module examples; this hardening tree adopts it for every custom CIL module shipped by any Foundation or Topic role. Hardcoding the value avoids accidental priority collisions between roles and keeps the verify-side filter (`semodule -lfull | awk '$1 == "400"'`) trivially uniform.

For the same module name, the highest-priority entry is the one the policy compiler activates; lower-priority entries remain in the store but are inactive. Removing the higher-priority instance causes the next-lower instance (typically the distribution's priority-100 stock entry, when one exists by that name) to become active again. This layered model is the basis of the canonical module-removal recovery path described under [Recovery paths](#recovery-paths).

Custom CIL source files live at:

```text
/usr/local/share/selinux/<name>.cil
```

The directory is package-default, mode `0755 root:root`, and carries the file-context `usr_t`:

```text
drwxr-xr-x. root root system_u:object_r:usr_t:s0 /usr/local/share/selinux
```

Source files within the directory inherit the `usr_t` label by default. No `semanage fcontext` rule is required for the source files themselves — the loader reads the file content and writes the *compiled* module artifacts to the policy store under `/var/lib/selinux/targeted/active/modules/`, which is the path that carries the access-controlled label. Source-file mode is operationally significant only at read time: a source written under a UMASK of `0027` lands at mode `0640 root:root` and is readable from the operator's `staff_t` shell only when an explicit `chmod 0644` follows the write. The Ansible role of this Foundation creates the directory at mode `0755`; the modes of individual source files are the responsibility of the role that ships each module. The convention adopted across the tree is `0644 root:root` for source files that the operator may want to inspect from `staff_t` and `0640 root:root` for source files that are intended to be read only from `sysadm_t` or by `root`. Both are acceptable to the loader; mode is not policy-relevant because `semodule` runs in `sysadm_t` and reads regardless.

### Install, list, and remove commands

Every command in this subsection mutates or inspects the policy store at `/var/lib/selinux/targeted/active/modules/`. The store is accessible only from `sysadm_t`. Plain `sudo` from a `staff_u`-confined account lands in `staff_sudo_t`, where the store is unreadable. The role-switch syntax (`sudo -r sysadm_r -t sysadm_t <cmd>`) and its rationale live in the Layer 1 Reference [staff_u and sudo role transitions](./sudo-roles.md); this layer reuses the syntax verbatim and does not restate the mechanism.

Install a custom CIL module at priority 400:

```bash
sudo -r sysadm_r -t sysadm_t semodule -X 400 -i /usr/local/share/selinux/<name>.cil
```

The `-X N` flag governs the priority and **must precede** `-i <path>`. The reverse form (`semodule -i <path> -X 400`) fails before any policy-store mutation with:

```text
libsemanage.map_compressed_file: Unable to open -X
```

because `getopt` parses `-X` as a positional argument when `-i` consumes the path slot first. The error is loud, the policy store is untouched, and the operator re-runs with corrected ordering. The flag-order trap is recoverable on its own; it cannot leave the host in a half-installed state.

Without the role switch, the same `semodule` invocation fails earlier and equally cleanly:

```text
libsemanage.semanage_create_store: Could not read from module store, active modules subdirectory at /var/lib/selinux/targeted/active/modules. (Permission denied).
libsemanage.semanage_direct_connect: could not establish direct connection (Permission denied).
semodule:  Could not connect to policy handler
```

The same error class governs `semodule -lfull`, `semodule -r`, `semodule -B`, and any `semanage` subcommand that walks the store. The operator does not need to memorize which command needs what — the rule is uniform: every `semodule`/`semanage` call on this layer runs from `sysadm_t`.

List currently loaded modules with priority and language extension:

```bash
sudo -r sysadm_r -t sysadm_t semodule -lfull
```

`semodule -lfull` reports one row per `(priority, name, lang)` triple. The default `semodule -l` form omits priority and `lang_ext` and is therefore unsuitable for the verify probe; the `-lfull` form is canonical. To filter only the priority-400 (custom) modules, the idiom is:

```bash
sudo -r sysadm_r -t sysadm_t semodule -lfull | awk '$1 == "400"'
```

A correctly bootstrapped host with no custom modules emits an empty list under that filter. The lowest possible noise floor is desirable so that verify-script Soll/Ist comparisons across roles do not have to discriminate between expected and incidental priority-400 entries.

Remove a custom module:

```bash
sudo -r sysadm_r -t sysadm_t semodule -X 400 -r <name>
```

Removal does not require the source file at `/usr/local/share/selinux/<name>.cil` to still be present; the policy store carries the compiled artifacts. If a lower-priority instance of the same name exists (typically a distribution stock module at priority 100), that instance becomes active. Otherwise the module name disappears from the store. Removal does not change DAC labels on disk, does not require a reboot, does not require any service restart, and is reversible by re-installing the source CIL.

Re-installing a CIL file whose content is byte-identical to the active priority-400 instance is a no-op on newer `semodule` versions: the policy DB checksum matches and the install short-circuits. Older `semodule` versions report a successful re-install (`changed=true` from an Ansible task's perspective) even when the content is identical. The Ansible role of this Foundation does not install any specific CIL module itself; roles that do — the Layer 1 role and any future Topic role — gate the `semodule -X 400 -i` task on a `copy:` predecessor that fires only when the source-file content drifts. A redundant re-install on identical content is tolerated as a benign signal across older `semodule` versions and is not treated as drift.

### Module-store layout and editing discipline

The compiled policy lives under:

```text
/var/lib/selinux/targeted/active/modules/<priority>/<name>/
```

Each per-module directory contains the compiled `cil`, `hll`, and `mod` artifacts plus a `lang_ext` marker that records the source language. The store is rebuilt automatically on every install (`semodule -i`), remove (`semodule -r`), and rebuild (`semodule -B`). Operators rarely interact with the store directly. The path is informational for two reasons: a verify-script presence check via `[[ -d /var/lib/selinux/targeted/active/modules/400/<name> ]]` from `sysadm_t` is faster than parsing `semodule -lfull` output, and an operator who knows the layout can identify a module's store directory before issuing `semodule -X 400 -r`. Entries in this directory are never written or read directly outside `semodule` and `libsemanage`.

Editing a custom module in place — typically appending a new `(allow …)` rule to grow an existing module — is supported through one of two patterns. The **full-file install pattern** keeps the source CIL under repository version control: edit the repository copy, redeploy the file to `/usr/local/share/selinux/<name>.cil`, install. This is the preferred model because the source is committed and reproducible from the repository alone. The **extend pattern** is the in-place alternative for iteration cycles between commits: pre-test that the desired allow does not already exist (`sesearch -A -s <src> -t <tgt> -c <class> -p <perm>`), back up the active source with `cp -p <name>.cil <name>.cil.pre-<context>-<date>`, append the new rule with a comment line marking the context of the addition, restore predictable file modes with `chmod 0644 <name>.cil` and `chown root:root <name>.cil` (the operator's UMASK 0027 from Layer 0 otherwise produces 0640), reload with `semodule -X 400 -i <name>.cil`, and post-verify with the same `sesearch` form that the pre-test used. Backups in `/usr/local/share/selinux/` carry the same `usr_t` label as the active source and the loader ignores them — the `-i` flag takes a single path, not a directory walk. Recovery from a botched edit is `cp -p <backup> <name>.cil` followed by `semodule -X 400 -i <name>.cil`.

A CIL module that contains only `(allow …)` rules does not change file labels and requires no follow-up `restorecon`. A module that introduces `(typetransition …)` or `(typebounds …)` rules requires `restorecon -RFv <affected paths>` from `sysadm_t` after `semodule -X 400 -i`, to relabel files that were created under the previous policy. The end-state posture of the priority-400 modules currently shipped by Foundation roles in this tree contains only `(allow …)` rules and does not require post-install relabeling. Topic roles that ship modules with type-transition rules document the relabel target paths in their own Reference and run `restorecon` from their tasks.

### Recovery paths

Three independent layers of recovery are available without reboot when a custom CIL module misbehaves at runtime.

The lowest-blast-radius option is single-module removal:

```bash
sudo -r sysadm_r -t sysadm_t semodule -X 400 -r <name>
```

The next install of the same name re-creates the module. If a lower-priority instance exists by that name, it becomes active immediately. Removal is reversible, requires no reboot, and changes nothing on disk outside the policy store.

The coarser emergency brake is permissive mode:

```bash
sudo -r sysadm_r -t sysadm_t setenforce 0
```

Denials are logged but not enforced; `setenforce 1` re-enables enforcement. Permissive mode is independent of the loader and works even when the policy store is corrupt. The `setenforce 0` / `setenforce 1` pair is documented in full in the Layer 1 Reference [staff_u and sudo role transitions](./sudo-roles.md) as the host-wide emergency brake; that wording applies symmetrically here and is not duplicated.

The third recovery property is structural rather than operational: a CIL file with a syntax error fails at `semodule -X 400 -i` compile time *before* any policy-store write. The error is reported on stderr, the active policy is unchanged, and the operator's edit is harmless as long as the operator does not also remove the active module before the new compile succeeds. Editing a custom CIL module is a low-risk operation because the loader is transactional at the install boundary.

All three recovery actions are reversible without reboot. None of them require a service restart.

## Verification

Probe:

```bash
bash ansible/roles/foundation_selinux_cil_bootstrap/files/probe.sh
```

Verify:

```bash
bash ansible/roles/foundation_selinux_cil_bootstrap/files/verify.sh
```

The verify script checks the loader infrastructure: the SELinux runtime mode reported by `getenforce` and the `/etc/selinux/config` declaration, the presence and mode of `/usr/local/share/selinux/`, the presence of the required tooling packages (`policycoreutils-python-utils`, `selinux-policy-targeted`), and — when run from `sysadm_t` — that `semodule -lfull` is callable. The script does not check for the presence of any specific priority-400 module: each role that ships a CIL module verifies its own module presence in its own verify script. The verify exits `0` on a clean host, `1` on drift, `2` on invocation error. Checks that need `sysadm_t` are reported as `SKIP` rather than as drift when the script is run from `staff_t`.

Expected verify output on a correctly applied host, run from `staff_t`:

```text
OK   selinux_runtime_mode           Enforcing
OK   selinux_config_mode            enforcing
OK   selinux_config_type            targeted
OK   selinux_dir_present            /usr/local/share/selinux mode=0755 owner=root:root
OK   selinux_dir_label              system_u:object_r:usr_t:s0
OK   pkg_policycoreutils_python     installed
OK   pkg_selinux_policy_targeted    installed
SKIP semodule_callable              needs sysadm_t
```

On the same host re-run as `sudo -r sysadm_r -t sysadm_t bash files/verify.sh`, the `SKIP` line becomes:

```text
OK   semodule_callable              semodule -lfull returned 0
```

Two observations are reported as `WARN` rather than `FAIL`: a runtime mode of `permissive` (the loader is operational under `permissive` and `enforcing`; permissive is treated as deliberate) and a divergence between `getenforce` and `/etc/selinux/config` (which arises after a manual `setenforce 0` / `setenforce 1` and is recoverable without re-applying the role). A runtime mode of `disabled` is reported as `FAIL` because recovery from `disabled` requires a kernel-time toggle and is out of this layer's scope.

## Related patterns

- [staff_u and sudo role transitions](./sudo-roles.md) — Layer 1 of the Foundation tier. The role-switch syntax (`sudo -r sysadm_r -t sysadm_t`) used by every command in this Reference, the `staff_sudo_t` access-denial signature on the policy store, and the `setenforce 0` emergency brake all live in the Layer 1 Reference and are cross-linked from this layer rather than restated.
