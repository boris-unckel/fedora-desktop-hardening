<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Python pip user-tree discipline

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the operator-deployed end-state for Python `pip` package management on a hardened single-user Fedora 44 or later desktop. It is not a daemon topic and not a sandbox topic; it is a maintenance and packaging discipline topic. The end-state ships **one** persistent on-disk artefact (a PEP-668 `EXTERNALLY-MANAGED` marker file at the active interpreter's stdlib path) plus **two** operator-policy conventions surfaced as recommended discipline (a symmetric `--user`-only `pip` form for operator update scripts and an opinionated curated whitelist of pip-only packages maintained in the user-tree). The Reference covers the marker file (path-shape rule, byte-exact body, mode, ownership, RPM-non-ownership invariant), the marker-path discovery rule (`sysconfig.get_path("stdlib")` derivation rather than a hard-coded constant), the defense-in-depth layering against `sudo pip install` invocations from a `staff_u`-mapped login, the symmetric `--user` discipline and its asymmetric anti-pattern, the curated-whitelist convention, the per-Python-minor-bump migration discipline, the orphan-tree cleanup discipline, the verify discipline, the canonical live-test under `sysadm_t`, the canonical no-op test under plain `sudo`, and the two-stage rollback posture. This topic does **not** cover the content of operator update scripts beyond the symmetric-pip discipline form, the specific package names in the operator's curated whitelist, virtual-environment workflows (`python3 -m venv`), `pipx`, `conda` / `mamba` / `micromamba`, system-Python upgrade mechanics (the Fedora Python minor-bump path is used as a trigger event for the migration discipline, not as in-scope content), the `selinux-policy-targeted` typing of the marker file (the marker is read by pip via stdlib `open(2)` in the invoker's domain, so no SELinux confinement applies at the file-read step), the `--break-system-packages` override-flag's interaction with audit logging, and the `pip download` / `pip wheel` build-from-source workflow.

## End-state configuration

The deploy footprint of this topic is a single file on disk: the PEP-668 marker at the active interpreter's stdlib path. There is no systemd unit, no systemd drop-in, no `/etc/profile.d/` script, no SELinux CIL module, no `semanage fcontext` mapping, no `restorecon` invocation, no polkit rule, no sudoers fragment, and no desktop-entry override. The Topic role's modify stage writes the marker, surfaces the symmetric-pip discipline as a `pause:` task with the byte-exact recommended form, and reports orphan trees without auto-removing them. The role does **not** issue `pip install`, `pip uninstall`, or any other mutation of the user-tree contents.

### Topic shape

The end-state has three structurally independent components, two of which are operator-policy conventions surfaced by the role as recommendations rather than as auto-applied changes:

- A PEP-668 marker file at `/usr/lib64/python3.X/EXTERNALLY-MANAGED` (where `python3.X` is the active Fedora 44 Python minor) that blocks `pip install <pkg>` invocations whose writability resolution lands on the system stdlib path.
- A symmetric `--user`-only pip discipline in operator update scripts (`pip3 list --outdated --user … | pip3 install --user -U`). Asymmetric scripting (`sudo pip3 list --outdated …` piped into a user-side install, or vice versa) is the documented anti-pattern that this topic blocks.
- An opinionated curated whitelist of pip-only packages the operator chooses to maintain in `~/.local/lib/python3.X/site-packages/` because they are not RPM-packaged on Fedora 44 (or are packaged at a version too old for the operator's use case). The Topic states that the list is operator-curated; it does not prescribe a specific package set, and a typical curated whitelist on a hardened single-user desktop is around half a dozen packages.

The downstream subsections are framed by this three-component structure: the marker is the only file the role writes; the symmetric discipline and the curated whitelist are operator-policy boundaries the role surfaces but does not edit.

### Marker path discovery

The marker path **must** match `sysconfig.get_path("stdlib")` of the active Fedora-shipped Python interpreter. On Fedora 44 x86_64 this resolves to `/usr/lib64/python3.X/`, **not** `/usr/lib/python3.X/`; the multi-arch convention places the platform stdlib under `/usr/lib64/` rather than `/usr/lib/`. The role's preflight runs

```bash
python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))'
```

and uses the literal output as the install-path. The role's task body does **not** hard-code `/usr/lib/python3.X/` or `/usr/lib64/python3.X/`. Hard-coding `/usr/lib/python3.X/` is the documented bug class — pip on Fedora x86_64 reads the marker from `/usr/lib64/python3.X/`, never from `/usr/lib/python3.X/`, so a marker placed at the `/usr/lib/` path is never consulted and the Layer-2 block is silently absent. Hard-coding `/usr/lib64/python3.X/` is correct on Fedora x86_64 today, but the discovery-based form survives a future architecture change or stdlib-layout change without operator intervention.

### PEP-668 marker

Path: `/usr/lib64/python3.X/EXTERNALLY-MANAGED` (resolved at deploy time as the literal output of `sysconfig.get_path("stdlib")` joined with `/EXTERNALLY-MANAGED`).

```ini
[externally-managed]
Error=System Python on this host is dnf-managed.
 Pip installs only:
   - pip install --user <name>      (per-user tree)
   - python3 -m venv .venv          (project-local venv)
 Override --break-system-packages requires deliberate override.
 Background: PEP 668, Fedora packaging convention.
```

The marker body uses INI form with one `[externally-managed]` section and one multi-line `Error=` key. Lines after the first `Error=` line are continued with leading single-space indentation per the standard INI multi-line value convention; pip reads the entire indented block as the value of `Error=` and renders it verbatim in the `error: externally-managed-environment` output that fires when the marker is consulted.

The marker is **not** RPM-owned. On a correctly applied host:

```bash
rpm -qf /usr/lib64/python3.X/EXTERNALLY-MANAGED
# file /usr/lib64/python3.X/EXTERNALLY-MANAGED is not owned by any package
```

The non-RPM-ownership is a load-bearing invariant. Fedora's stock `python3` packaging on the Fedora 44 baseline does not ship the marker. The marker is operator-policy; if a future Fedora packaging change made `python3` own the file, a `dnf reinstall python3` would `%postun`-remove it and a subsequent `%post`-not-rewrite would silently drop the Layer-2 protection. The role does not place the marker under any RPM-packageable location (no `/etc/python3-pep668-marker.d/`, no `/usr/share/python3/`-side path) for the same reason: the marker stays at the canonical stdlib path, owned by no package, deliberately. The non-ownership invariant also lets the marker survive `dnf upgrade python3` of the same minor version — the upgrade does not own the file, so `%postun` cleanup does not touch it.

### Defense-in-depth boundary

The block on `sudo pip install <pkg>` from a `staff_u`-mapped login is two-layered. The marker is the **second** layer, not the primary block. The strict layer order:

- **Layer 1 — SELinux DAC-caps gap on `staff_sudo_t` (primary block on `staff_u`-mapped hosts).** Plain `sudo pip install <pkg>` from a `staff_u`-mapped login lands in `staff_sudo_t`. This domain is a `sudodomain` but does not inherit `DAC_OVERRIDE` or `DAC_READ_SEARCH` from `staff_t`. pip's writability check on the system site-packages directory (`os.access('/usr/lib64/python3.X/site-packages', os.W_OK)`) returns `False` because the kernel's DAC check fails before SELinux ever evaluates the path. pip interprets the failed writability as "not running as a privileged install context" and falls through to `--user` mode automatically. The marker is **never consulted** on this path — pip only reads the marker after passing the writability check.
- **Layer 2 — PEP-668 marker (block on `sysadm_r:sysadm_t` invocations).** A deliberate `sudo -r sysadm_r -t sysadm_t pip install <pkg>` invocation runs in `sysadm_t`, which carries `DAC_OVERRIDE`. The writability check now succeeds (the directory is writable for `root` with `DAC_OVERRIDE`), so pip proceeds to the marker check. The marker fires `error: externally-managed-environment` and renders the `Error=` block from the file.

The role-switch surface that Layer 2 transits through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md). The Layer-1 DAC-caps gap is the same gap pattern documented in [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md) — used here inverted, as a feature: the gap is what lets pip's writability fallback do the right thing on a plain-`sudo` invocation, rather than as the bug it is in the daemon-readability framing.

### Symmetric pip discipline

The recommended form for operator update scripts is symmetric on the `--user` flag — both the listing and the install run as the operator, against the operator's user-tree:

```bash
pip3 list --outdated --user --format=json \
  | jq -r '.[] | .name' \
  | xargs -r -n1 pip3 install --user -U
```

The asymmetric form is the documented anti-pattern:

```bash
# Anti-pattern: do not use this form.
sudo pip3 list --outdated --format=json \
  | jq -r '.[] | .name' \
  | xargs -r -n1 pip3 install --user -U
```

The asymmetric form lists outdated packages in the **system** Python site-packages tree (because `sudo pip3 list` runs as root and resolves `--user` to root's `~/.local/`, which is empty) and then installs the listed names into the **invoking user's** tree. On a host where the user-tree was last populated under an earlier Python minor (for example `python3.X`) and the system Python has since bumped to `python3.Y`, the listing is empty, so the install loop becomes a no-op. The user's actual `~/.local/lib/python3.X/site-packages/` is never updated; worse, when the operator next bumps Python again (`python3.Y` → `python3.Z`), the `python3.X` user-tree never gets re-built under the new minor and remains as a multi-hundred-megabyte orphan tree on disk. The symmetric form prevents this drift class because both the listing and the install resolve `--user` to the same operator-owned tree.

System-side `pip3 install` is not part of any legitimate update flow on this Topic's deploy profile. The only acceptable `pip` invocations on a hardened host are user-side `pip install --user <name>` for runtime adds and project-local `python3 -m venv` for project-isolated workflows. The marker enforces this for `sysadm_t`-driven `sudo pip` flows; the symmetric-discipline rule enforces it for plain-`sudo`-driven update scripts.

### Curated whitelist

The user-tree contains **only** pip-only packages — those that are not packaged as `python3-<name>` RPMs on Fedora 44, or are packaged but at a version too old for the operator's use case. The curated whitelist is operator-curated; this Topic states the convention but does not name specific packages. A typical curated whitelist on a hardened single-user desktop is around half a dozen packages.

The whitelist is the list of packages the operator chooses to keep in the user-tree; the update flow updates **all** outstanding packages in the user-tree without consulting the whitelist (the whitelist is enforced at install time, not update time). The operator audits the user-tree at every Python minor-bump (`python3.X` → `python3.Y`): each surviving package is re-evaluated for "still pip-only?" against the current Fedora 44 RPM shadow. Pip-only packages that turn out to be RPM-shadowed are removed from the user-tree at the next minor-bump; the operator switches to the RPM via `dnf install python3-<name>`.

### Minor-bump migration

The operator runs the canonical migration sequence at every Fedora Python minor-bump. The migration is **not** automated by the role: there is no automatic mechanism in pip, dnf, or systemd to move PEP-668 markers across Python minors, and the curated whitelist is operator-policy that the role does not own. The role's preflight detects a marker mismatch (marker exists at one stdlib path but not at the active interpreter's stdlib path) and surfaces a `pause:` task with the migration sequence; subsequent re-applies after the operator has run the migration are fully idempotent.

1. Before the `dnf` transaction that bumps Python, capture the current curated whitelist by listing `~/.local/lib/python3.X/site-packages/` top-level distributions.
2. Apply the `dnf` transaction. Fedora's Python minor-bump installs the new interpreter alongside (or replaces, depending on the release vehicle) the previous one. The old `~/.local/lib/python3.X/` user-tree remains on disk; nothing references it any more (no `python3.X` interpreter binary remains in `/usr/bin/`).
3. Re-install the curated whitelist into the new user-tree under `python3.Y`: `pip install --user <pkg-1> <pkg-2> …`.
4. Remove the orphan old user-tree: `rm -rf ~/.local/lib/python3.X`.
5. Re-create the PEP-668 marker at the **new** stdlib path. Run `python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))'` to confirm the new path, then write the marker there with mode `0644 root:root` under `sudo -r sysadm_r -t sysadm_t`.
6. Remove the **old** marker at `/usr/lib64/python3.X/EXTERNALLY-MANAGED` if the old stdlib directory still exists (it usually does — Fedora keeps multiple parallel `python3.X` directories for transitional periods).
7. Remove any `/usr/local/lib/python3.X/` sudo-pip residue accumulated by accidental pre-marker `sudo pip install` invocations. This is the trigger pattern for the orphan-tree drift class documented under §"Orphan tree cleanup".
8. Run the live-test under §"Verification — live-test" to confirm the new marker is enforced.

### Orphan tree cleanup

Two distinct orphan-tree classes can accumulate on a host that has run an asymmetric update script across multiple Python minor-bumps, or that has run `sudo pip install` before the marker was placed.

- **User-tree orphans** at `~/.local/lib/python3.X/` for any `python3.X` interpreter no longer installed. These accumulate from natural Python-minor bumps when the migration discipline above was not followed; cumulative size on a multi-year host can reach single-digit GB.
- **System-tree sudo-pip layers** at `/usr/local/lib/python3.X/` and `/usr/local/{bin,sbin}/pip*`. These accumulate from `sudo pip install <pkg>` invocations made before the marker was deployed, or from a single accidental `sudo -r sysadm_r -t sysadm_t pip install <pkg>` invocation made before the marker was placed at the correct stdlib path (the path-shape bug under §"Marker path discovery"). Cumulative size ranges from kilobytes to tens of megabytes per drift event.

The cleanup commands:

```bash
# User-tree orphans (user shell, no role-switch needed)
rm -rf ~/.local/lib/python3.X        # for each non-active python3.X minor

# System-tree sudo-pip layer (sysadm_r:sysadm_t)
sudo -r sysadm_r -t sysadm_t rm -rf /usr/local/lib/python3.X
sudo -r sysadm_r -t sysadm_t rm -f /usr/local/bin/pip /usr/local/bin/pip3 \
                                   /usr/local/bin/pip3.X /usr/local/sbin/pip3
```

The role-switch is structural for the system-tree path: `staff_sudo_t` lacks the DAC capabilities to traverse and remove under `/usr/local/lib/`, so `sudo rm -rf` from a `staff_u`-mapped login fails with `Permission denied`. The user-tree path runs as the operator and does not require a role-switch.

### File modes

The role writes one file. The modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK, applying the explicit `chmod 0644` reflex established in [UMASK 0027](../foundation/umask.md). Without the explicit mode-set, the operator UMASK 0027 would land the file at `0640 root:root`; pip reads the marker as the unprivileged user (after the writability check fails, the marker-check path is exercised on a `sysadm_t`-only invocation), and `0640 root:root` would mask the file from the unprivileged read and silently bypass the marker.

| Path | Mode | Owner | RPM-owned? |
|---|---|---|---|
| `/usr/lib64/python3.X/EXTERNALLY-MANAGED` | `0644` | `root:root` | no |

The path's `python3.X` minor placeholder is resolved at deploy time from `sysconfig.get_path("stdlib")`. The non-RPM-ownership is asserted by `verify.sh` and is the load-bearing invariant for the marker's survival across `dnf` operations on the `python3` package.

### Idempotence and rollback

The role's modify stage is idempotent. The marker body is rendered from a Jinja template into the discovered stdlib path; the `ansible.builtin.copy` (or `ansible.builtin.template`) module's content-hash check makes the write a no-op on subsequent re-applies if the body and mode already match. The role removes any non-active-minor marker file under `/usr/lib64/python3.*/EXTERNALLY-MANAGED` whose `python3.*` interpreter is no longer installed (orphan-marker cleanup). The role detects orphan user-trees and orphan sudo-pip layers via `find` and surfaces them in a report; the role does **not** auto-remove them — the operator runs the migration `pause:` task explicitly because the cleanup is destructive against operator data even when the data is dead. On a correctly applied host every modify task reports `ok` (no `changed`). Stated as a claim, not a guarantee.

The rollback posture is two-stage.

- **Stage 1.** Remove the marker only:

  ```bash
  sudo -r sysadm_r -t sysadm_t rm -f /usr/lib64/python3.X/EXTERNALLY-MANAGED
  ```

  Reverts only the second-layer defense; the SELinux DAC-caps gap on `staff_sudo_t` continues to block plain-`sudo pip install` invocations from a `staff_u`-mapped session, but a deliberate `sudo -r sysadm_r -t sysadm_t pip install <pkg>` now writes to `/usr/lib64/python3.X/site-packages/` unblocked. Operator-tree contents remain untouched.

- **Stage 2.** In addition to Stage 1, drop the symmetric `--user` discipline from operator update scripts. Reverts the topic-owned pip-discipline surface entirely. The host returns to a state where pip behaviour is governed only by Foundation Layer 1 (the SELinux DAC-caps gap on `staff_sudo_t`) plus pip's own writability fallback.

The role does **not** ship a Stage-2 task. The operator update script is operator-policy, not Topic-policy, and the role does not auto-edit any operator-named file. Filesystem-integrity tracking via the audit and logging baseline is not applied to the marker (the marker is rapidly Python-minor-bump-volatile, so adding it to the integrity database would create more drift noise than signal).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell. The marker write itself happens under `sysadm_r:sysadm_t`; the verify scripts only read state and do not require the role-switch.

### Probe

```bash
bash ansible/roles/topic_python_pip_user_tree/files/probe.sh
```

The probe reports state without judging it. It enumerates the active interpreter identity (`python3 --version`, `python3 -c 'import sys; print(sys.executable)'`), the active stdlib path (`python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))'` — load-bearing for the marker-path resolution), the marker presence across all installed Python minors (`ls -la /usr/lib64/python3*/EXTERNALLY-MANAGED`), the RPM-non-ownership invariant for the active-minor marker (`rpm -qf <marker-path>` — expected output contains `is not owned by any package`), the active pip identity (`pip3 --version`), the user-tree presence per Python minor (`ls -d /home/<user>/.local/lib/python3.*`), the sudo-pip-layer detection (`ls -d /usr/local/lib/python3.*` and `ls /usr/local/bin/pip* /usr/local/sbin/pip*`; expected: empty), and the PATH-resolution probe (`type -a pip3`; expected output lists `/usr/bin/pip3` only). The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_python_pip_user_tree/files/verify.sh
```

The verify script computes the expected marker path from `sysconfig.get_path("stdlib")` plus `/EXTERNALLY-MANAGED` rather than from a hard-coded constant — the path varies by Python minor and by Fedora architecture. The hardcoded expected set:

| Property | Expected value |
|---|---|
| Marker file at `<stdlib>/EXTERNALLY-MANAGED` exists | yes |
| Marker mode | `644` |
| Marker owner | `root:root` |
| Marker is not RPM-owned | `rpm -qf <marker-path>` exits non-zero or output contains `is not owned by any package` |
| Marker first line | `[externally-managed]` |
| Marker contains an `Error=` line | yes |
| `/usr/local/lib/python3.*` directory count | `0` |
| `/usr/local/bin/pip*` and `/usr/local/sbin/pip*` file count | `0` |
| Orphan user-tree count | `0` (each `~/.local/lib/python3.X/` directory must have its corresponding `python3.X` interpreter at `/usr/bin/python3.X`; a tree without an interpreter is an orphan) |

The verify script does **not** assert a specific pip version (operator-policy free-floating). It does **not** enforce a specific package whitelist (operator-policy outside Topic scope). It does **not** ship a `MainPID` liveness check, a `[ -d /proc/$pid ]` liveness check, an `EXPECTED_NNP`, an `EXPECTED_PROTECT_*`, an `EXPECTED_PRIVATE_*`, an `EXPECTED_RESTRICT_*`, an `EXPECTED_LOCK_PERSONALITY`, an `EXPECTED_MDWE`, an `EXPECTED_SYSCALL_FILTER_*`, or an `EXPECTED_CAP_BOUNDING_SET`. There is no daemon to harden and no daemon to liveness-check; presence of any of these constants in `verify.sh` is itself drift against the present end-state.

### Verification — live-test

The canonical live-test is a two-step sequence. Both steps require the live host (Ansible `--check` does not exercise the runtime pip resolution path).

- **Step 1 (positive — marker fires).**

  ```bash
  sudo -r sysadm_r -t sysadm_t pip install <fresh-pkg>
  ```

  The `<fresh-pkg>` placeholder must be chosen so the package is **not** currently installed on the host and is **not** on the curated whitelist. Expected output begins with `error: externally-managed-environment` and contains the verbatim body of the `Error=` block from the marker. A package that is already installed produces `Requirement already satisfied: …` before the marker check fires and is therefore not a valid live-test target.

- **Step 2 (negative — plain sudo cannot reach the marker).**

  ```bash
  sudo pip install <fresh-pkg>
  ```

  No role-switch. Expected behaviour: pip detects the writability failure on system site-packages, prints `Defaulting to user installation because normal site-packages is not writeable`, and proceeds toward a user-tree install. The marker check is **not** reached on this path; the live-test confirms the writability-vs-marker layering. The operator interrupts the install with `Ctrl-C` before completion to avoid contaminating the user-tree with the test package.

The role-switch boundary is load-bearing for Step 1: only a `sudo -r sysadm_r -t sysadm_t pip install <fresh-pkg>` invocation drives pip past the writability check (which `staff_sudo_t` fails) and into the marker-check path (which the marker blocks). A plain-`sudo` live-test never reaches the marker-check path and produces a misleading `--user` fallback that does **not** validate the marker. The role-switch surface is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Pre-hardening recon

Before deploying the Topic, the operator runs the informational recon (no action):

```bash
python3 --version
python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))'
ls /usr/lib64/python3*/EXTERNALLY-MANAGED 2>/dev/null
ls -d /home/<user>/.local/lib/python3.* 2>/dev/null
ls -d /usr/local/lib/python3.* 2>/dev/null
ls /usr/local/bin/pip* /usr/local/sbin/pip* 2>/dev/null
```

On a stock host without the Topic applied, the marker listing is empty (Fedora distribution policy does not ship the marker); the user-tree listing typically shows one or more `python3.X/` directories from prior pip activity; the `/usr/local/lib/python3.X/` listing is empty unless the operator has previously run `sudo pip install` (the trigger pattern for the orphan-layer drift class). The role's preflight stage runs the same recon and reports the outcome non-fatally. A non-empty `/usr/local/lib/python3.*` finding on a vanilla host signals the operator to clean up before deploying.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md) — The Layer-1 SELinux DAC-caps gap on `staff_sudo_t` is the same UMASK-027-derived file-readability gap pattern documented in the daemon-readability framing. This Topic uses the gap inverted: as a feature that lets pip's writability fallback do the right thing on a plain-`sudo` invocation, rather than as the bug that masks daemon-config files. The same `chmod 0644` reflex documented for Foundation Layer 0 applies to the marker write to keep the file readable for pip's unprivileged-side marker check.
