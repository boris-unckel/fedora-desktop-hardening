<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Flatpak collection-id binding repair

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the persistent-state repair an operator applies to every system-wide Flatpak ostree-typed remote whose per-remote configuration block in `/var/lib/flatpak/repo/config` lacks a `collection-id=` entry. The repair is one role-switched `flatpak remote-modify --collection-id=<binding> <remote>` call per affected remote, followed by a single trailing `flatpak update --appstream` AppStream refresh. The two well-known third-party remotes carrying public collection-id bindings on Fedora 44 are `flathub` (collection-id `org.flathub.Stable`) and `gnome-nightly` (collection-id `org.gnome.Nightly`); both bindings are upstream-published constants, declared in the upstream `.flatpakrepo` files of the respective projects and stable since the introduction of collection-bindings. The repair is per-remote, idempotent in effect, and structurally independent of the GPG signature posture of the targeted remote — the binding is an ostree configuration property, not a signing-key property. This topic applies on hosts where the operator login is mapped to the confined SELinux user `staff_u` and Flatpak system-store maintenance is issued from the role-switched `sysadm_t` admin context against the system-wide remote inventory at `/var/lib/flatpak/repo/`.

This topic does **not** cover the full ostree configuration model (the schema of `/var/lib/flatpak/repo/config`, the `[core]` section, the per-remote `[remote "<name>"]` section's full field set including `url=`, `gpg-verify=`, `gpg-verify-summary=`, `xa.title=`, `xa.comment=`, `xa.description=`, `xa.deploy-collection-id=`, `xa.disable=`, `xa.filter=`, etc.); the topic confines itself to the single field `collection-id=` and refers any operator who wants the full schema to upstream documentation. Out of scope as well: the Flatpak permission/sandbox model (`flatpak override`, the `[Context]` section format of override-store files, the application-side sandbox-permission posture — owned by separate topics in this tree), the Document portal cache-lifecycle reflex (owned by a separate topic), the per-Flatpak-application sandbox-permission posture (owned by application-specific topic articles), the `staff_u`-mapping deployment decision (owned by Foundation Layer 1), Flatpak-side workarounds (for example `flatpak remote-delete <remote>` followed by `flatpak remote-add <remote> <flatpakrepo-url>` to reinitialize the remote with the modern `collection-id=` line baked in by the upstream `.flatpakrepo` file — the canonical operator-facing repair path is the in-place `flatpak remote-modify --collection-id=<binding>` invocation documented here, because it preserves all other per-remote configuration without requiring a re-pull of the affected refs), per-user Flatpak installs (`flatpak install --user`, store under `~/.local/share/flatpak/`; the same gap can occur on the per-user store but the surrounding hardening posture is owned by separate articles), GPG-key rotation, GPG-trust-store maintenance, the `gpg-verify=` field interaction with the binding (the binding and the GPG verification are orthogonal mechanisms), and custom collection-id minting for self-hosted Flatpak repos. The `systemd-analyze security` numeric score model is also out of scope: this topic ships no system-side service unit and the score model does not apply.

## End-state configuration

The end-state ships **no** operator-installed file. There is no systemd unit, no systemd drop-in, no `/etc/profile.d/` script, no configuration file under `/etc/flatpak/`, no polkit rule, no sudoers fragment, no desktop-entry override, no SELinux CIL module, no `semanage fcontext` mapping, no `restorecon` invocation, and no file-label change. The end-state is a persistent on-disk repair of the per-remote `collection-id=` field inside the existing system-wide Flatpak ostree store at `/var/lib/flatpak/repo/config`, applied via the `flatpak remote-modify` CLI from the role-switched `sysadm_t` admin context.

### Topic identity

The runtime artefacts under repair are the per-remote sections in `/var/lib/flatpak/repo/config` (the ostree-layer INI store backing the system-wide Flatpak install at `/var/lib/flatpak/`). The end-state depends on two stock packages on Fedora 44 or later: `flatpak` (provides `/usr/bin/flatpak` and the `flatpak remote-modify` subcommand; provides the SELinux type binding for `/var/lib/flatpak/` and the per-remote configuration file) and `ostree` (provides the underlying ostree library that owns the `collection-id` binding semantics; the topic does not invoke the `ostree` CLI directly, but the library is the load-bearing transitive dependency for the binding behaviour). The topic does not require an additional package install. The role's preflight asserts both packages are present and aborts fail-fast on a missing entry. The topic is structurally out of scope on hosts that have no system-wide Flatpak install (`/var/lib/flatpak/repo/` does not exist), on hosts whose only Flatpak install is per-user, and on hosts whose system-wide remote inventory contains only OCI-typed remotes; in each case the role's preflight emits an informational note and exits without applying the modify action. The topic applies to operators whose desktop login is mapped to `staff_u`.

### Topic shape — persistent-state configuration repair

This topic occupies a structurally different shape than the sibling Flatpak topics in this tree. It is **not** a single-rule CIL gap-patch (no SELinux module is shipped), **not** a runtime-cache-lifecycle reflex (no per-user user-systemd unit is restarted, no FUSE-anchored truth path is consulted), **not** a sandbox bind-mount AVC patch (no `staff_t × device_t` allow), and **not** a portal-permission default-deny (no per-application portal-DB write). The end-state is a persistent on-disk repair of the system-wide Flatpak ostree store's per-remote `collection-id=` binding on every affected remote. Every downstream subsection is framed by this structural fact: the role's `tasks/main.yml` orders preflight → per-remote modify loop → conditional AppStream refresh → post-modify verify; the modify stage is exactly two mutating call classes per applicable remote (the `flatpak remote-modify --collection-id=<binding>` call and the trailing single `flatpak update --appstream`); no system-wide artefact is written under `/etc/`; no file label is altered; the role's `files/` directory contains exactly the probe and verify scripts plus the role README.

### Functional symptom

On a host where one or more system-wide Flatpak ostree-typed remotes lack the `collection-id=` binding, `flatpak update` from any role-switched admin context emits one warning per affected ref of the form

```text
Warning: Treating remote fetch error as non-fatal since <ref> is already installed: No such ref '<ref>' in remote <name>
```

and silently skips the affected refs. The exit status of `flatpak update` is `0` even when the entire batch is skipped: the warning class is non-fatal by design. The practical consequence: an operator who relies on `flatpak update` for maintenance of installed runtime, extension, and application refs accumulates an unbounded update lag on every ref originally pulled from a `collection-id`-less remote, with no negative signal in the operator-facing output beyond the warning text. The lag is on the order of months on a typical hardened desktop where `flatpak update` is the only update path for the affected refs. The silent-skip property is the load-bearing operator-side rationale for this repair: the deploy is not about closing a denial — it is about restoring a maintenance path that appears to work but in fact is a no-op.

### Root cause

Flatpak `>= 1.13` uses ostree collection-bindings (`ostree.collection-binding` ref-metadata, persisted per-remote as `collection-id=` in `/var/lib/flatpak/repo/config`) to identify refs across remotes deterministically. On a host whose system-wide Flatpak install was initialized with a Pre-1.13 Flatpak — the Pre-1.13 versions emitted no `collection-id=` line on `flatpak remote-add`, because the collection-bindings concept did not yet exist — the per-remote sections in `/var/lib/flatpak/repo/config` carry no `collection-id` field. On a `>= 1.13` Flatpak the missing field forces the ref-resolution code path to fall back to a URL-based heuristic; the heuristic does not stably re-bind the existing refs to the configured remote, the fetch fails the lookup, and Flatpak treats the failure as non-fatal because the ref is already installed and the update can be deferred until the next pass — at which point the same heuristic fails the same way, and the loop is closed. The heuristic-vs-binding split is the root cause; the missing `collection-id=` line is the artefact-side anchor. The underlying ostree-side mechanism is documented upstream; the repair surface this topic targets is the per-remote `collection-id=` line, not the ostree internals.

### Remote-type discrimination

Flatpak supports two remote-payload formats: the historical **ostree** format (canonical examples: the public Flathub remote at `https://dl.flathub.org/repo/`, the GNOME-nightly remote at `https://nightly.gnome.org/repo/`) and the newer **OCI** format (canonical example: the Fedora-shipped `fedora` remote at `oci+https://registry.fedoraproject.org`). The `collection-id=` field is an ostree-layer property and is meaningful only on ostree-typed remotes. OCI-typed remotes do not negotiate ref identity through ostree collection-bindings; their per-remote sections in `/var/lib/flatpak/repo/config` legitimately do not contain a `collection-id=` line and do not require this repair. The role's preflight inspects each configured remote's URL prefix (`oci+` indicates an OCI-typed remote; anything else indicates an ostree-typed remote) and applies the repair only to ostree-typed remotes that lack the binding.

### Reset action

The role-switched mutating sequence is reproduced byte-exact:

```bash
sudo -r sysadm_r -t sysadm_t flatpak remote-modify \
  --collection-id=org.flathub.Stable flathub
sudo -r sysadm_r -t sysadm_t flatpak remote-modify \
  --collection-id=org.gnome.Nightly gnome-nightly
sudo -r sysadm_r -t sysadm_t flatpak update --appstream
```

The first two calls each open `/var/lib/flatpak/repo/config`, write a single `collection-id=<binding>` line into the named remote section (creating it if absent), and exit. The third call refreshes the per-remote AppStream metadata against the now-bound remote (one HTTPS round-trip per remote) and is the operator-facing signal that the repair has taken effect — on the next `flatpak update` pass the per-ref resolution succeeds against the bound remote and the previously-skipped refs become updatable. The role-switch surface is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md): plain `sudo` from a `staff_u`-mapped login lands in `staff_sudo_t`, which lacks the DAC capability to write reliably against the UMASK-027-locked Flatpak system store and additionally lacks the SELinux write transition the policy expects for the system-wide remote configuration; the role-switched `sudo -r sysadm_r -t sysadm_t` form is the canonical escalation path.

The `org.flathub.Stable` and `org.gnome.Nightly` literals are upstream-published constants; the role hardcodes them as defaults for the two remotes named above and supports an operator-defined override via the Ansible `defaults/main.yml` mapping for any additional system-wide remote the operator has configured.

### Out-of-scope — flatpak repair

`sudo -r sysadm_r -t sysadm_t flatpak repair --system` verifies the integrity of the on-disk ostree object store (checksum each blob, re-validate trees, prune dangling refs) and does **not** mutate the per-remote configuration in `/var/lib/flatpak/repo/config`. A `repair` run on an affected host completes successfully without writing any `collection-id=` line and without changing the silent-update-skip behaviour. An operator who has already tried `flatpak repair` and observed no improvement has correctly observed the no-effect of that command on this surface; the repair this topic ships is the only structurally-correct path. The no-effect property is a stable end-state property of the `flatpak repair` command on the Fedora-44 baseline.

### Diagnose reflex

The diagnostic for the silent-skip class on an unrepaired host is the count of `Treating remote fetch error as non-fatal` lines emitted during a `flatpak update` pass on a host where no actual update is expected to be applied. A high line-count (typically ten or more on a hardened desktop) combined with a zero update count is the load-bearing fingerprint. A naive reflex of grepping the warning text alone is an under-signal: a single warning can occur from an unrelated cause (transient network condition, single broken ref). The combination of high warning-line-count and zero applied updates is the signature this topic addresses. The dry-run form `flatpak update --noninteractive --no-deploy` produces the same warning class without exercising the deploy code path and is the form the role's probe and verify use.

### File modes

| Path | Mode | Owner:Group | SELinux type |
|---|---|---|---|
| `/var/lib/flatpak/repo/config` | `0644` (host-default) | `root:root` | `flatpak_var_lib_t` (host-default for the Flatpak system store) |

The file is owned by the stock `flatpak` package's runtime initialization, not by this role; the role does not alter its mode, owner, or SELinux type. The file is mutated in place by the `flatpak remote-modify` invocation, which preserves mode, owner, and SELinux type by design — the underlying ostree configuration-write code path opens the file with `O_RDWR` rather than `O_CREAT`. No `chmod`/`chown`/`restorecon` reflex is required, and the operator UMASK 0027 reflex documented in the Foundation layer does not apply here, because the role does not write a fresh file under operator UMASK influence.

## Verification

The role's `files/` directory ships two scripts: a read-only probe that operates partially as the operator and partially with role-switched `sysadm_t` for the config-file read and the dry-run line-count, and a Soll/Ist verify that reports per-remote drift attribution. Both scripts run from the operator's user session and are runnable standalone for out-of-band debugging.

### Probe

```bash
bash ansible/roles/topic_flatpak_collection_id/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`rpm -q flatpak ostree`), the operator's runtime SELinux mapping via `id -Z` (the canonical applicability anchor — `staff_u:staff_r:staff_t`; on `unconfined_u` the probe completes but emits an informational note that this topic's framing assumes a `staff_u`-mapped login), the operator-configured remote inventory via `flatpak remotes --columns=name,url,collection` (per row the probe reports whether the URL prefix indicates OCI-typed (`oci+`) or ostree-typed, and whether the `collection` column is empty), the ostree-side authoritative read via `sudo -r sysadm_r -t sysadm_t grep -E '^\[remote |^collection-id=' /var/lib/flatpak/repo/config` (per-remote section heading lines and any `collection-id=` lines present in the file), the diagnostic line-count signal via `sudo -r sysadm_r -t sysadm_t flatpak update --noninteractive --no-deploy 2>&1 | grep -c 'Treating remote fetch error as non-fatal'` (a high value on a host that was supposed to be up-to-date is the load-bearing fingerprint), and the operator-installed ref inventory by remote-of-origin via `flatpak list --app --columns=application,origin` and `flatpak list --runtime --columns=ref,origin` (informational, used to map any silent-skip count back to the affected remote). The probe captures the full output of the dry-run for human inspection alongside the line-count. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling (`flatpak`, `ostree` package not installed).

### Verify

```bash
bash ansible/roles/topic_flatpak_collection_id/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set parameterized by the role's per-remote binding mapping (`topic_flatpak_collection_id_remote_bindings` in `defaults/main.yml`) and exits `0` on a clean match, `1` on drift, and `2` on invocation error. The expected set covers two end-state facts:

| Property | Expected value |
|---|---|
| Per-remote `collection-id=` line under `[remote "<name>"]` in `/var/lib/flatpak/repo/config` | The configured `<binding>` for every `<remote>` in the role's mapping that is currently configured on the host |
| `flatpak update --noninteractive --no-deploy` non-fatal-fetch-warning count | `0` |

The byte-exact ostree-side authoritative read the verify performs is:

```bash
sudo -r sysadm_r -t sysadm_t \
  grep -E '^\[remote |^collection-id=' /var/lib/flatpak/repo/config
```

The expected post-repair shape is one `collection-id=<binding>` line directly under each `[remote "<name>"]` heading for which the role applies a repair, with the `<binding>` value matching the role's defaults (or the operator's override). On a host where the operator has additional ostree-typed system remotes beyond `flathub` and `gnome-nightly`, the verify reports the additional remote sections without asserting a `collection-id=` value (the role's default mapping does not cover unknown remotes; the operator-side decision is whether to extend the role's mapping or accept the additional remote without binding).

The two signals are not redundant. A `collection-id=`-line-only verify would miss a transient upstream condition that re-introduces the warning class against an already-bound remote, and a warning-count-only verify would miss a binding that has been rolled back to the empty-string but where the dry-run happens to produce zero warnings during the verify window. The verify reports the per-remote `collection-id=` line as a per-remote line in its output to make drift attribution unambiguous. `flatpak update --appstream` returning `0` post-reset is a necessary-but-not-sufficient signal in itself: it confirms the AppStream-fetch path resolves against the bound remote, but does not confirm any specific ref will now update — the authoritative end-state signal is the `collection-id=` line in the config file plus the dry-run non-fatal-fetch-warning count. On a host where a remote named in the role's mapping is not currently configured (the operator removed it after the role's last apply), the verify reports the remote as absent and exits `0` with an informational note — the topic is per-remote-applicable, not all-or-nothing. The verify does not trigger `flatpak update` without `--no-deploy`; an unbounded number of refs could be updatable at the time of the call, and producing a deterministic Soll/Ist against that surface is structurally impossible. The deploy itself is the operator's manual call after the role's reset action and is captured by the role's run report, not by the verify. The verify uses `[[ -d /proc/${pid} ]]` for any liveness inspection it ever performs (it does not, in this topic, because the config-file read and the dry-run line-count read are sufficient end-state signals), never `kill -0`: cross-user `kill -0` from a non-privileged context against a foreign-uid PID returns `EPERM` rather than `ESRCH` and would misreport a live process as dead. The verify is post-repair-applicable and is a clean no-op on a host whose targeted remotes already carry the configured binding (every per-remote check passes and the dry-run line-count is zero).

The expected verify output on a correctly applied host is:

```text
OK   collection_id[flathub]                        expected=org.flathub.Stable actual=org.flathub.Stable
OK   collection_id[gnome-nightly]                  expected=org.gnome.Nightly actual=org.gnome.Nightly
OK   nonfatal_fetch_warning_count                  expected=0 actual=0
```

### Cache-state posture

The configuration-state posture has three parts.

**Pre-reset state** on a Pre-1.13-initialized host: the per-remote sections in `/var/lib/flatpak/repo/config` for `flathub` and `gnome-nightly` carry `url=`, `gpg-verify=`, `xa.title=`, and similar fields, but no `collection-id=` line. The `flatpak remotes --columns=name,url,collection` listing shows the corresponding rows with the `collection` column empty. A dry-run `flatpak update --noninteractive --no-deploy` emits one `Treating remote fetch error as non-fatal` warning per ref originally pulled from each of the affected remotes (line-count typically in the five-to-twenty range on a hardened desktop) and reports zero applied updates regardless of upstream artefact freshness. An operator who only reads the warning text and exit-status superficially would conclude the host is up-to-date; the silent-skip count is the load-bearing diagnostic.

**Post-reset state** immediately after the role's reset action: the per-remote sections in `/var/lib/flatpak/repo/config` for the targeted remotes carry one new `collection-id=<binding>` line each (matching the role's defaults or operator-override mapping). The `flatpak remotes --columns=name,url,collection` listing shows the `collection` column populated for the targeted remotes. A dry-run `flatpak update --noninteractive --no-deploy` emits zero `Treating remote fetch error as non-fatal` warnings; the AppStream-fetch path resolves cleanly against the bound remote. The first full `flatpak update` pass after the repair updates any refs that were silently skipped on prior passes; on a host that has been silently skipping for an extended period this initial backlog is typically large (ten or more refs, potentially many tens or hundreds of MiB of accumulated diff per ref).

**Drift signals on an applied host:** any `collection-id=` line absent from a targeted remote's section indicates the binding has been rolled back (root cause typically the operator running `flatpak remote-modify --collection-id="" <remote>` for an unrelated reason — see the rollback paragraph below — or a stock-Flatpak update that re-wrote the remote-config and dropped the binding; both are operator-investigation). A surge of `Treating remote fetch error as non-fatal` warnings post-reset under `flatpak update --no-deploy` is drift caused by this topic if the targeted remotes' bindings are still present (suggests a transient upstream condition that warrants a re-run), and is **not** drift caused by this topic if the warnings name remotes outside the role's mapping (the operator has added a system remote that needs its own binding decision; the role's mapping is the operator-side extension point). `flatpak update --appstream` returning `0` post-reset is a necessary-but-not-sufficient signal — it confirms the AppStream-fetch path resolves against the bound remote, but does not confirm any specific ref will now update. The authoritative end-state signal is the `collection-id=` line in the config file plus one full `flatpak update` pass that updates the previously-skipped refs.

The role's modify stage is idempotent in the Ansible-`--check`-reports-zero-changes sense. For each `<remote>: <binding>` entry in the mapping, the per-remote `flatpak remote-modify --collection-id=<binding> <remote>` call is wrapped in a `changed_when` predicate that re-reads `/var/lib/flatpak/repo/config` after the call and reports `changed=true` only if the targeted remote's `collection-id=` line was added or modified. On a host where the targeted remote already carries the configured binding, the call is a Flatpak-internal no-op (the implementation reads the existing config, computes the merged result, and writes the file only if the merged result differs). The trailing `flatpak update --appstream` is run exactly once per role apply, only if at least one per-remote modify reported `changed=true`; otherwise it is skipped. The dependency is encoded via a registered fact (`__topic_flatpak_collection_id_any_changed`) consulted by the AppStream task's `when:` clause, not via a handler — handlers fire after the entire play and would defer the AppStream refresh past any subsequent task that needs it. On a correctly applied host, `--check` reports zero changes (every per-remote modify reports `changed=false` and the AppStream refresh is skipped). Stated as a claim, not a guarantee.

Recovery: the role ships an explicit per-remote rollback verb only for the `--collection-id=""` empty-string case, which is a Flatpak-side mechanism documented for the rare event of a GPG-key/binding mismatch (the upstream-published binding string changes, and an operator on a host with the prior binding wants to disable collection-binding entirely until the new binding is propagated). The byte-exact rollback form is:

```bash
sudo -r sysadm_r -t sysadm_t flatpak remote-modify \
  --collection-id="" flathub
sudo -r sysadm_r -t sysadm_t flatpak remote-modify \
  --collection-id="" gnome-nightly
```

The empty-string call removes the `collection-id=` line from the targeted remote section. Post-rollback the remote returns to the silent-skip behaviour described in the pre-reset state above. The rollback is per-remote and is the operator's deliberate decision; the role does not auto-rollback on any condition. Boot-failure risk for this topic is structurally zero — the repair operates on a per-remote configuration file under `/var/lib/flatpak/repo/`, which is consulted only at `flatpak`-CLI invocation time and is not part of the system-init pipeline; no boot-time code path reads the `collection-id` field. The Recovery-Pointer banner below is included for tree consistency, even though this topic's failure modes do not include a boot failure.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

This topic does not cross-link any pattern article. The reset reflex repairs a per-remote ostree-layer configuration field on a system-wide Flatpak install whose CLI invocation surface is independent of the system-init pipeline; the repair does not exercise the kernel NoNewPrivileges-transition constraint, the systemd `SystemCallFilter` privilege-drop sequence, the systemd `PrivateMounts` implicit-enable, the systemd `ReadWritePaths` runtime race, the cross-user liveness-probe trap, or any other cross-cutting hardening pattern documented in this tree. The Topic ships no system-wide configuration file under `/etc/`, no SELinux module, no systemd drop-in, and no file-label change — the per-remote `flatpak remote-modify --collection-id=<binding>` invocation under role-switched `sysadm_t` carries the entire deploy.
