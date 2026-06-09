<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Mozilla Firefox

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Application identity

Mozilla Firefox is a desktop web browser. The end-state described here obtains Firefox from the Flathub remote as the application ref `org.mozilla.firefox` and runs it as a system-installed Flatpak on Fedora 44 or later. The stock Fedora `firefox` and `firefox-langpacks` RPM packages are absent on the post-deploy host. The system store lives at `/var/lib/flatpak/`; the application's per-user data path is `/home/<user>/.var/app/org.mozilla.firefox/.mozilla/firefox/`. The Flathub-shipped ref carries the upstream Mozilla build and tracks each upstream point release closely, which is the structural rationale for selecting the Flathub source rather than the Fedora-OCI source: the latter ships the same upstream-to-distribution lag as the RPM build because both flow through the Fedora maintainer pipeline.

## Scope

The end-state described here is the canonical configuration of this topic: a system-wide Flathub install of `org.mozilla.firefox`, a system-wide sandbox-override that scopes the application's filesystem and socket access down from its Flathub-manifest defaults, and a per-Firefox-profile preference seed that activates VAAPI hardware video decoding. The end-state assumes the Fedora-shipped Firefox RPM tree has been removed before the Flatpak ref becomes the operator's primary browser.

Out of scope: the Mozilla-stack mail-client topic is owned by a separate sibling topic in this tree and is not cross-linked from this Reference even by name (the contrast against its hard-deny portal posture is mentioned once in §"Portal posture" as structural-shape illustration only); the OCI-pull DBus token-request denial class is owned by a separate sibling topic and is not cross-linked here because the Flathub-ostree path does not exercise it; the deferred custom SELinux sub-domain `flatpak_browser_t` (a future split that would anchor the application's process tree on a custom binary fcontext, a `staff_t → flatpak_browser_t` type-transition, and a per-user data-tree label, with the goal of limiting post-bwrap-escape blast radius) is forward-mentioned once under §"Related patterns" without article body and without mechanism explanation; the Mozilla-Account sync workflow internals, the operator-side bookmark export workflow, the YubiKey/PCSC integration via the application's `pcsc` socket, the Firefox-side telemetry surfaces beyond the operator-facing VAAPI confirmation surface mentioned once in §"VAAPI preference seed", the operator-side privacy preferences beyond the VAAPI pair, and the Wayland-vs-X11 display-server mechanics beyond the override directive itself are all out of scope. The `systemd-analyze security` numeric score model is also out of scope: the topic ships no system-side service unit and the score model does not apply.

## Topic shape

This topic occupies a structurally different shape than the SELinux-CIL-shaped sibling Flatpak topics in this tree. The end-state is **three-fold**:

A system-wide Flatpak ref `org.mozilla.firefox` from the `flathub` remote is installed under `/var/lib/flatpak/app/org.mozilla.firefox/`. The bwrap-launched application processes run under the operator's stock interactive-shell SELinux domain `staff_u:staff_r:staff_t:s0-s0:c0.c1023`; no custom sub-domain transition fires (the topic ships no CIL module). The Flatpak'd binary at `/var/lib/flatpak/app/org.mozilla.firefox/current/active/files/lib/firefox/firefox` carries the stock `bin_t` label inherited from the Flatpak system store's deploy of the application's runtime tree. The Foundation-layer SELinux baseline plus the SELinux allow rule supplied by the [Flatpak audio sandbox](flatpak-audio-sandbox.md) sibling topic provide the runtime allow surface the application needs at start: the application's bwrap-launched start mounts `/dev/snd` into the sandbox at `/newroot/dev/snd` because the application's Flathub manifest carries `pulseaudio` in the default permission set, and on a stock SELinux baseline the `staff_t × device_t : dir mounton` check fires and aborts the bwrap stage with `Can't bind mount /oldroot/dev/snd on /newroot/dev/snd: Unable to mount source on destination: Permission denied`. The audio-sandbox topic owns the byte-exact CIL allow rule that closes that gap; it is the structural precondition the operator must apply on a stock SELinux baseline before this topic's deploy succeeds.

A system-wide sandbox-override at `/var/lib/flatpak/overrides/org.mozilla.firefox` declares an explicit negative filesystem-policy and an explicit Wayland-only socket-policy. The override is the load-bearing operator-controlled hardening: the application's Flathub manifest declares broad `filesystems=host`/`filesystems=home` permissions by default, and the negative override is what scopes the sandbox down to a `home`-deny end-state with `xdg-download` as the only operator-data path inside the sandbox.

Per-Firefox-profile preference seeds at `/home/<user>/.var/app/org.mozilla.firefox/.mozilla/firefox/<profile>/user.js` activate VAAPI hardware video decoding through two `user_pref(...)` lines. The preference seed is independent of the sandbox-override and applies per profile.

## End-state configuration

The end-state ships **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/firefox/` or `/etc/mozilla/`, **no** polkit rule, **no** sudoers fragment, **no** desktop-entry override under `/usr/share/applications/`, **no** SELinux CIL module, **no** `semanage fcontext` mapping, **no** `restorecon` invocation, and **no** file-label change. The end-state is the system-wide Flatpak ref install, the system-wide sandbox-override file, and the per-profile preference seed, applied via the `flatpak install --system` and `flatpak override --system` CLI from the role-switched `sysadm_t` admin context and via a per-profile block-write under the operator's own UID.

### System-install

The system-wide install of the application ref is issued from the role-switched `sysadm_t` admin context against the `flathub` remote:

```bash
sudo -r sysadm_r -t sysadm_t flatpak install -y --system flathub org.mozilla.firefox
```

The install pulls the Flathub-shipped ref over the ostree transport, deploys it under `/var/lib/flatpak/app/org.mozilla.firefox/`, exports the application's desktop entry as a symlink under `/var/lib/flatpak/exports/share/applications/org.mozilla.firefox.desktop`, and refreshes the AppStream metadata for the remote. The role-switch surface is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md): plain `sudo` from a `staff_u`-mapped login lands in `staff_sudo_t`, which lacks the DAC capability to write reliably against the UMASK-027-locked Flatpak system store and additionally lacks the SELinux write transition the policy expects against the system-wide Flatpak store; the role-switched form is the canonical escalation path. The application ref is installed on the `stable` branch by default; the role does not pin a specific point release, and on every `flatpak update` pass the deployed branch promotes to the latest available point release at the Flathub remote.

### RPM-removal posture

The end-state assumes the Fedora-shipped Firefox RPM tree is absent. The canonical removal set on a Fedora 44 host is four packages: `firefox` and `firefox-langpacks` (the RPM Firefox itself and its language pack provider), `mozilla-openh264` (the OpenH264 codec provider, no operator-relevant function once the RPM Firefox is gone), and `mozilla-filesystem` (the directory provider for `/usr/lib*/mozilla/native-messaging-hosts/`; on a host where the operator runs no Native-Messaging bridges, the directory provider is a no-op orphan). A trailing `dnf autoremove` typically picks up `gnome-browser-connector` (the GNOME-Shell-Browser-Connector Native-Messaging provider) and `speech-dispatcher-utils` as packages whose RPM dependency chain rooted at the Firefox RPM is now empty.

The role's preflight runs an explicit SONAME-aware reverse-dependency probe before staging the removal: for each package in the removal set, the preflight enumerates the package's `.so` files via `rpm -ql <pkg> | grep '\.so'` and runs `rpm -q --whatrequires '<libfoo.so.N>()(64bit)'` against each SONAME. The probe aborts fail-fast on a non-empty reverse-dependency list, because the plain `rpm -q --whatrequires <pkg>` query does not surface SONAME-level dependencies and would let a removal silently break a downstream consumer. The end-state RPM inventory is `rpm -qa | grep -iE '^(firefox|thunderbird|mozilla)'` returning empty.

### Sandbox override

The role writes the sandbox-override file at `/var/lib/flatpak/overrides/org.mozilla.firefox` via a single `flatpak override --system` invocation under role-switched `sysadm_t`. The byte-exact form:

```bash
sudo -r sysadm_r -t sysadm_t flatpak override --system org.mozilla.firefox \
  --nofilesystem=host --nofilesystem=home \
  --filesystem=xdg-download \
  --nosocket=x11 --socket=wayland
```

The post-override file content is a `[Context]` block carrying `filesystems=xdg-download;!host;!home;` and `sockets=wayland;!x11;`. The override file is mutated in place by the `flatpak override --system` code path (the implementation reads the existing override, computes the merged result, and writes the file only if the merged result differs); mode and owner are preserved by design, and the override takes effect on the next application start, not on a restart of any system service. The override is the load-bearing operator-controlled hardening: the application's Flathub manifest declares broad defaults, and the negative override scopes the sandbox down.

The post-override permission table reported by `flatpak info --show-permissions org.mozilla.firefox` carries seven rows on the post-deploy host:

| Permission class | Value |
|---|---|
| `shared` | `ipc;network` |
| `sockets` | `cups;pcsc;pulseaudio;wayland` |
| `devices` | `all` |
| `features` | `devel` |
| `filesystems` | `xdg-config/gtk-3.0:ro;xdg-download;/run/.heim_org.h5l.kcm-socket;xdg-run/speech-dispatcher:ro` |
| `persistent` | `.mozilla` |
| (session-bus / system-bus policy) | (Manifest-default) |

The `sockets` row carries `pulseaudio`, `wayland`, `cups`, and `pcsc` from the Manifest defaults; `x11` is absent because the override removes it. The `filesystems` row carries `xdg-download` from the override and the read-only Manifest-default entries for the GTK config and the speech-dispatcher runtime path; `host` and `home` are absent because the override removes them. The `devices=all` value is the Manifest default and is **deliberately retained**: the application's videocall workflow over `getUserMedia()` depends on the camera and microphone surface, and `devices=all` is the default access-class for those surfaces; the role does not narrow this further (see §"Portal posture" for the surrounding decision).

The override file is the persistent-state surface; the per-user xdg-document-portal cache is independent of the override file content and survives the on-disk persistence of the override. Pre-override portal tokens (both persistent and transient) continue to grant the application read-access into pre-override file paths until the portal service is restarted. The post-override reset reflex against the per-user xdg-document-portal cache is owned by the [Flatpak portal cache](flatpak-portal-cache.md) sibling topic, which is the canonical reset reflex applied immediately after this topic's override write; the role schedules the reset under the operator's own UID via `systemctl --user restart xdg-document-portal.service` as a regular task with a `become: false` clause. The reset is conditional on the override task reporting `changed=true`; an unchanged override does not invalidate any portal-cache token state.

The role does not run a host reboot and does not restart any system-bus service. The only service restart the role performs is the per-user `xdg-document-portal.service` reset reflex; the operator restarts any running Firefox application instance to pick up the new override and the new VAAPI preference seed. No host reboot is required.

### Portal posture

The end-state portal-permission posture for the `org.freedesktop.impl.portal.access` table on the application ID `org.mozilla.firefox` is **default `ask`**: there are no entries in the Flatpak permission DB at `/var/lib/flatpak/db/org.freedesktop.impl.portal.access` for this application. A `flatpak permission-list org.freedesktop.impl.portal.access` query reports zero rows for `org.mozilla.firefox`. The role does **not** write a `flatpak permission-set ... no` entry for the camera, microphone, or location surfaces under this application ID.

The structural rationale: videocall workflows over `getUserMedia()` are an active operator workflow under this application; a hard-deny on the camera or microphone surface would break every origin uniformly without a per-call confirmation prompt, and the per-call prompt path under default `ask` is the operator-facing decision boundary rather than a sandbox-time policy decision. The sibling Mozilla-stack mail-client topic in this tree does hard-deny those surfaces under its own application ID — its workflow has no `getUserMedia()` path — and the contrast is the structural-shape difference between the two Mozilla-stack topics (named here once without cross-link, because the contrast is structural-shape illustration). An operator with no videocall workflow under this application can extend the role's `defaults/main.yml` mapping to opt into a hard-deny posture without altering the topic's deploy reflex elsewhere.

### VAAPI preference seed

The role writes a single byte-exact append-block to `/home/<user>/.var/app/org.mozilla.firefox/.mozilla/firefox/<profile>/user.js` for each Firefox profile the operator declares in `defaults/main.yml`:

```js
// VAAPI hardware video decoding (operator-side preference seed)
user_pref("media.ffmpeg.vaapi.enabled", true);
user_pref("media.hardware-video-decoding.force-enabled", true);
```

The role uses an Ansible `blockinfile` with a unique marker; a re-run on a host whose `user.js` already carries the block is a functional no-op. The rationale for using `user.js` rather than editing `prefs.js` directly: Firefox re-serializes `prefs.js` at every clean exit, so a direct edit of `prefs.js` does not survive a clean exit; the supplementary `user.js` is the canonical operator-managed override path that Firefox reads at every startup and merges into the in-memory preference table without persisting back to `user.js`. The end-state file mode is `0640 <user>:<user>` (the operator UMASK 0027 is inherited by the append, and the bwrap-launched application reads the file under the same UID, so `0640` is sufficient). The operator-facing confirmation surface for the VAAPI activation is `about:support`; the Reference does not reproduce its expected output because a byte-exact reproduction would be brittle against minor Firefox-version drift.

### Profile seeding

When the operator has an existing host-side Firefox profile tree under `/home/<user>/.mozilla/firefox/` (typically from a prior RPM Firefox install), the role's profile-seeding stage migrates the tree into the Flatpak'd application's data path under `/home/<user>/.var/app/org.mozilla.firefox/.mozilla/firefox/`. The migration is an archive-and-extract round-trip:

```bash
tar --zstd --acls --xattrs -cpf - -C /home/<user>/.mozilla/firefox/ . \
  | tar --zstd --acls --xattrs -xpf - -C /home/<user>/.var/app/org.mozilla.firefox/.mozilla/firefox/
```

The role does **not** create a symbolic link from the Flatpak data path back to the host-side path. The structural rationale: Firefox holds its profile lock as an exclusive `places.sqlite-wal` lock with PID-bound semantics; a symbolic link from the sandbox-side path back to the host-side path would let two Firefox processes (a Flatpak'd one and any leftover host-side one) compete for the same lock and produce a profile-corruption race at concurrent start. The role's profile-seeding stage runs only on a host where no host-side or sandbox-side Firefox process is alive; the role's preflight runs `pgrep -u "${operator_uid}" -f '/usr/(lib64|bin)/firefox/'` and a parallel `pgrep` for the bwrap-launched ref, and aborts fail-fast on a non-empty result.

The seeded tree carries the operator's Mozilla-Account sync anchor inside `places.sqlite`; on first launch of the Flatpak'd Firefox the sync mechanism re-establishes against the operator's account, and the canonical bookmark restore mechanism is the operator's Mozilla-Account sync rather than any local export. An operator-side bookmark export under an external snapshot tree is **not** an import path for the seeding stage — a JSON export carries no sync anchor and would replace the seeded `places.sqlite` with a sync-naive copy. The role seeds one or more named profile directories plus the `profiles.ini` and `installs.ini` index files; the operator declares which named profiles to include in the role's `defaults/main.yml` mapping.

### MIME defaults

On a post-deploy host with the Flathub-installed application ref and the RPM Firefox absent, the standard MIME and scheme-handler defaults all resolve to `org.mozilla.firefox.desktop`. The Flatpak system store exports the application's desktop entry as a symlink:

```text
/var/lib/flatpak/exports/share/applications/org.mozilla.firefox.desktop
  -> ../../../app/org.mozilla.firefox/current/active/export/share/applications/org.mozilla.firefox.desktop
```

The desktop entry's `Exec=` line uses the canonical Flatpak run form:

```text
Exec=/usr/bin/flatpak run --branch=stable --arch=x86_64 \
  --command=firefox --file-forwarding org.mozilla.firefox @@u %u @@
```

The `--file-forwarding @@u %u @@` token pair is the canonical xdg-document-portal forwarding anchor: when an external invoker hands the application a file URL (via `xdg-open` or similar), the URL flows through the portal so the file becomes visible to the sandbox via the per-token FUSE-mount under `/run/user/${uid}/doc/by-app/org.mozilla.firefox/<token>/`.

The end-state MIME-default resolution on a typical post-deploy host:

| MIME / scheme | Resolves to |
|---|---|
| `text/html` | `org.mozilla.firefox.desktop` |
| `application/xhtml+xml` | `org.mozilla.firefox.desktop` |
| `x-scheme-handler/http` | `org.mozilla.firefox.desktop` |
| `x-scheme-handler/https` | `org.mozilla.firefox.desktop` |
| `default-web-browser` (`xdg-settings get`) | `org.mozilla.firefox.desktop` |
| `xdg-mime query default text/html` | `org.mozilla.firefox.desktop` |

The role does not write any `xdg-mime default` invocation. On a Fedora 44 host whose pre-deploy state already had the same desktop-entry IDs as the post-deploy state, the Flatpak install simply resolves the previously-dangling IDs to the now-resolvable Flatpak-export targets without operator-side mapping intervention. On a host whose pre-deploy MIME mappings point elsewhere, the role's preflight emits an informational note and the operator's manual `xdg-mime default org.mozilla.firefox.desktop <mime>` call is the closing intervention.

### Update path

The application ref's update path runs through the Flathub remote's stock `flatpak update` mechanism. The deploy assumes the system-wide Flatpak install's ostree-typed `flathub` remote in `/var/lib/flatpak/repo/config` carries the upstream-published `collection-id=` binding; on a system-wide Flatpak install initialized with a Pre-1.13 Flatpak the binding was not set at remote-add time, and on those hosts `flatpak update` silently skips the application ref under the standard `Treating remote fetch error as non-fatal` warning class. The binding repair is owned by the [Flatpak collection-id binding repair](flatpak-collection-id.md) sibling topic; it is a precondition the operator must apply on a Pre-1.13-initialized host before the Flathub-shipped application ref participates in `flatpak update`. The role's preflight checks for the binding presence and emits an informational note naming the sibling topic if it is missing.

### File modes

| Path | Mode | Owner:Group | SELinux type |
|---|---|---|---|
| `/var/lib/flatpak/overrides/org.mozilla.firefox` | `0644` (host-default) | `root:root` | `flatpak_var_lib_t` (host-default for the Flatpak system store) |
| `/home/<user>/.var/app/org.mozilla.firefox/.mozilla/firefox/<profile>/user.js` | `0640` | `<user>:<user>` | `data_home_t` (host-default for `/home/<user>/.var/app/`) |

The override file is owned by the stock `flatpak` package's runtime initialization, not by this role; the role does not alter its mode, owner, or SELinux type. The file is mutated in place by the `flatpak override --system` code path, which preserves mode, owner, and SELinux type by design. No `chmod`/`chown`/`restorecon` reflex is required. The per-profile `user.js` file is written under the operator's own UID with operator UMASK 0027 inherited; the resulting `0640` mode is sufficient because the bwrap-launched application reads the file under the same UID.

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. The probe operates partially as the operator (`flatpak list`, `flatpak info --show-permissions`, `flatpak permission-list`, `xdg-mime query`, `xdg-settings get`, the per-profile `user.js` content read) and partially with role-switched `sysadm_t` (the sandbox-override file content read at `/var/lib/flatpak/overrides/org.mozilla.firefox`, the `ausearch` against the AVC stream). Both scripts run from the operator's user session and are runnable standalone for out-of-band debugging.

### Probe

```bash
bash ansible/roles/topic_mozilla_firefox/files/probe.sh
```

The probe reports state without judging it. It enumerates RPM-Firefox-tree absence (`rpm -qa | grep -iE '^(firefox|thunderbird|mozilla)'` — post-deploy: empty), the Flatpak ref inventory (`flatpak list --columns=application,branch,origin,installation,version | grep -E '^org\.mozilla\.firefox'` — post-deploy: one row from the `flathub` remote, `system` installation, branch `stable`), the post-override permission table (`flatpak info --show-permissions org.mozilla.firefox` — post-deploy: the seven rows from §"Sandbox override"), the override-file content under role-switched `sysadm_t` (`sudo -r sysadm_r -t sysadm_t cat /var/lib/flatpak/overrides/org.mozilla.firefox` — post-deploy: the `[Context]` block with `filesystems=xdg-download;!host;!home;` and `sockets=wayland;!x11;`), the portal-permission row count (`flatpak permission-list org.freedesktop.impl.portal.access | grep -E '^org\.freedesktop\.impl\.portal\.access[[:space:]]+(camera|microphone|location)[[:space:]]+org\.mozilla\.firefox'` — post-deploy: zero rows; the probe prints an explicit `(no portal-permission rows for org.mozilla.firefox — default ask)` line in that case), the per-profile VAAPI preference state (`grep -E '^user_pref\("media\.(ffmpeg\.vaapi\.enabled|hardware-video-decoding\.force-enabled)"' /home/<user>/.var/app/org.mozilla.firefox/.mozilla/firefox/<profile>/user.js` — post-deploy: two lines per profile, both with the `, true);` suffix), the MIME-default resolution (`xdg-mime query default text/html` and `xdg-mime query default x-scheme-handler/https` — post-deploy: both `org.mozilla.firefox.desktop`), the live runtime-domain context if a `firefox-bin` process is alive (`cat /proc/${pid}/attr/current` after a `[ -d /proc/${pid} ]` liveness check, never `kill -0`; the canonical assertion target is the substring `staff_t`), and the AVC backlog from boot under role-switched `sysadm_t` (`sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot | grep -E '(firefox|bwrap|flatpak.*org\.mozilla\.firefox)'`; the probe prints `CLEAN` when the filtered output is empty, or empty output if the application has not been started since boot). The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_mozilla_firefox/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match, `1` on drift, and `2` on invocation error. The expected set covers nine independent surfaces, each reported as a separate line in the verify output to make drift attribution unambiguous:

| Property | Expected value |
|---|---|
| RPM Firefox tree absent | `rpm -qa | grep -iE '^(firefox|thunderbird|mozilla)'` returns empty |
| Flatpak ref present | `org.mozilla.firefox` from `flathub`, `system` installation, branch `stable` |
| Override `filesystems=` line | `xdg-download;!host;!home;` (byte-exact, trailing semicolon included) |
| Override `sockets=` line | `wayland;!x11;` (byte-exact, trailing semicolon included) |
| Portal-permission row count for the application | `0` (default `ask` posture) |
| Per-profile VAAPI `user_pref` line count | `2` per profile in the role's mapping |
| Default web browser | `xdg-settings get default-web-browser` returns `org.mozilla.firefox.desktop` |
| Live runtime-domain substring | `cat /proc/${pid}/attr/current` of any live `firefox-bin` process contains the substring `staff_t` (substring assertion, not full-string equality, because the MCS range component is host-specific) |
| AVC backlog from boot | `sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot | grep -E '(firefox|bwrap|flatpak.*org\.mozilla\.firefox)'` returns zero matches |

Liveness is checked through `[[ -d /proc/${pid} ]]`. From a `staff_t` shell, `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the directory-existence form is ownership-independent. The verify reads the override file via the explicit role-switched `sudo -r sysadm_r -t sysadm_t cat /var/lib/flatpak/overrides/org.mozilla.firefox` invocation; it does not invoke any wrapper script. The AVC-clean assertion uses the explicit role-switched `ausearch` invocation `sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot`.

The expected verify output on a correctly applied host:

```text
OK   rpm_firefox_absent                              expected=yes actual=yes
OK   flatpak_ref_present                             expected=org.mozilla.firefox actual=org.mozilla.firefox
OK   override_filesystems                            expected=xdg-download;!host;!home; actual=xdg-download;!host;!home;
OK   override_sockets                                expected=wayland;!x11; actual=wayland;!x11;
OK   portal_permission_row_count                     expected=0 actual=0
OK   user_js_vaapi_line_count[<profile>]             expected=2 actual=2
OK   default_web_browser                             expected=org.mozilla.firefox.desktop actual=org.mozilla.firefox.desktop
OK   runtime_domain_substring                        expected=staff_t actual=staff_t (substring match)
OK   avc_backlog_for_firefox_from_boot               expected=0 actual=0
```

### AVC posture

The AVC posture has two parts.

**Boot-clean expectation.** On a host with the Foundation-layer SELinux baseline plus the audio-sandbox SELinux allow rule supplied by the [Flatpak audio sandbox](flatpak-audio-sandbox.md) sibling topic, `sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot` filtered against the application's process tree (the `firefox`, `bwrap`, and `flatpak.*org\.mozilla\.firefox` keyword set) returns empty. No application-start, sandbox-rebuild, or workflow-driven AVC fires under enforcing SELinux on this end-state. The four-tool diagnosis loop (`ausearch`, `audit2why`, `audit2allow`, `sealert`) for the AVC stream is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

**Drift signals.** A non-empty filtered `ausearch` return is the operator-investigation signal, not an automatic recovery trigger. The most common drift class on a host whose audio-sandbox precondition has lapsed (the CIL module unloaded, or a file fcontext relabel reverted) is the `staff_t × device_t : dir mounton` denial that fires at the next application start; the audio-sandbox sibling topic's verify catches that drift class through its own surface. The most common drift class on a host whose Flathub remote `collection-id` binding has lapsed is **not** an AVC at all but a `flatpak update` `Treating remote fetch error as non-fatal` warning surge against the application ref; the [Flatpak collection-id binding repair](flatpak-collection-id.md) sibling topic's verify catches that drift class through its own surface. Any `permissive=0` denial whose `scontext` is `staff_t` and whose `tcontext` is **not** in the Foundation-layer-baseline-allowed set is a third drift class and is the operator-investigation signal that the application's runtime allow surface has gained a class the baseline does not yet cover.

### Idempotence

The role's modify stage:

- Runs `flatpak install -y --system flathub org.mozilla.firefox` via `ansible.builtin.command` wrapped in a `creates: /var/lib/flatpak/app/org.mozilla.firefox` style guard, so on a host already carrying the application ref the install is a Flatpak-internal no-op and the task reports `changed=false`. On a re-run with a newer upstream point release available at the Flathub remote, the install promotes the host's deployed branch to the latest available point release; the `creates:` guard is conservative against the install-or-noop boundary.
- Runs `flatpak override --system` via `ansible.builtin.command` wrapped in a `changed_when` predicate that re-reads `/var/lib/flatpak/overrides/org.mozilla.firefox` after the call and reports `changed=true` only if the file content was added or modified. The `flatpak override --system` implementation reads the existing override, computes the merged result, and writes the file only if the merged result differs; on a host already in the end-state the call is a Flatpak-internal no-op.
- Runs `systemctl --user restart xdg-document-portal.service` via `ansible.builtin.systemd_service` (`scope: user`) with a `when:` clause consulting a registered fact set by the override task to `true` only if the override task reported `changed=true`. The reset is conditional rather than unconditional because an unchanged override does not invalidate any portal-cache token state.
- Runs the per-profile `user.js` block-edit via `ansible.builtin.blockinfile` with a unique marker; on a host whose `user.js` already carries the block, the block-edit is a no-op.
- Runs the four-package RPM removal via `ansible.builtin.dnf` with `state: absent`, and the trailing `dnf autoremove` via the same module with `autoremove: true`. On a host already in the end-state both calls are DNF-internal no-ops.
- Writes **no** SELinux module, runs **no** `restorecon`, runs **no** `semanage fcontext`, runs **no** `systemctl daemon-reload`, runs **no** system-bus `systemctl restart`, sets **no** SELinux boolean, and invokes **no** `flatpak permission-set` for the application's portal surfaces.

On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

### Recovery posture

The role ships an explicit rollback verb that reverses the three-fold deploy in reverse order. The byte-exact form:

```bash
sudo -r sysadm_r -t sysadm_t flatpak override --system --reset org.mozilla.firefox
sudo -r sysadm_r -t sysadm_t flatpak uninstall -y --system org.mozilla.firefox
sudo dnf install -y firefox firefox-langpacks mozilla-openh264 mozilla-filesystem
# operator-side: restore the host-side profile tree from the operator's external snapshot if applicable
```

Post-rollback, the sandbox-override file at `/var/lib/flatpak/overrides/org.mozilla.firefox` is gone (an empty `[Context]` block is normalized away by `--reset`), the application ref is uninstalled from the system store, the RPM Firefox tree is reinstalled, and the operator's host-side profile tree is restored from the operator's external snapshot. The role does not own the snapshot path; the snapshot is the operator's pre-deploy responsibility, named once in `defaults/main.yml` for documentation but not consumed automatically by the rollback. The rollback requires network access for the RPM reinstall step (the role ships no RPM-cache-backup mechanism by design — the operator's external snapshot covers the profile tree, and the RPM tree is recoverable from the Fedora 44 repository at any time). Boot-failure risk for this topic is **structurally zero**: the application is a post-login user-application; a Flatpak-side or sandbox-side misconfiguration is reversible from `sysadm_t` without rebooting; the application's bwrap-launched process tree has no dependency on `init_t` and cannot block the boot path. The Recovery-Pointer banner below is included for tree consistency, even though this topic's failure modes do not include a boot failure.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

This topic does not cross-link any existing pattern article in this tree. Two slug-only forward-mentions name the trap classes that surround the deploy state described here, neither of which has a written article in this tree: `flatpak-browser-subdomain-cut` (planned pattern explanation, not yet written) names the broader class — a custom SELinux sub-domain anchored on the Flatpak'd browser binary via a custom file fcontext mapping plus a `staff_t → <subdomain>_t` type-transition rule plus a custom data-tree label on the per-user sandbox path under `/home/<user>/.var/app/<appid>/` — that this topic explicitly does not instantiate (the end-state is `staff_t` for the application's process tree, see §"Topic shape"); `flatpak-inner-sandbox-userns-eperm` (planned pattern explanation, not yet written) names the broader class an operator should recognize as benign on the application's startup-time output, where a Flatpak-hosted browser-or-Electron application emits a single line of the form `Sandbox: CanCreateUserNamespace() clone() failure: EPERM` because its inner content-process sandbox setup requests a nested unprivileged user namespace and the bwrap-default seccomp filter denies the request, and the application falls back to its inner-sandbox alternate mode without losing its outer-confinement posture. The mechanism of either class is not reproduced in this topic body; mechanism explanation belongs in the pattern explanation when it is written.
