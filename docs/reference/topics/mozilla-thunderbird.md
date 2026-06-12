<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Mozilla Thunderbird

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Application identity

Mozilla Thunderbird is a desktop email-and-calendar client with built-in OpenPGP key management. The end-state described here obtains Thunderbird from the Fedora-OCI remote (`registry.fedoraproject.org`) as the application ref `net.thunderbird.Thunderbird` and runs it as a system-installed Flatpak on Fedora 44 or later. The stock Fedora `thunderbird` and `thunderbird-librnp-rnp` RPM packages are absent on the post-deploy host. The system store lives at `/var/lib/flatpak/`; the application's per-user data path is `/home/<user>/.var/app/net.thunderbird.Thunderbird/.thunderbird/`. The Fedora-OCI-shipped ref tracks the upstream Rapid-Release cadence with a Fedora-Hardened Manifest, typically reaching the host one upstream point release ahead of the Bodhi-promoted RPM build; the rationale for selecting the Fedora-OCI source rather than the Flathub source (which ships a different application ID on the ESR Major-Stream branch) is that the Fedora-OCI source closes the upstream-to-distribution lag the Fedora maintainer pipeline introduces, while the Flathub-side ESR build would produce an `x-scheme-handler/mailto` desktop-entry-ID mismatch against the host's existing scheme-handler mapping.

## Scope

The end-state described here is the canonical configuration of this topic: a system-wide Fedora-OCI install of `net.thunderbird.Thunderbird`, a system-wide sandbox-override that scopes the application's filesystem and socket access down from its Fedora-Hardened Manifest defaults, and a system-wide three-row portal-permission hard-deny against the camera, microphone, and location surfaces. The end-state assumes the Fedora-shipped Thunderbird RPM tree has been removed before the Flatpak ref becomes the operator's primary mail client.

Out of scope: the Mozilla-stack browser topic is owned by a separate sibling topic in this tree and is not cross-linked from this Reference even by name (the contrast against its default-`ask` portal posture is mentioned once in §"Portal posture" as structural-shape illustration only); the Flathub-remote `collection-id=` binding repair is owned by a separate sibling topic and is not cross-linked here because the Fedora-OCI transport does not exercise that surface; the deferred custom SELinux sub-domain that would anchor the application's process tree on a custom binary fcontext, a `staff_t → <subdomain>_t` type-transition, and a per-user data-tree label is forward-mentioned once under §"Related patterns" (`flatpak-browser-subdomain-cut`) without article body and without mechanism explanation; the application's built-in OpenPGP workflow internals (the key-export/import UI surfaces, the `key4.db` schema, the per-account encrypt-and-sign settings); the operator-side mail-account inventory; the calendar and address-book internals (CardDAV/LDAP integration, per-account synchronisation cadence); the `bubblewrap` package internals (the inner-policy derivation, the `setup_seccomp()` source-anchor, the per-Flatpak-permission-class allow surface); the application-side telemetry and privacy preferences; the Wayland-vs-X11 display-server mechanics beyond the override directive itself; and the YubiKey/PCSC integration via the application's `pcsc` socket are all out of scope. The `systemd-analyze security` numeric score model is also out of scope: the topic ships no system-side service unit and the score model does not apply.

## Topic shape

This topic occupies a structurally different shape than the SELinux-CIL-shaped sibling Flatpak topics in this tree. The end-state is **three-fold**:

A system-wide Flatpak ref `net.thunderbird.Thunderbird` from the `fedora` remote (Fedora-OCI transport, `oci+https://registry.fedoraproject.org`) is installed under `/var/lib/flatpak/app/net.thunderbird.Thunderbird/`. The bwrap-launched application processes run under the operator's stock interactive-shell SELinux domain `staff_u:staff_r:staff_t:s0-s0:c0.c1023`; no custom sub-domain transition fires (the topic ships no CIL module). The Flatpak'd binary at `/var/lib/flatpak/app/net.thunderbird.Thunderbird/current/active/files/lib/thunderbird/thunderbird` carries the stock `bin_t` label inherited from the Flatpak system store's deploy of the application's runtime tree. The Foundation-layer SELinux baseline plus the SELinux allow rule supplied by the [Flatpak audio sandbox](flatpak-audio-sandbox.md) sibling topic provide the runtime allow surface the application needs at start: the application's bwrap-launched start mounts `/dev/snd` into the sandbox at `/newroot/dev/snd` because the application's Fedora-Hardened Manifest carries `pulseaudio` in the default permission set (the application's new-mail audio cue surface drives the dependency), and on a stock SELinux baseline the `staff_t × device_t : dir mounton` check fires and aborts the bwrap stage with `Can't bind mount /oldroot/dev/snd on /newroot/dev/snd: Unable to mount source on destination: Permission denied`. The audio-sandbox topic owns the byte-exact CIL allow rule that closes that gap; it is the structural precondition the operator must apply on a stock SELinux baseline before this topic's deploy succeeds. A second structural precondition applies on hosts running Flatpak 1.18 or later whose kernel exposes the AMD compute device node `/dev/kfd`: the application's Fedora-Hardened Manifest carries `dri` in the `devices=` permission set, Flatpak 1.18 includes `/dev/kfd` in the device-bind set derived from that permission, and on a stock SELinux baseline the bwrap bind-source `stat(2)` aborts the sandbox construction with `bwrap: Can't get type of source /dev/kfd: Permission denied` — with no AVC record, because the denial is `dontaudit`-suppressed. The [Flatpak compute-device bind surface](flatpak-kfd-device.md) sibling topic owns the byte-exact CIL allow rule that closes that gap.

A system-wide sandbox-override at `/var/lib/flatpak/overrides/net.thunderbird.Thunderbird` declares an explicit negative filesystem-policy and an explicit Wayland-only socket-policy. The override is the load-bearing operator-controlled hardening: the application's Fedora-Hardened Manifest declares broad `filesystems=host`/`filesystems=home` permissions by default, and the negative override scopes the sandbox down to a `home`-deny end-state with `xdg-download` as the only operator-data path inside the sandbox. The override leaves the Manifest-default OpenPGP-related filesystem entries (`~/.gnupg`, `xdg-run/gnupg:ro`) untouched: the application's built-in OpenPGP key management depends on operator-side gpg keychain access via the host gpg-agent's `xdg-run/gnupg` socket and the per-user `~/.gnupg` directory tree, and a hard-deny on either entry would break the OpenPGP-signed-and-encrypted mail workflow.

A system-wide portal-permission hard-deny at `/var/lib/flatpak/db/org.freedesktop.impl.portal.access` declares three rows for `net.thunderbird.Thunderbird` covering the `camera`, `microphone`, and `location` portal surfaces, each with the policy value `no`. The hard-deny is the load-bearing operator-controlled scope reduction: a mail-client workflow carries no first-class use of the hardware-camera, microphone, or location surfaces, and a hard-deny short-circuits the per-call portal prompt at the portal backend before the application's own UI surfaces a Yes/No dialog.

## End-state configuration

The end-state ships **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/thunderbird/` or `/etc/mozilla/`, **no** polkit rule, **no** sudoers fragment, **no** desktop-entry override under `/usr/share/applications/`, **no** SELinux CIL module, **no** `semanage fcontext` mapping, **no** `restorecon` invocation, **no** file-label change, and **no** per-profile preference seed (the application has no VAAPI-equivalent operator-side surface in this topic's framing). The end-state is the system-wide Flatpak ref install, the system-wide sandbox-override file, and the three-row portal-permission hard-deny, applied via the `flatpak install --system`, `flatpak override --system`, and `flatpak permission-set` CLI from the role-switched `sysadm_t` admin context.

### System-install

The system-wide install of the application ref is issued from the role-switched `sysadm_t` admin context against the `fedora` remote:

```bash
sudo -r sysadm_r -t sysadm_t flatpak install -y --system fedora net.thunderbird.Thunderbird
```

The install pulls the Fedora-OCI-shipped ref over the OCI transport from `oci+https://registry.fedoraproject.org`, deploys it under `/var/lib/flatpak/app/net.thunderbird.Thunderbird/`, exports the application's desktop entry as a symlink under `/var/lib/flatpak/exports/share/applications/net.thunderbird.Thunderbird.desktop`, and refreshes the AppStream metadata for the remote. The role-switch surface is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md): plain `sudo` from a `staff_u`-mapped login lands in `staff_sudo_t`, which lacks the DAC capability to write reliably against the UMASK-027-locked Flatpak system store and additionally lacks the SELinux write transition the policy expects against the system-wide Flatpak store, the system-wide override directory, and the system-wide portal-permission database. The application ref is installed on the `stable` branch by default; the role does not pin a specific point release, and on every `flatpak update` pass the deployed branch promotes to the latest available point release at the Fedora-OCI remote.

The first system-install of any ref from an OCI-typed remote on a host whose Foundation-layer SELinux baseline does not yet allow the OCI-pull DBus token-request class fails at the install stage. The OCI-pull DBus token-request precondition is owned by the [Flatpak OCI-pull DBus](flatpak-oci-pull-dbus.md) sibling topic, which is the structural precondition the operator must apply on a stock SELinux baseline before this topic's first `flatpak install --system` call succeeds.

### RPM-removal posture

The end-state assumes the Fedora-shipped Thunderbird RPM tree is absent. The canonical removal set on a Fedora 44 host is four packages: `thunderbird` and `thunderbird-librnp-rnp` (the RPM Thunderbird itself and its OpenPGP/RNP backend), and the two Mozilla-stack-shared packages `mozilla-openh264` (the OpenH264 codec provider, no operator-relevant function once the RPM Mozilla stack is gone) and `mozilla-filesystem` (the directory provider for `/usr/lib*/mozilla/native-messaging-hosts/`). The two shared packages are also part of the sibling Mozilla-stack browser topic's removal set; on a host where the sibling topic has already removed them, the `dnf` removal of those two packages is an idempotent no-op for this topic and the role's task reports `changed=false` for them. The trailing `dnf autoremove` typically picks up `gnome-browser-connector` and `speech-dispatcher-utils` as orphans only when the sibling browser topic has not yet been applied; on a host where the browser topic was applied first, `dnf autoremove` reports no further orphans.

The role's preflight runs an explicit SONAME-aware reverse-dependency probe before staging the removal: for each package in the removal set, the preflight enumerates the package's `.so` files via `rpm -ql <pkg> | grep '\.so'` and runs `rpm -q --whatrequires '<libfoo.so.N>()(64bit)'` against each SONAME. The probe aborts fail-fast on a non-empty reverse-dependency list, because the plain `rpm -q --whatrequires <pkg>` query does not surface SONAME-level dependencies and would let a removal silently break a downstream consumer. The end-state RPM inventory is `rpm -qa | grep -iE '^(firefox|thunderbird|mozilla)'` returning empty when both Mozilla-stack topics have been applied, or returning only the browser-side row set when this topic alone has been applied.

### Sandbox override

The role writes the sandbox-override file at `/var/lib/flatpak/overrides/net.thunderbird.Thunderbird` via a single `flatpak override --system` invocation under role-switched `sysadm_t`. The byte-exact form:

```bash
sudo -r sysadm_r -t sysadm_t flatpak override --system net.thunderbird.Thunderbird \
  --nofilesystem=host --nofilesystem=home \
  --filesystem=xdg-download \
  --nosocket=x11 --socket=wayland
```

The post-override file content is a `[Context]` block carrying `filesystems=xdg-download;!host;!home;` and `sockets=wayland;!x11;`. The override file is mutated in place by the `flatpak override --system` code path (the implementation reads the existing override, computes the merged result, and writes the file only if the merged result differs); mode and owner are preserved by design, and the override takes effect on the next application start, not on a restart of any system service.

The post-override permission table reported by `flatpak info --show-permissions net.thunderbird.Thunderbird` carries seven rows on the post-deploy host:

| Permission class | Value |
|---|---|
| `shared` | `ipc;network` |
| `sockets` | `cups;pcsc;pulseaudio;wayland` |
| `devices` | `dri` |
| `features` | (empty) |
| `filesystems` | `xdg-download;xdg-run/gnupg:ro;/run/.heim_org.h5l.kcm-socket;~/.gnupg;xdg-run/speech-dispatcher:ro` |
| `persistent` | `.thunderbird` |
| (session-bus / system-bus policy) | (Manifest-default) |

The `sockets` row carries `pulseaudio`, `wayland`, `cups`, and `pcsc` from the Manifest defaults; `x11` is absent because the override removes it. The `filesystems` row carries `xdg-download` from the override and the read-only Manifest-default entries for the gpg-agent runtime path, the Heimdal Kerberos credential cache socket, the gpg keychain directory tree, and the speech-dispatcher runtime path; `host` and `home` are absent because the override removes them. The Manifest-default `~/.gnupg` (read-write) and `xdg-run/gnupg:ro` (read-only) entries are retained because the application's built-in OpenPGP key management depends on operator-side gpg keychain access; an operator who does not use the application's built-in OpenPGP key management can extend the role's `defaults/main.yml` mapping to opt into a hard-deny posture against `~/.gnupg` and `xdg-run/gnupg:ro` without altering the topic's deploy reflex elsewhere. The `devices=dri` value is the Manifest default and supplies the DRM render-node surface for hardware-accelerated rendering of HTML mail content; the row does not carry the broader `devices=all` value, so the application has no host-camera or host-microphone device-node access through the `devices=` axis. The `features` row is empty because the Fedora-Hardened Manifest does not declare `features=devel` for this application.

The override file is the persistent-state surface; the per-user xdg-document-portal cache is independent of the override file content and survives the on-disk persistence of the override. Pre-override portal tokens (both persistent and transient) continue to grant the application read-access into pre-override file paths until the portal service is restarted. The post-override reset reflex against the per-user xdg-document-portal cache is owned by the [Flatpak portal cache](flatpak-portal-cache.md) sibling topic, which is the canonical reset reflex applied immediately after this topic's override write; the role schedules the reset under the operator's own UID via `systemctl --user restart xdg-document-portal.service` as a regular task with a `become: false` clause. The reset is conditional on the override task or any of the three portal-permission tasks reporting `changed=true`; an unchanged override and unchanged portal-permission database do not invalidate any portal-cache token state.

The role does not run a host reboot and does not restart any system-bus service. The only service restart the role performs is the per-user `xdg-document-portal.service` reset reflex; the operator restarts any running Thunderbird application instance to pick up the new override and the new portal-permission rows. No host reboot is required.

### Portal posture

The end-state portal-permission posture for the `org.freedesktop.impl.portal.access` table on the application ID `net.thunderbird.Thunderbird` is **hard-deny** for the camera, microphone, and location surfaces. A `flatpak permission-list org.freedesktop.impl.portal.access` query reports three rows on the post-deploy host:

```text
org.freedesktop.impl.portal.access  camera      net.thunderbird.Thunderbird  no  0x00
org.freedesktop.impl.portal.access  microphone  net.thunderbird.Thunderbird  no  0x00
org.freedesktop.impl.portal.access  location    net.thunderbird.Thunderbird  no  0x00
```

The role writes the three rows via three `flatpak permission-set` invocations under role-switched `sysadm_t`. The byte-exact form of each invocation:

```bash
sudo -r sysadm_r -t sysadm_t flatpak permission-set \
  org.freedesktop.impl.portal.access camera \
  net.thunderbird.Thunderbird no
sudo -r sysadm_r -t sysadm_t flatpak permission-set \
  org.freedesktop.impl.portal.access microphone \
  net.thunderbird.Thunderbird no
sudo -r sysadm_r -t sysadm_t flatpak permission-set \
  org.freedesktop.impl.portal.access location \
  net.thunderbird.Thunderbird no
```

The `flatpak permission-set` command accepts neither a `--system` nor a `--user` flag: the Flatpak permission database is single-instance, system-wide, and the role-switched `sudo -r sysadm_r -t sysadm_t` invocation is the canonical write path. The structural rationale for the hard-deny posture: a mail-client workflow carries no first-class use of the hardware-camera, microphone, or location surfaces; a hard-deny short-circuits the per-call portal prompt at the portal backend before the application's own UI surfaces a Yes/No dialog, removing both the user-confirmation latency on a rare incidental access attempt and the operator-confusion surface that a per-call prompt would create on a workflow that does not expect it. The sibling Mozilla-stack browser topic in this tree retains default `ask` for the same three surfaces — its videocall workflow exercises camera and microphone — and the contrast is the structural-shape difference between the two Mozilla-stack topics (named here once without cross-link, because the contrast is structural-shape illustration).

The role does **not** write a `flatpak permission-set ... no` entry for the `background` portal surface. The application's mail-background-polling and notification surfaces depend on the default `background` posture, and a hard-deny would suppress new-mail notifications. The role does **not** write a `flatpak permission-set` entry for any portal surface other than the three named above.

### Profile seeding

When the operator has an existing host-side Thunderbird profile tree under `/home/<user>/.thunderbird/` (typically from a prior RPM Thunderbird install), the role's profile-seeding stage migrates the tree into the Flatpak'd application's data path under `/home/<user>/.var/app/net.thunderbird.Thunderbird/.thunderbird/`. The migration is an archive-and-extract round-trip:

```bash
tar --zstd --acls --xattrs -cpf - \
    -C /home/<user>/.thunderbird/ \
    profiles.ini installs.ini <profile-1> <profile-2> ... \
  | tar --zstd --acls --xattrs -xpf - \
        -C /home/<user>/.var/app/net.thunderbird.Thunderbird/.thunderbird/
```

The role does **not** create a symbolic link from the Flatpak data path back to the host-side path. The structural rationale: Thunderbird holds its profile lock as an exclusive file-lock with PID-bound semantics on the per-profile lock file; a symbolic link from the sandbox-side path back to the host-side path would let two Thunderbird processes (a Flatpak'd one and any leftover host-side one) compete for the same lock and produce a profile-corruption race at concurrent start. The role's profile-seeding stage runs only on a host where no host-side or sandbox-side Thunderbird process is alive; the role's preflight runs `pgrep -u "${operator_uid}" -f '/usr/(lib64|bin)/thunderbird/'` and a parallel `pgrep` for the bwrap-launched ref, and aborts fail-fast on a non-empty result.

The role's `tar` invocation packs a **selective** subset of the host-side profile tree by default: `profiles.ini`, `installs.ini`, and one or more named profile directories declared in `defaults/main.yml`. Obsolete profile directories that the operator does not list are deliberately omitted from the archive. The seeded `profiles.ini` may continue to reference a `Default=` entry whose directory was deliberately excluded from the seeded set; in that case the application's Profile Manager UI surfaces the stale entry on first launch and the operator removes it interactively (the role does not auto-edit `profiles.ini`). The seeded tree carries the operator's mail-account configuration and the operator's built-in OpenPGP key material; the OpenPGP key material lives **inside** the seeded profile tree (the `key4.db` and OpenPGP-key-store files under the profile directory), so the seeded archive carries the operator's full OpenPGP private key material. The role's preflight emits an informational note that the seeded archive is sensitive material and that the operator's external snapshot path declared in `defaults/main.yml` must be on operator-trusted storage. The role does not own the snapshot path; the snapshot is the operator's pre-deploy responsibility.

### MIME defaults

On a post-deploy host with the Fedora-OCI-installed application ref and the RPM Thunderbird absent, the standard scheme-handler default for `x-scheme-handler/mailto` resolves to `net.thunderbird.Thunderbird.desktop`. The Flatpak system store exports the application's desktop entry as a symlink:

```text
/var/lib/flatpak/exports/share/applications/net.thunderbird.Thunderbird.desktop
  -> ../../../app/net.thunderbird.Thunderbird/current/active/export/share/applications/net.thunderbird.Thunderbird.desktop
```

The desktop entry's `Exec=` line uses the canonical Flatpak run form:

```text
Exec=/usr/bin/flatpak run --branch=stable --arch=x86_64 \
  --command=thunderbird --file-forwarding net.thunderbird.Thunderbird @@u %u @@
```

The `--file-forwarding @@u %u @@` token pair is the canonical xdg-document-portal forwarding anchor: when an external invoker hands the application a file URL (most commonly a `mailto:` URI from the desktop or an `.eml` attachment opened from a file manager), the URL flows through the portal so the file becomes visible to the sandbox via the per-token FUSE-mount under `/run/user/${uid}/doc/by-app/net.thunderbird.Thunderbird/<token>/`.

The end-state MIME-default resolution on a typical post-deploy host:

| MIME / scheme | Resolves to |
|---|---|
| `x-scheme-handler/mailto` | `net.thunderbird.Thunderbird.desktop` |
| `xdg-mime query default x-scheme-handler/mailto` | `net.thunderbird.Thunderbird.desktop` |

The role does not write any `xdg-mime default` invocation. On a Fedora 44 host whose pre-deploy state already had the same desktop-entry ID as the post-deploy state (a typical surface, because the host's pre-deploy `mailto` handler was already `net.thunderbird.Thunderbird.desktop` from the RPM tree), the Flatpak install simply resolves the previously-dangling ID to the now-resolvable Flatpak-export target without operator-side mapping intervention. On a host whose pre-deploy `mailto` mapping points elsewhere, the role's preflight emits an informational note and the operator's manual `xdg-mime default net.thunderbird.Thunderbird.desktop x-scheme-handler/mailto` call is the closing intervention.

### Update path

The application ref's update path runs through the `fedora` remote's stock `flatpak update` mechanism. The remote uses the `oci+https://registry.fedoraproject.org` transport; OCI-typed remotes do not carry the per-remote `collection-id=` binding that ostree-typed remotes require for cross-remote update propagation, so the Fedora-OCI-side update path does **not** depend on the binding-repair step that the sibling topic for the ostree-typed remote owns. Subsequent `flatpak update` invocations exercise the same OCI-pull DBus token-request code path as the first install; the precondition is owned by the [Flatpak OCI-pull DBus](flatpak-oci-pull-dbus.md) sibling topic and applies on every `flatpak update` pass against the `fedora` remote.

### File modes

| Path | Mode | Owner:Group | SELinux type |
|---|---|---|---|
| `/var/lib/flatpak/overrides/net.thunderbird.Thunderbird` | `0644` (host-default) | `root:root` | `flatpak_var_lib_t` (host-default for the Flatpak system store) |
| `/var/lib/flatpak/db/org.freedesktop.impl.portal.access` | `0644` (host-default) | `root:root` | `flatpak_var_lib_t` (host-default for the Flatpak system store) |

The override file is mutated in place by the `flatpak override --system` code path; the portal-permission database file is mutated in place by the `flatpak permission-set` code path. Both code paths preserve mode, owner, and SELinux type by design. No `chmod`/`chown`/`restorecon` reflex is required. The topic does not write any per-user-UID file path under operator UMASK influence; no per-profile preference seed is shipped, and the seeded profile tree is written under the operator's own UID and read by the bwrap-launched application as the same UID.

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. The probe operates partially as the operator (`flatpak list`, `flatpak info --show-permissions`, `flatpak permission-list`, `xdg-mime query`, the runtime-domain context read) and partially with role-switched `sysadm_t` (the sandbox-override file content read at `/var/lib/flatpak/overrides/net.thunderbird.Thunderbird`, the `ausearch` against the AVC stream). Both scripts run from the operator's user session and are runnable standalone for out-of-band debugging.

### Probe

```bash
bash ansible/roles/topic_mozilla_thunderbird/files/probe.sh
```

The probe reports state without judging it. It enumerates RPM-Thunderbird-tree absence (`rpm -qa | grep -iE '^(firefox|thunderbird|mozilla)'` — post-deploy: empty when both Mozilla-stack topics have been applied; only browser-side rows when this topic alone has been applied), the Flatpak ref inventory (`flatpak list --columns=application,branch,origin,installation,version | grep -E '^net\.thunderbird\.Thunderbird'` — post-deploy: one row from the `fedora` remote, `system` installation, branch `stable`), the post-override permission table (`flatpak info --show-permissions net.thunderbird.Thunderbird` — post-deploy: the seven rows from §"Sandbox override"), the override-file content under role-switched `sysadm_t` (`sudo -r sysadm_r -t sysadm_t cat /var/lib/flatpak/overrides/net.thunderbird.Thunderbird` — post-deploy: the `[Context]` block with `filesystems=xdg-download;!host;!home;` and `sockets=wayland;!x11;`), the portal-permission row inventory (`flatpak permission-list org.freedesktop.impl.portal.access | grep -E '^org\.freedesktop\.impl\.portal\.access[[:space:]]+(camera|microphone|location)[[:space:]]+net\.thunderbird\.Thunderbird[[:space:]]+no'` — post-deploy: three rows, all `no`), the MIME-default resolution (`xdg-mime query default x-scheme-handler/mailto` — post-deploy: `net.thunderbird.Thunderbird.desktop`), the live runtime-domain context if a `thunderbird` process is alive (`cat /proc/${pid}/attr/current` after a `[[ -d /proc/${pid} ]]` liveness check, never `kill -0`; the canonical assertion target is the substring `staff_t`), and the AVC backlog from boot under role-switched `sysadm_t` (`sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot | grep -E '(thunderbird|bwrap|flatpak.*net\.thunderbird\.Thunderbird)'`; the probe prints `CLEAN` when the filtered output is empty, or empty output if the application has not been started since boot). The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_mozilla_thunderbird/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match, `1` on drift, and `2` on invocation error. The expected set covers nine independent surfaces, each reported as a separate line in the verify output to make drift attribution unambiguous; the portal-permission surface is asserted jointly as a row count plus the per-row policy-value triple, so a partial-deploy state with only one or two of the three rows fails the verify on the value-triple line rather than passing the row-count line silently.

| Property | Expected value |
|---|---|
| RPM Thunderbird tree absent | `rpm -qa | grep -iE '^(thunderbird\|thunderbird-librnp-rnp)'` returns empty |
| Flatpak ref present | `net.thunderbird.Thunderbird` from `fedora`, `system` installation, branch `stable` |
| Override `filesystems=` line | `xdg-download;!host;!home;` (byte-exact, trailing semicolon included) |
| Override `sockets=` line | `wayland;!x11;` (byte-exact, trailing semicolon included) |
| Portal-permission row count for the application | `3` (one row each for camera, microphone, location) |
| Portal-permission per-row policy values | `no no no` (joint assertion across the three rows; catches partial-deploy state) |
| Default `mailto` handler | `xdg-mime query default x-scheme-handler/mailto` returns `net.thunderbird.Thunderbird.desktop` |
| Live runtime-domain substring | `cat /proc/${pid}/attr/current` of any live `thunderbird` process contains the substring `staff_t` (substring assertion, not full-string equality, because the MCS range component is host-specific) |
| AVC backlog from boot | `sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot | grep -E '(thunderbird|bwrap|flatpak.*net\.thunderbird\.Thunderbird)'` returns zero matches |

Liveness is checked through `[[ -d /proc/${pid} ]]`. From a `staff_t` shell, `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the directory-existence form is ownership-independent. The verify reads the override file via the explicit role-switched `sudo -r sysadm_r -t sysadm_t cat /var/lib/flatpak/overrides/net.thunderbird.Thunderbird` invocation; it does not invoke any wrapper script. The AVC-clean assertion uses the explicit role-switched `ausearch` invocation `sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot`.

The expected verify output on a correctly applied host:

```text
OK   rpm_thunderbird_absent                          expected=yes actual=yes
OK   flatpak_ref_present                             expected=net.thunderbird.Thunderbird actual=net.thunderbird.Thunderbird
OK   override_filesystems                            expected=xdg-download;!host;!home; actual=xdg-download;!host;!home;
OK   override_sockets                                expected=wayland;!x11; actual=wayland;!x11;
OK   portal_permission_row_count                     expected=3 actual=3
OK   portal_permission_values                        expected=no no no actual=no no no
OK   default_mailto_handler                          expected=net.thunderbird.Thunderbird.desktop actual=net.thunderbird.Thunderbird.desktop
OK   runtime_domain_substring                        expected=staff_t actual=staff_t (substring match)
OK   avc_backlog_for_thunderbird_from_boot           expected=0 actual=0
```

### AVC posture

The AVC posture has two parts.

**Boot-clean expectation.** On a host with the Foundation-layer SELinux baseline plus the SELinux allow rules supplied by the [Flatpak audio sandbox](flatpak-audio-sandbox.md) sibling topic (the bwrap audio bind-mount class), the [Flatpak compute-device bind surface](flatpak-kfd-device.md) sibling topic (the bwrap `/dev/kfd` bind-source stat class on Flatpak 1.18+ AMD-GPU hosts; its denial class is `dontaudit`-suppressed and never appears in the audit stream in either state), and the [Flatpak OCI-pull DBus](flatpak-oci-pull-dbus.md) sibling topic (the OCI-pull DBus token-request class), `sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot` filtered against the application's process tree (the `thunderbird`, `bwrap`, and `flatpak.*net\.thunderbird\.Thunderbird` keyword set) returns empty. No application-start, sandbox-rebuild, mail-account-test, OpenPGP-key-list, or `flatpak update` invocation triggers an AVC under enforcing SELinux on this end-state. The four-tool diagnosis loop (`ausearch`, `audit2why`, `audit2allow`, `sealert`) for the AVC stream is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

**Drift signals.** A non-empty filtered `ausearch` return is the operator-investigation signal, not an automatic recovery trigger. The most common drift class on a host whose audio-sandbox precondition has lapsed (the CIL module unloaded, or a file fcontext relabel reverted) is the `staff_t × device_t : dir mounton` denial that fires at the next application start; the audio-sandbox sibling topic's verify catches that drift class through its own surface. The most common drift class on a host whose OCI-pull-DBus precondition has lapsed is the `sysadm_t × unconfined_dbusd_t : unix_stream_socket connectto` denial against `/run/user/0/bus` that fires at the next `flatpak install` or `flatpak update` invocation against the `fedora` remote; the OCI-pull-DBus sibling topic's verify catches that drift class through its own surface. The drift class on a host whose compute-device precondition has lapsed produces **no** AVC at all (the denial is `dontaudit`-suppressed): the operator-visible signal is the application failing to start with `bwrap: Can't get type of source /dev/kfd: Permission denied` on a `flatpak run` from a terminal; the compute-device sibling topic's verify catches that drift class through its own functional `stat` surface. Any `permissive=0` denial whose `scontext` is `staff_t` and whose `tcontext` is **not** in the Foundation-layer-baseline-allowed set is a third drift class and is the operator-investigation signal that the application's runtime allow surface has gained a class the baseline does not yet cover.

### Idempotence

The role's modify stage:

- Runs `flatpak install -y --system fedora net.thunderbird.Thunderbird` via `ansible.builtin.command` wrapped in a `creates: /var/lib/flatpak/app/net.thunderbird.Thunderbird` style guard, so on a host already carrying the application ref the install is a Flatpak-internal no-op and the task reports `changed=false`. On a re-run with a newer upstream point release available at the Fedora-OCI remote, the install promotes the host's deployed branch to the latest available point release; the `creates:` guard is conservative against the install-or-noop boundary.
- Runs `flatpak override --system` via `ansible.builtin.command` wrapped in a `changed_when` predicate that re-reads `/var/lib/flatpak/overrides/net.thunderbird.Thunderbird` after the call and reports `changed=true` only if the file content was added or modified. The `flatpak override --system` implementation reads the existing override, computes the merged result, and writes the file only if the merged result differs; on a host already in the end-state the call is a Flatpak-internal no-op.
- Runs three `flatpak permission-set` invocations (one per portal surface: camera, microphone, location) via `ansible.builtin.command` wrapped in a `changed_when` predicate that compares the post-call `flatpak permission-list` output against the pre-call output. On a host already carrying the three rows with policy value `no`, the calls are Flatpak-internal no-ops.
- Runs `systemctl --user restart xdg-document-portal.service` via `ansible.builtin.systemd_service` (`scope: user`) with a `when:` clause consulting a registered fact set to `true` only if the override task or any of the three portal-permission tasks reported `changed=true`. The reset is conditional rather than unconditional because an unchanged override and unchanged portal-permission database do not invalidate any portal-cache token state.
- Runs the four-package RPM removal via `ansible.builtin.dnf` with `state: absent`, and the trailing `dnf autoremove` via the same module with `autoremove: true`. On a host already in the end-state both calls are DNF-internal no-ops; on a host where the sibling browser topic has already removed the two shared packages, the per-package state is `absent` for those entries from the start and the dnf module reports `changed=false` against them.
- Writes **no** SELinux module, runs **no** `restorecon`, runs **no** `semanage fcontext`, runs **no** `systemctl daemon-reload`, runs **no** system-bus `systemctl restart`, sets **no** SELinux boolean, and writes **no** per-profile preference seed.

On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

### Recovery posture

The role ships an explicit rollback verb that reverses the three-fold deploy in reverse order. The byte-exact form:

```bash
sudo -r sysadm_r -t sysadm_t flatpak permission-reset net.thunderbird.Thunderbird
sudo -r sysadm_r -t sysadm_t flatpak override --system --reset net.thunderbird.Thunderbird
sudo -r sysadm_r -t sysadm_t flatpak uninstall -y --system net.thunderbird.Thunderbird
sudo dnf install -y thunderbird thunderbird-librnp-rnp mozilla-openh264 mozilla-filesystem
# operator-side: restore the host-side profile tree from the operator's external snapshot if applicable
```

Post-rollback, the three portal-permission rows for the application ID are gone (`flatpak permission-reset` removes all three on a single call), the sandbox-override file at `/var/lib/flatpak/overrides/net.thunderbird.Thunderbird` is gone (an empty `[Context]` block is normalized away by `--reset`), the application ref is uninstalled from the system store, the RPM Thunderbird tree is reinstalled, and the operator's host-side profile tree is restored from the operator's external snapshot. The role does not own the snapshot path; the snapshot is the operator's pre-deploy responsibility, named once in `defaults/main.yml` for documentation but not consumed automatically by the rollback. The rollback requires network access for the RPM reinstall step; the role ships no RPM-cache-backup mechanism by design — the operator's external snapshot covers the profile tree, and the RPM tree is recoverable from the Fedora 44 repository at any time. Boot-failure risk for this topic is **structurally zero**: the application is a post-login user-application; a Flatpak-side or sandbox-side misconfiguration is reversible from `sysadm_t` without rebooting; the application's bwrap-launched process tree has no dependency on `init_t` and cannot block the boot path. The Recovery-Pointer banner below is included for tree consistency, even though this topic's failure modes do not include a boot failure.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

This topic does not cross-link any existing pattern article in this tree. The existing patterns describe traps that fire on system-init-time services, on storage daemons, on systemd-managed unit dependencies, or on SELinux module-deploy mechanics for system-side services; none of them describe a trap class that a Flatpak-hosted user-application's sandbox-override-and-portal-deny mechanism can exercise. Two slug-only forward-mentions name the trap classes that surround the deploy state described here, neither of which has a written article in this tree this session: `flatpak-browser-subdomain-cut` (planned pattern explanation, not a written article in this tree this session) names the broader class — a custom SELinux sub-domain anchored on the Flatpak'd Mozilla-stack binary via a custom file fcontext mapping plus a `staff_t → <subdomain>_t` type-transition rule plus a custom data-tree label on the per-user sandbox path under `/home/<user>/.var/app/<appid>/` — that this topic explicitly does not instantiate (the end-state is `staff_t` for the application's process tree, see §"Topic shape"); `flatpak-inner-sandbox-userns-eperm` (planned pattern explanation, not a written article in this tree this session) names the broader class an operator should recognize as benign on the application's startup-time output, where a Flatpak-hosted Mozilla-stack application emits a single line of the form `Sandbox: CanCreateUserNamespace() clone() failure: EPERM` because its inner content-process sandbox setup requests a nested unprivileged user namespace and the bwrap-default seccomp filter denies the request, and the application falls back to its inner-sandbox alternate mode without losing its outer-confinement posture. The mechanism of either class is not reproduced in this topic body; mechanism explanation belongs in the pattern explanation when it is written.
