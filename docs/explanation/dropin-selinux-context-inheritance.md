<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Drop-in files and SELinux context inheritance

## The trap

A configuration file or unit drop-in written into `/etc/**` receives the SELinux type of the directory it is created in, not the type that `file_contexts` maps for its own path. For a unit drop-in under `/etc/systemd/system/<unit>.service.d/`, that means the generic `systemd_unit_file_t` rather than the service-specific `<service>_unit_file_t` the policy defines for the path.

Nothing about the result looks wrong. PID 1 reads the drop-in, `systemctl show -p DropInPaths` lists it, and every directive in it takes effect: `NoNewPrivileges=`, `ProtectSystem=`, capability bounding sets, and syscall filters all apply exactly as written. Service status stays `active`, `systemd-analyze verify` is silent, and no AVC is logged, because nothing was denied. The deploy step that produced the file exits `0`.

What is missing is not a permission the service needs but a restriction the specific type would have imposed. The generic type is a strictly wider label: it is reachable by every subject that reaches the specific type, plus a handful more. The hardening artefact ends up less protected than the stock unit file sitting next to it, which the package installed with the correct type.

The same trap has a second, quieter half. The SELinux **user field** of the context — `system_u`, `unconfined_u`, `staff_u` — records the identity of whoever created the file. A drop-in written through `sudo` from a confined administrative account carries that account's SELinux user indefinitely. Type-only tooling never reports it.

## Why it happens

SELinux assigns a label at file creation from the kernel's transition rules: a new file takes the type of its parent directory unless a `type_transition` rule names something else. The `file_contexts` database — the mapping from path patterns to labels — is not consulted at creation time at all. It is a userspace table, read only by `restorecon`, `setfiles`, `matchpathcon`, and the RPM installation path. A file therefore acquires its path-correct type only if a relabel step runs after it is written.

A deploy step that writes a drop-in and fixes its DAC mode is a complete-looking operation:

```bash
install -m 0644 /dev/stdin /etc/systemd/system/<unit>.service.d/99-hardening.conf <<'EOF'
…
EOF
```

The mode is right, the owner is right, the content is right, and the unit picks it up. The label is wrong, and nothing in that sequence would reveal it.

Two mechanisms make the correct expectation less obvious than it looks:

- **Path equivalency.** `file_contexts.subs_dist` maps `/etc/systemd/system` onto `/usr/lib/systemd/system` before the pattern table is consulted. The rule that decides a drop-in's type is therefore written against the `/usr/lib` path — for example `/usr/lib/systemd/system/<service>.*  --  system_u:object_r:<service>_unit_file_t:s0` — even though the file lives under `/etc`. Reading the table for a literal `/etc/systemd/system/...` pattern finds nothing and suggests, wrongly, that no specific mapping exists.
- **The file-type qualifier.** The `--` field in a `file_contexts` entry restricts the rule to regular files. A directory or a symlink at the same path does not match it and falls through to whatever generic rule covers the tree. A drop-in *directory* therefore has a different expected type from the files inside it, and a compatibility symlink has a different expected type from the binary it points at. Any comparison that ignores the file type will produce a confident wrong answer.

The width difference between the generic and the specific type is concrete rather than theoretical. Comparing the access vectors of `systemd_unit_file_t` against a service-specific `<service>_unit_file_t` shows the generic type carrying additional subjects, among them generator domains with write, create, rename, and unlink on the file. A generator can rewrite a hardening drop-in that carries the generic type; it cannot touch one that carries the service-specific type.

## How to detect it

Compare the live context against `file_contexts` for both the drop-in directory and its contents, honouring the file type of each path:

```bash
for path in /etc/systemd/system/<unit>.service.d \
            /etc/systemd/system/<unit>.service.d/*; do
  case "$(LC_ALL=C stat -c '%F' "${path}")" in
    *"symbolic link"*) mode=link ;;
    "directory")       mode=dir ;;
    *)                 mode=file ;;
  esac
  actual=$(stat -c '%C' "${path}")
  expected=$(matchpathcon -m "${mode}" "${path}" | sed 's#.*\t##')
  [ "${actual}" = "${expected}" ] \
    || printf '%s expected=%s actual=%s\n' "${path}" "${expected}" "${actual}"
done
```

Two properties of this comparison matter:

- It compares the **full** context, including the SELinux user field. `restorecon -n` reports type differences only, so a path that is correct in type and wrong in user is invisible to it — and to any integrity check built on top of it. Adding `-F` to the dry run (`restorecon -F -n -v -R <dir>`) restores the user field to the comparison and needs no package beyond `policycoreutils`.
- It derives the file type from `stat`, not from `[[ -d ]]` or `[[ -L ]]`. Those operators report false when the path cannot be stat'ed, which silently selects the regular-file rule and yields a plausible but wrong expectation. A path whose type cannot be determined should be reported as such, not guessed at.

The drop-in **directory** deserves its own line in any such check. It is created by the deploy step, it is never revisited, and a relabel pass that lists only the files inside it leaves the directory on its inherited label permanently.

## How to mitigate it

Relabel as part of the same deploy step that sets mode and owner, recursively and against the directory rather than a list of files:

```bash
sudo -r sysadm_r -t sysadm_t \
  restorecon -F -v -R /etc/systemd/system/<unit>.service.d
```

- `-R` covers the directory itself along with everything in it, and stays correct when the deploy step later gains another drop-in file.
- `-F` resets the SELinux user field in addition to the type. Without it the artefacts keep the identity of whoever applied them, and that residue is invisible to type-only tooling.
- The role escalation is required: `restorecon` transitions into `setfiles_t`, which a plain `sudo` from a confined administrative account cannot enter.

Relabelling changes no file content. Units do not need a `daemon-reload`, services do not need a restart, and no merged unit changes as a result — the effective directives before and after are identical. It is safe to apply to a running system.

Edge cases the mitigation does not cover:

- **Units with no service-specific type.** Targeted policy does not define a `<service>_unit_file_t` for every unit. Where it does not, the expected type *is* the generic `systemd_unit_file_t` and the relabel is a no-op on the type. Keep the step anyway: it still normalises the user field, and it stays correct if policy later gains a specific mapping for the path.
- **Recursion into stock directories.** A recursive relabel is appropriate for a directory the deploy step owns. Applying it to a shared stock directory such as `/etc/sysctl.d` or `/etc/modprobe.d` reaches files belonging to other packages. List individual paths there instead.
- **Files regenerated at runtime.** A file recreated on each boot by its owning service takes the label its creator gives it. Relabelling such a path holds only until the next regeneration; the honest resolution is either an upstream fix or a documented exception, not a relabel repeated forever.
- **Filesystems without label support.** A path resolving onto a filesystem that cannot carry an SELinux context — a vfat EFI partition, for example — can never satisfy the comparison. Such a path belongs in an explicit exception list, not in a relabel loop.

## See also

- [UMASK and daemon readability](umask-and-daemon-readability.md) — The DAC sibling of this trap: the same deploy step, the same silent outcome, produced by the mode bits instead of the label.
- [F44 sbin/bin merge fcontext](f44-sbin-bin-merge.md) — The path-equivalency and file-type-qualifier mechanics described above, in the form that costs a daemon its confinement domain.
