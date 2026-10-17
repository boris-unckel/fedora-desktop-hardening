<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Replaced files lose their mode

## The trap

A file has the wrong mode, an operator or a role runs `chmod`, and the file has the right mode. The fix looks complete and a check run right after it passes. The next time the tool that owns the file runs, the mode is wrong again.

The trap occurs when the owning tool does not modify the file in place but replaces it: it writes a new file next to the old one and renames it over the old path. The `chmod` acted on an inode that no longer exists. The new inode takes its mode from the umask of whoever ran the tool this time, not from the file it replaced.

Under a system-wide UMASK of `0027`, every such rewrite started from an operator session produces `0640`. The failure is silent: the tool succeeds, the file has the expected content, and only an unprivileged reader fails — with `Permission denied` in the best case, and in the worst case through a front end that reports the unreadable file as a parse error or an empty result.

## Why it happens

Write-new-then-rename is the standard way to update a file atomically. A reader either sees the complete old file or the complete new one, never a half-written mix. The cost is that the result is a new file. Unless the tool explicitly copies the old file's mode, or sets one itself, the mode is `0666 & ~umask`.

Most tools do neither, because under the distribution default umask of `0022` the result is `0644` either way and nobody notices. A hardened umask turns an invisible implementation detail into a readability defect.

The libdnf5 system state is the reference case. At the end of every transaction libdnf5 writes `/usr/lib/sysimage/libdnf5/<name>.toml.new` for six state files and renames each over `<name>.toml`. `sudo` combines the caller's umask with its own default of `0022`, which leaves `0027` in effect, and the files come out `0640`. Unprivileged `dnf info`, `dnf list --installed`, and `dnf repoquery --installed` then fail on the unreadable `packages.toml`. `transaction_history.sqlite` in the same directory is updated in place and keeps whatever mode it had.

The same class applies to any tool that keeps state or configuration through atomic replacement: package-manager databases, `alternatives` link records, editors that save by rename, and configuration managers that template a file to a temporary path and move it into place.

## How to detect it

The distinguishing signal is the inode. A file modified in place keeps its inode number; a replaced file gets a new one.

```bash
stat -c '%i %a %y %n' /usr/lib/sysimage/libdnf5/packages.toml
# run the owning tool once, then:
stat -c '%i %a %y %n' /usr/lib/sysimage/libdnf5/packages.toml
```

A changed inode together with the restricted mode identifies the class. A sibling file in the same directory that the tool writes in place, and that kept its mode, is a useful contrast.

A fix in this class is only proven by running the owning tool after the fix and checking the result again. A check immediately after a `chmod` proves nothing about the next run.

## How to mitigate it

Set the mode where the file is written, not on the file:

- Prefer a post-write hook of the owning tool, one that runs after the replacement. For libdnf5 this is the actions plugin (`libdnf5-plugin-actions`) with a `post_transaction` action that runs `chmod 0644` on the state files; libdnf5 saves the system state before it runs `post_transaction`, so the action sees the files the transaction has just written. The hook runs for every caller of the tool, whatever umask that caller has.
- Where no hook exists, fix the umask of the process that runs the tool, for that process only — for example a wrapper that runs the tool with `umask 0022`. This covers only the callers that go through the wrapper.
- Avoid a periodic or path-triggered re-`chmod`. It leaves a window between the rename and the repair, and it adds a component whose own failure is silent.

Verify the mitigation by running the owning tool and checking for a new inode and the expected mode together. A new inode with the wrong mode means the hook did not fire; an unchanged inode means the test did not exercise the rewrite.

## See also

- [UMASK and daemon readability](umask-and-daemon-readability.md) — The general trap of a hardened umask on files created through `sudo`, and the write patterns that fix it for files written once.
- [UMASK 0027](../reference/foundation/umask.md) — The Foundation layer that sets the umask and ships the libdnf5 countermeasure described here.
