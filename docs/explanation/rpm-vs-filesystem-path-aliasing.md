<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# RPM-versus-filesystem path aliasing

## The trap

Any check that compares a filesystem walk against the package database — "which files on this host does no package own?" — produces wrong results unless both path-aliasing classes are normalised away first. The failure mode is the dangerous kind: the comparison succeeds, the exit status is zero, the counts look plausible, and the answer is simply wrong.

Wrong in both directions. Files that *are* package-owned are reported as unowned, because the walk and the database spell the same path differently. And a genuinely unowned file can be masked, because the operator, faced with hundreds of obviously-bogus entries, adds a broad suppression that swallows the real one with them.

On a representative Fedora 44 host, a comparison that resolved only the first aliasing class and not the second reported **635 false positives on every single run** — every one of them a compatibility symlink whose target the database records under a different directory. There is no error message, no warning, and no signal in the tooling that anything is amiss.

## Why it happens

Two independent filesystem-layout merges each introduce an aliasing class, and they compose.

**The merged-`/usr` layout.** The top-level `/bin`, `/sbin`, `/lib` and `/lib64` are symlinks into `/usr`. A package may record its file list against the top-level form — `/lib/modules/<release>/kernel/...` — while a walk rooted at `/usr` reports the same file as `/usr/lib/modules/<release>/kernel/...`. Both strings name the same inode. A string comparison sees two different paths.

**The merged `sbin`/`bin` layout.** On Fedora 44, `/usr/sbin` is not a symlink but a real directory populated with compatibility symlinks whose targets live in `/usr/bin`. The package database records the target, under `/usr/bin`. A walk that descends into `/usr/sbin` reports the symlink, under `/usr/sbin`. Asking the package manager which package owns a given `/usr/sbin` entry answers "no package" — truthfully, because the entry the database holds is the `/usr/bin` one.

This second class is easy to miss precisely because it inverts the intuition built by the first. After learning that `/sbin` is a symlink into `/usr`, one expects `/usr/sbin` to be a symlink too, and expects a walk not to descend into it at all. It is a real directory, the walk does descend, and every entry it finds looks unowned.

The two classes compose, so a normalisation that handles them in the wrong order also fails. Rewriting the top-level `/sbin` prefix to `/usr/sbin` is only correct if a second rewrite then folds `/usr/sbin` into `/usr/bin`.

## How to detect it

The absence of an error is not evidence of correctness here. Three checks, in increasing order of effort:

- **Spot-check a sample of the reported-unowned set against the package manager directly.** If it names a package, the comparison is broken, not the host. This is the fastest decisive test and it takes one command.
- **Look at the directory distribution of the reported set.** A long run of entries sharing one system binary directory, or a four-figure count under a kernel-module tree, is the signature. Genuine unowned files scatter; aliasing artefacts cluster.
- **Compare set sizes before and after adding each normalisation step.** A step that removes hundreds of entries was fixing an aliasing class, not filtering signal.

```text
# Reported as unowned by a naive comparison:
/usr/sbin/<daemon>

# But the package database disagrees:
$ rpm -qf /usr/sbin/<daemon>
<package>-<version>.<arch>

# Because what it actually records is the target:
$ readlink -f /usr/sbin/<daemon>
/usr/bin/<daemon>
```

## How to mitigate it

Normalise **both** sides of the comparison through the same function before comparing, and resolve both classes in order. Rewrite the top-level directories into `/usr`, then fold `/usr/sbin` into `/usr/bin`:

```sh
normalize_paths() {
  sed -E -e 's#^/(bin|sbin|lib|lib64)/#/usr/\1/#' -e 's#^/usr/sbin/#/usr/bin/#'
}

package_owned="$(rpm -qal | normalize_paths | sort -u)"
on_disk="$(find /usr /etc -xdev \( -type f -o -type l \) | normalize_paths | sort -u)"
unowned="$(comm -23 <(printf '%s\n' "$on_disk") <(printf '%s\n' "$package_owned"))"
```

Two further requirements that are easy to overlook and break the result just as thoroughly:

- **Pin the locale.** `comm` requires both inputs to be sorted identically, and `sort` collates according to the active locale. A comparison built under one locale and run under another silently produces wrong set differences. Export `LC_ALL=C` around the whole comparison.
- **Apply the same function to both sides.** Normalising only the walk, or only the database list, produces a different wrong answer rather than a partial improvement.

Edge cases the mitigation does not cover:

- **Bind mounts and additional symlinked trees** beyond the two merge classes. A site-specific symlink farm introduces its own aliasing that this normalisation knows nothing about. Verify against the host's actual layout rather than assuming these two classes are exhaustive.
- **Files a package owns under a path that no longer exists**, for example after a package changed a directory into a symlink and the package manager moved the old tree aside. The moved-aside tree is genuinely unowned and correctly reported — it is a real finding, not an aliasing artefact, and it should not be normalised away.
- **Ghost entries.** Paths the package declares but does not ship are present in the database and absent from disk. They do not produce false unowned entries, but they do skew any ownership ratio computed from the same data.

## See also

- [F44 sbin/bin merge fcontext](f44-sbin-bin-merge.md) — the same `sbin`/`bin` merge seen from the SELinux side, where it silently drops a daemon into the default service domain.
