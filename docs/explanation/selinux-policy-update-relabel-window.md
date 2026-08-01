<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# SELinux relabel windows during policy updates

## The trap

A file carries the wrong SELinux type after a policy-package update, while `matchpathcon` for that same path reports the correct one. Both statements are true at the same time, and the contradiction is not in the reading — it is in the timing.

For an executable the consequence is the one described in [F44 sbin/bin merge fcontext](./f44-sbin-bin-merge.md): the type transition into the service's own domain does not fire, the daemon runs unconfined, the unit is `active`, no error is logged and the audit backlog stays empty because the fallback domain is broadly permitted. The difference is that here the mapping is present and correct. Re-checking the table confirms the expected value and therefore reads as evidence that nothing is wrong.

The trap has a second, more consequential shape. Because the table looks correct, this state is easy to mistake for a defect that has been resolved upstream — and a workaround removed on that reading reopens the gap silently.

## Why it happens

A policy-package transaction does three things in sequence, and the order matters:

1. It removes generated policy modules from the store before the rebuild. Modules generated on the host — rather than shipped by the package — are removed at this point precisely so the rebuild does not carry stale content.
2. It rebuilds the context table and relabels parts of the filesystem, including the system binary directories.
3. It regenerates the removed modules and loads them again, which rebuilds the context table a second time.

Any mapping that exists *only* because a generated module supplies it is therefore absent during step 2. The relabel in that step resolves the affected paths against a table that does not contain the mapping, and assigns the generic type of the surrounding directory. Step 3 restores the mapping — but nothing relabels the affected paths again afterwards.

The result is deterministic, not intermittent: it recurs on every policy update, and it always leaves the table in the correct state by the time anyone inspects it.

## How to detect it

The timestamps carry the evidence; the table does not.

```bash
stat -c 'ctime %z' /usr/bin/<binary>
stat -c 'mtime %y' /usr/bin/<binary>
stat -c 'mtime %y' /etc/selinux/targeted/contexts/files/file_contexts
```

- An unchanged `mtime` on the binary with a recent `ctime` means the inode was relabelled, not reinstalled. Cross-check the package installation time; a reinstall would move both.
- A `file_contexts` modification time **after** the binary's `ctime` means the current table is not the table the relabel used.

Then establish that the invocation itself is sound, so the timing explanation is the only one left:

```bash
restorecon -n -v -R /usr/bin
```

If this reports the path with the correct target type, the relabel logic computes correctly against the present table, and the discrepancy can only be a difference in *when* it ran.

Finally, determine where the mapping comes from. This is the step that distinguishes a distribution-supplied mapping from a generated one:

```bash
semodule -l | grep -w <generated-module>
semodule --cil --extract=<generated-module>
grep filecon <generated-module>.cil
```

A path listed there is supplied by the generated module. The `file_contexts` table is derived output and mixes both sources, so it cannot answer this question — a point that generalises well beyond this trap: **a generated artefact is not evidence about its sources.**

## How to make a topic resilient

Two measures, and they address different halves of the problem.

**Hold the mapping locally.** A mapping written to `file_contexts.local` is not removed by the transaction that clears generated modules, so it is present in the table during the relabel step and the relabel resolves to the intended type. Qualify it to the object type it should govern — an unqualified mapping also matches compatibility symlinks that no distribution entry applies to, which converts one silent defect into a permanent context-drift report:

```bash
semanage fcontext -a -f f -t <type> /usr/bin/<binary>
```

**Assert the label, and restore it.** The mapping being correct says nothing about the inode, which is the whole point of this trap. A topic that claims a label must compare the actual context against the expected type **as a constant** — comparing it against `matchpathcon` passes whenever both are wrong together — and must be able to put it back. An assertion without a remediation detects the regression and then requires manual work every time it recurs.

Both measures survive the removal of one another's justification. If a distribution later supplies the mapping in its own policy source, the local mapping becomes redundant; the assertion does not, because it is what would report the loss. Removing a workaround is a decision about the remediation, never about the check that guards it.

## See also

- [F44 sbin/bin merge fcontext](./f44-sbin-bin-merge.md) — The related trap in which the mapping is genuinely absent rather than temporarily absent. Same symptom on the daemon side, different cause, and the detection step that separates them is whether the current table contains the mapping at all.
- [Drop-in files and SELinux context inheritance](./dropin-selinux-context-inheritance.md) — Why a newly created file takes the type of its directory rather than the type its path maps to, and why the file-type qualifier decides which of two paths a rule governs.
- [SELinux custom CIL bootstrap](../reference/foundation/selinux-cil-bootstrap.md) — The Foundation layer for locally held policy content; the mapping described here is written to the local file-context store rather than to a CIL module, but the operator role-switch surface is the same.
