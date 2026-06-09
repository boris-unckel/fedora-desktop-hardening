<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# SELinux denial sequence-masking

## The trap

A single operation often requires more than one SELinux permission on the *same* `(source, target, class)` vector. A read-write `mmap(2)` on a file needs `file { read write map }`; opening and using a socket needs `sock_file { read write }` plus the stream-socket `{ connectto }`; an atomic save that renames a temporary file over a target needs `file { create rename ... }` together with `dir { write add_name remove_name }`. When more than one of those permissions is missing at once, the kernel does **not** report them all. The access check short-circuits at the first permission it evaluates and finds denied, returns `EACCES` (or `EPERM`) to the caller, and the calling code aborts that operation before it ever reaches the system-call stage that would have exercised the next permission. The audit subsystem records exactly one denial — naming only the first-failing permission.

The trap is that this single record looks complete. An operator who collects the audit stream once, writes an allow rule for the one permission named, loads it, and declares the gap closed has shipped a policy module that is correct for the first permission and silent about the rest. The remaining permissions are not absent from the requirement — they are masked. They surface only after the first gap is closed and the operation is exercised again, at which point the access path advances to the next check and a *new* denial appears on the very same vector. A policy authored from a one-shot probe under-covers any access vector whose depth is greater than one, and the under-coverage is invisible until the workload runs once more.

## Why it happens

The kernel's SELinux access decision is computed permission-by-permission as the calling code requests each access, not all at once for the whole operation. A user-space operation that maps to several permissions reaches the kernel as a *sequence* of checks at distinct points in the call path, and each check is a gate: the first one that denies stops the operation.

Consider a read-write file mapping. The calling code requests `read` and `write` access to the descriptor, and the `mmap(2)` call requests `map`. If `write` is denied first, the code path returns an error and never issues the `mmap(2)` — so the `file:map` check is never reached, and the audit log shows a `write` denial and nothing else. Grant `write`, and the next run advances past the write check, issues the `mmap(2)`, and *now* the `map` check fires; if `map` is also missing, a fresh `map` denial appears. The two permissions were always both required; they merely became observable in sequence because the code could not reach the second gate until the first was open.

Two stock-policy mechanisms deepen the masking:

- **`dontaudit` suppression.** Stock policy marks some benign-but-denied permissions `dontaudit`, which removes them from the audit stream entirely. A `dontaudit`-suppressed permission on the same vector never appears even after the louder permissions are granted; it is observable only by rebuilding the policy with suppressions disabled (`semodule -DB`).
- **Boolean-gated stock allows.** A stock allow rule can be conditional on a tunable boolean. `sesearch` shows the rule, so a permission looks granted — but if the boolean is off at runtime, the conditional rule does not grant the access, and the operation is denied as if the rule were absent. The permission is "present in policy, absent at runtime", which is easy to misread as covered.

The net effect is that the *observable* denial set on a vector is a moving frontier. It depends on which permissions have already been granted, on whether any are `dontaudit`-suppressed, and on the runtime state of any gating booleans — none of which a single probe pass reveals.

## How to detect it

The signature is a sequence of denials on one stable `(scontext, tcontext, tclass)` triple, where the *permission* advances between successive runs while the triple stays fixed:

```text
# first run, unmodified host:
denied  { write }  scontext=...:source_t tcontext=...:target_t tclass=file
# after granting write, next run:
denied  { map }    scontext=...:source_t tcontext=...:target_t tclass=file
```

The detection discipline has two halves.

**Filter on both ends of the vector, not one.** Aggregating the audit stream by source domain alone hides denials whose source is a different domain acting on the same target — and many real gaps are on a domain the operator is not thinking about (one process acting on a buffer or socket it received from another, a mediator acting on an object it brokers for a confined peer). Filter on `scontext` **or** `tcontext` and render the result grouped by `scontext → tcontext : tclass (permission)`, so that every denial touching either end of the vector is visible:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m avc,user_avc -ts "${T0}" \
  | awk '/type=AVC|type=USER_AVC/ {
      s=""; t=""; c=""; p=""
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^scontext=/)   { split($i, a, ":"); s = a[3] }
        if ($i ~ /^tcontext=/)   { split($i, a, ":"); t = a[3] }
        if ($i ~ /^tclass=/)     { c = substr($i, 8) }
        if ($i ~ /^permissive=/) { p = substr($i, 12) }
      }
      print s " -> " t " : " c " (permissive=" p ")"
    }' | sort | uniq -c | sort -rn
```

**Re-probe after every grant, from a fresh timestamp.** A probe pass is not complete when it returns a clean result *before* the workload re-runs. After loading a new allow rule, re-exercise the exact operation, capture the audit stream from a fresh `T0`, and re-aggregate. A new denial on the same vector with a different permission is the tell that the vector's depth was greater than one. Treat the cycle as finished only when a fresh re-exercise yields zero new denials on that vector. Read each record's timestamp against `T0` to discard stale buffered records (timestamp before `T0`) and the kernel AVC cache (timestamp after `T0` but naming an already-granted permission) from the genuine next-frontier denials (timestamp after `T0`, naming a permission not yet granted).

## How to mitigate it

The reliable mitigation does not rely on the audit stream at all: **derive the full permission set from the semantics of the operation**, and let the probe confirm rather than discover.

Reason forward from what the operation does to the permissions it must require. A read-write file mapping requires `file { read write map }` — the `map` is implied by `mmap(2)` regardless of the protection flags, and the `write` by `PROT_WRITE`. A socket connect-and-use requires the create/connect/read/write set for its class. An atomic rename-over-target requires the file create/rename pair plus the parent-directory name-management permissions. Each of these is knowable from the call semantics before a single denial is observed, and a rule that grants the whole set in one pass closes the vector without a multi-pass chase:

```cil
;; one access vector, both permissions of a read-write file mapping,
;; granted together because the semantics — not the audit stream —
;; establish the requirement.
(allow source_t target_t (file (write map)))
```

When the operation's permission set cannot be fully derived in advance and must be learned empirically, grant one permission per pass, re-load, re-exercise, and re-probe from a fresh timestamp, repeating until a re-exercise yields no new denial on the vector. Each granted permission must be backed by an observed denial, not by speculation — the empirical loop and the forward-derivation are complementary, and the loop's stop condition is an empty re-probe, never a single clean pass taken before the workload re-runs.

Edge cases the mitigation does not cover:

- **`dontaudit`-suppressed permissions.** A permission stock policy suppresses never appears in the stream even after the louder permissions on the vector are granted. Confirming the vector is fully covered against a suppressed permission requires a `semodule -DB` rebuild (suppressions off), the exercise, the read, and a `semodule -B` rebuild to restore the default — a heavyweight pass that belongs in a deliberate audit, not in every probe.
- **Boolean-gated stock allows.** When `sesearch` shows a permission as allowed but the allow is conditional on a tunable, the permission is granted only when the boolean is on at runtime. The host-specific boolean state is part of the vector's true coverage, and a permission that looks covered on one host may be denied on another whose boolean is off. Toggling the boolean system-wide to "fix" the gap grants the permission far more broadly than the cause; a targeted custom allow on the exact vector is the scope-correct alternative.
- **Permissive domains do not mask.** In a permissive domain (or under global permissive mode) the kernel logs every denial without stopping the operation, so the full permission set appears in one pass. The masking is a property of *enforcing* mode only — which means a vector probed in a permissive domain and then switched to enforcing can still surface a runtime denial if a `dontaudit` or boolean edge case was in play. The permissive-pass result is a starting inventory, not a guarantee.

The trap is distinct from a plain missing-single-permission gap, where one grant closes the vector and one probe confirms it. The distinguishing feature here is *depth*: the vector requires more than one permission, the permissions become observable in sequence, and the cost of treating the first observation as complete is a policy module that is correct about what it grants and silent about what it still omits.

## See also

- [Silent EACCES on unlabeled or mislabeled file types](./unlabeled-t-silent-eacces.md) — A neighbouring "denial you do not see" class: there the denial is suppressed by `dontaudit` on a mislabeled target rather than masked by sequence position, but the operator-facing failure mode (an `EACCES` with no obvious audit record) and the discipline of reading beyond the first clean probe are shared.
