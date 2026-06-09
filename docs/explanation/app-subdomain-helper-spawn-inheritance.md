<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Application sub-domains and the helper-spawn inheritance trap

## The trap

A custom SELinux sub-domain for a user-launched application is a strong confinement tool: the application enters its own domain on launch, and a `file_type`-only label on its data files cuts every other domain off from those files. To keep that data label stable across the application's atomic save — write a temporary file, then `rename(2)` it onto the target — the design adds a dynamic `type_transition` so that any file the sub-domain creates in a home-directory tree receives the data label automatically. Each half is sound on its own.

The trap is the coupling. Many desktop applications launch helpers: opening a stored link spawns a browser, an attachment spawns a viewer, a "reveal in files" action spawns a file manager. Those helpers are generic binaries, and a process keeps its current SELinux domain across an `execve(2)` of a generic binary unless a transition rule says otherwise. So the helper — and everything it spawns in turn — runs in the application's sub-domain. Now the dynamic `type_transition` fires for every file that helper creates across unrelated home-directory trees: a browser profile, a cache directory, a downloads folder all acquire the application's private data label. The blast radius is wide and the symptom is delayed — the mislabeled helper then behaves as if its own profile were corrupt or missing, because *its* domain can no longer read files now wearing a foreign type.

## Why it happens

Two SELinux mechanics combine.

First, domain inheritance across `exec`. SELinux transitions a process to a new domain on `execve(2)` only when a `type_transition <source> <exec_type> process <target>` rule matches. With no such rule, the process retains its current domain. A sub-domain that execs a generic helper binary (on a merged-`/usr` host, nearly every helper is labeled `bin_t`) therefore stays in the sub-domain; the helper inherits it, and so does the helper's own fork/exec chain.

Second, the file-type cut and its permissive interaction. Anchoring the data type to the `file_type` attribute **only** — not to `user_home_type`, not to `non_security_file_type` — means no stock allow rule matches `<unconfined-user-domain> × <data_type> : file *`, so the unconfined user domain is denied access to the data files. That denial is enforced even while the application sub-domain itself runs in a permissive discovery posture, because a `permissive` marker only suppresses enforcement for records whose **source** context is the permissive type. A denial whose source is the user domain and whose target is the data type is unaffected. The same asymmetry is why the helper mislabel is silent: the inherited-domain helper *creates* files under the dynamic transition without raising any enforced denial, so nothing lands in the audit stream to flag it.

## How to detect it

- A sweep for the application's data label **outside** its designated data directory. On a healthy host the count is zero; a non-zero count means a helper spawn inherited the sub-domain and the dynamic transition relabeled a foreign tree.
- A user-visible symptom with no matching AVC: a helper application (browser, viewer) repeatedly starts as if freshly installed, or reports its profile missing or locked, because label-conflicted files it created are now unreadable from its own domain.
- The absence of audit records is itself a signal. Under a permissive discovery posture the mislabel produces no enforced denial; the drift surfaces only through the label sweep, not through `ausearch`.

```text
$ find "${HOME}" -path "${data_dir}" -prune -o -context '*:<data_type>:*' -print
/home/<user>/.var/app/<some-browser>/.../prefs.js
/home/<user>/.var/app/<some-browser>/.../places.sqlite
... (files a helper created while running in the sub-domain)
```

## How to mitigate it

Ship a companion module that breaks the inheritance: a `type_transition` that kicks any generic-helper exec from the sub-domain back to the launching user's natural domain, plus the two allows the kick-back requires.

```cil
(typetransition <app>_t bin_t process <caller>_t)
(allow <app>_t bin_t (file (execute)))
(allow <app>_t <caller>_t (process (transition rlimitinh siginh noatsecure)))
```

After this, a helper the application launches runs under `<caller>_t`, its own fork/exec chain stays there, and the dynamic data-label transition — which is keyed on the sub-domain as source — never fires for the files those helpers create. The label-durability transition and the spawn-containment transition are **coupled by design**: the first is what makes a leaked sub-domain dangerous, the second is what keeps the sub-domain from leaking. Treat them as a pair and ship them together; a host that carries the first without the second is exactly the trap.

Keep the two transitions in separate CIL modules from the base sub-domain so each can be loaded or rolled back on its own, and remove a module that references the base types **before** removing the base module, or the policy rebuild fails on the unresolved type.

Edge cases the mitigation does not cover:

- A helper that is **not** labeled `bin_t` (a vendor binary carrying its own exec type) is not caught by a `bin_t`-scoped transition; the target type must be widened to the observed exec type, confirmed empirically rather than assumed.
- An application that legitimately needs to run a specific helper **inside** its own sub-domain needs a narrower carve-out — a transition scoped to the generic case plus an explicit exception for that one helper — rather than a blanket kick-back.

## See also

- [SELinux custom CIL bootstrap](../reference/foundation/selinux-cil-bootstrap.md) — The Foundation layer that provisions the priority-400 publish path and the `semodule -X 400 -i` mechanism the companion modules ride on.
- [The /usr/sbin merge and stale file-context rules](./f44-sbin-bin-merge.md) — Why nearly every helper binary on a merged-`/usr` host resolves to `bin_t`, which is what makes a single `bin_t`-scoped containment transition cover the common helper set.
- [Audit and logging baseline](../reference/foundation/audit-logging-baseline.md) — The diagnosis loop for the AVC stream, and the reason a silent mislabel under a permissive posture must be caught by a label sweep rather than by `ausearch`.
