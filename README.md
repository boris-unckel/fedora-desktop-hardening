<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Hardening reference for Fedora-based desktops

A topic-oriented, end-state reference for hardening a **Fedora 44 (or later)** desktop running with `staff_u` as the default SELinux user mapping. Documentation is organized by the [Diátaxis](https://diataxis.fr/) framework. Each system service or system layer has a dedicated Reference article and a matching Ansible role that applies, verifies, and probes the end state.

This is a *thematic* reference, not a chronological log. There is no migration history, no incident write-ups, no iteration narratives. Each topic stands alone.

## Layout

```
docs/
├── tutorials/        Guided bootstrap path: take a fresh host to a hardened state.
├── how-to/           Task-oriented recipes: apply, verify, recover.
├── reference/
│   ├── foundation/   Platform layers (UMASK, sudo roles, SELinux CIL, audit baseline).
│   └── topics/       One article per service or per system feature.
└── explanation/      Cross-cutting traps and patterns (NNP-SELinux, SCF-privdrop, ...).

ansible/
├── inventory/        Example inventories.
├── molecule/         Shared Molecule plumbing (create/destroy/prepare) and the system-tier scenario.
├── roles/            One role per Foundation layer and per Topic. Cloud-testable topic
│                     roles carry their own Molecule component scenario.
├── playbooks/        Bootstrap playbook plus per-topic playbooks.
└── group_vars/       Shared variables.

livetest/
├── harness/          Committed cloud drivers: infrastructure bootstrap, base-snapshot
│                     bake, suite run, teardown.
└── reports/          Per-run findings, dispositions, and security scores.
```

The `livetest/` suite exercises these roles on ephemeral cloud virtual machines, with the
Ansible controller separate from the target, to confirm the end state applies, verifies,
and survives a reboot away from the authoring host. The suite is green through its system
tier: the Foundation plus 22 cloud-testable topics apply cumulatively, are idempotent,
survive a real reboot, and verify post-reboot in both SELinux contexts, with pre/post
security scores captured. See `livetest/README.md` for the current status.

## Tier model

Reading order is intentional:

1. **Foundation** — apply once, in fixed order. Required for every topic.
2. **Topic** — co-equal, isolated. A topic article assumes the Foundation is in place. Pick topics in any order.
3. **Pattern (Explanation)** — cross-cutting traps. Linked from topics that exhibit them. Read on demand to understand *why* a topic is configured the way it is.

A topic article never duplicates a pattern. If the same trap shows up in three topics, the pattern is in `explanation/` once and linked three times.

## Where to start

- New to this reference: the Bootstrap tutorial under `docs/tutorials/bootstrap-hardened-host.md` walks through the Foundation layers in fixed order plus one example topic.
- Already have a hardened host and want to apply one more topic: the recipe at `docs/how-to/apply-topic.md` covers manifest preparation, role apply, and verify.
- A deployment broke the boot: the recovery procedure at `docs/how-to/recover-from-boot-failure.md` covers live-media boot, drop-in rollback, and CIL module backout.

All articles named above exist, as do the four Foundation references, the 27 topic references, and the pattern articles under `docs/explanation/`.

## Scope and assumptions

- Target: single-user Fedora 44+ desktop, AMD or Intel, no enterprise identity management.
- SELinux is enforcing. The user runs as `staff_u`.
- The hardened state intentionally restricts user-application installs and uses `sysadm_r` for administrative actions.
- Hosts with different SELinux user mappings (e.g. `unconfined_u` defaults), server roles, or HSM/TPM-bound trust paths require their own analysis — patterns transfer, exact configurations may not.

For operators upgrading from a previous Fedora release, the article *Preserve SELinux state during a Fedora major-version upgrade* (under `docs/how-to/`) covers the upgrade procedure. That article is the only place where pre-44 Fedora is in scope; it generalizes from the F43→F44 upgrade and applies to any subsequent major-version bump.

## Conventions

- All paths, identifiers, prose, and comments are English (en-US).
- All hostnames, paths, and identifiers are anonymized; substitute your own.
- Code blocks declare a language. Tables describe tabular data, not narrative.
- Cross-references are relative paths within this tree.

## Contributing

(Out of scope. The repository is maintained by a single operator.)

## License

- `ansible/` and `livetest/` are licensed under the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.html.en) (SPDX: `AGPL-3.0-or-later`; full text in [LICENSE.md](LICENSE.md)).
- `docs/` is licensed under [Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/legalcode.en) (SPDX: `CC-BY-SA-4.0`; full text in [docs/LICENSE](docs/LICENSE)).

Each file carries its SPDX identifier in its first line (for executable scripts, in the line after the shebang).
