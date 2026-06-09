<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Livetest cloud harness

Reproducible drivers for the cloud live-test. They turn the documented
provision-test-recycle flow into committed, re-runnable scripts so a suite run
does not depend on ad-hoc commands. The harness provisions real cloud VMs
because containers cannot exercise SELinux-enforcing, PID 1, or a real reboot.

All scripts read the project-scoped provider token from the `HCLOUD_TOKEN`
environment variable and shell out to the `hcloud` CLI; the token value is never
printed. They use the local key pair `~/.ssh/livetest_harness`.

## Topology

Three roles, as in `../test-environment.md`:

- **Operator workstation** — runs these scripts and drives the control node
  over SSH.
- **Control node** (`livetest-control`) — an unhardened bastion inside the
  private network. Holds the Molecule venv, the role tree, the harness key, and
  the token; runs `molecule test` against managed nodes.
- **Managed nodes** (`managed-<topic>`) — provisioned from the base snapshot
  with no public IPv4, reachable from the control node over the private
  network. Transient: created and destroyed per scenario.

## Scripts

| Script | Where it runs | What it does |
|---|---|---|
| `lib.sh` | sourced | Resource names, topology constants, SSH helpers. Single source of truth for the names the Molecule create play expects. |
| `bootstrap_infra.sh` | workstation | Ensure the key, network, firewalls, and control node exist; provision the control node (venv, Molecule, collections, key, token, role tree). Idempotent; re-run to reconcile a changed operator IPv4 and re-sync. |
| `bake_base_snapshot.sh` | workstation | Build the enforcing, desktop-like base snapshot from a short-lived builder, then delete the builder. Labels the snapshot so the suite finds it. |
| `run_suite.sh` | workstation | Resolve the base snapshot, re-sync the role tree, and run `molecule test` per topic on the control node. Prints a PASS/FAIL matrix. Keeps the reusable infrastructure. |
| `teardown.sh` | workstation | Remove every livetest resource. Run only on an explicit operator request. |

## Cost policy

The base snapshot, network, key, and control node are **kept** between runs:
re-creating them costs more than the idle server. Managed nodes are recycled per
scenario by the shared destroy play. Run `teardown.sh` only when the operator
asks to stop all costs.

## Typical flow

```sh
export HCLOUD_TOKEN=...        # project-scoped token (already in the env)
./bootstrap_infra.sh          # once; re-run to reconcile or re-sync
./bake_base_snapshot.sh       # once per package-set change
./run_suite.sh                # all topics, or: ./run_suite.sh auditd cups
```

The base snapshot and the boot-enforcing substrate are described in
`../test-environment.md`; per-run findings live under `../reports/`.
