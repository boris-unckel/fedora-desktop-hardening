<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Storage SMART and CAP_SYS_RAWIO

## The trap

A storage daemon that polls SATA drives for SMART data — the class includes any service that reads health, temperature, or power-state attributes from a SATA disk via the SCSI generic interface — depends on `CAP_SYS_RAWIO` to issue ATA-pass-through IOCTLs through `SG_IO`. A hardening drop-in that reduces the daemon's `CapabilityBoundingSet=` to `CAP_SYS_ADMIN` only, on the assumption that mount-management or block-device-mediation requires no further capability, breaks every SMART read on every connected SATA drive. The breakage is silent in two senses simultaneously: the daemon's primary functions (mount, list, query) continue to work because they do not require the IOCTL path, and `NVMe` drives are not affected because their IOCTLs route through a different kernel interface that does not check `CAP_SYS_RAWIO`. A host with one or more SATA drives plus one or more NVMe drives shows partial SMART coverage, which an unaware operator may misread as an unrelated SATA-side hardware quirk.

The symptom in the daemon's journal is the kernel error `Operation not permitted` on an `SG_IO` IOCTL, surfaced through whatever wrapper the daemon uses around the ATA pass-through. A representative line:

```text
Error sending ATA command CHECK POWER MODE: SGIO v3 ioctl failed
(v4 not supported): Operation not permitted
```

The same line appears for the `READ SMART DATA`, `IDENTIFY DEVICE`, and `CHECK POWER MODE` commands — every ATA pass-through that a SMART poller issues. Service status remains `active`. The daemon's mount, list, and query functions continue. The only observable effects are a journal that fills with the IOCTL error at the daemon's polling cadence, a SMART status block in the daemon's introspection output that never updates, and — for daemons that drive desktop UI surfaces such as a disk-utility application — empty or stale SMART panels.

## Why it happens

`SG_IO` ATA pass-through enters the kernel through `drivers/scsi/sg.c` and `drivers/ata/libata-scsi.c`. The capability check is `capable(CAP_SYS_RAWIO)`, not `capable(CAP_SYS_ADMIN)`. The two capabilities overlap in many privileged operations but are distinct in this one: an unprivileged process holding `CAP_SYS_ADMIN` alone cannot issue ATA pass-through IOCTLs.

The split is deliberate. `CAP_SYS_RAWIO` historically grants raw block-device IOCTLs and `/dev/mem` access — the operations that bypass the block-layer abstraction and address the device directly. ATA pass-through fits that description: the kernel forwards a vendor-defined ATA command frame to the controller, expecting the caller to know what they are doing. `CAP_SYS_ADMIN` covers a much broader surface but is, paradoxically, not the gate for this narrow operation. A drop-in that pares the capability set to `CAP_SYS_ADMIN` only, with the intent of preserving mount or block-mediation functionality, removes `CAP_SYS_RAWIO` and silently disables the SMART path.

The NVMe divergence follows from the same kernel-interface split. NVMe devices accept admin and IO commands through `/dev/nvme<N>` and the NVMe character-device IOCTLs in `drivers/nvme/host/ioctl.c`. Those IOCTLs check `CAP_SYS_ADMIN` (and, for some passthrough subclasses, no capability at all because the kernel routes them through the standard NVMe abstraction layer). They do not call `capable(CAP_SYS_RAWIO)`. A daemon polling SMART data on an NVMe drive therefore continues to work after `CAP_SYS_RAWIO` is dropped — the IOCTL path it uses is not gated on that capability.

A separate confusion: the systemd directive `SystemCallFilter=` carries an `@raw-io` syscall class. That class is orthogonal to `CAP_SYS_RAWIO`. `@raw-io` covers `iopl(2)`, `ioperm(2)`, `pciconfig_*` syscalls, and a small set of related primitives — direct port-IO and PCI-config-space access. It does not include `ioctl(2)`, the syscall that `SG_IO` uses. A drop-in that lists `~@raw-io` in its filter does not block SMART because SMART rides on `ioctl(2)`, which lives in `@system-service`. Conversely, granting `@raw-io` is unnecessary for SMART because the IOCTL path needs only the `ioctl(2)` syscall and the `CAP_SYS_RAWIO` capability — two independent gates that both must be open.

## How to detect it

Three observable signals, in order of how reliably they appear:

- A journal entry from the daemon at the configured polling cadence, containing the substring `SGIO`, `housekeeping`, or `Operation not permitted` in the context of an ATA-command failure. The detection form is uniform:

  ```text
  $ journalctl -u <unit> -b 0 | grep -iE 'sgio|housekeeping|operation not permitted'
  ```

  On a correctly configured host with one or more SATA drives, this command returns zero hits across the boot. On an affected host, the count grows at the polling rate (one entry per drive per polling cycle is typical).

- A drift between the daemon's effective capability set and the SMART-required set. Read the live value:

  ```text
  $ systemctl show -p CapabilityBoundingSet --value <unit>
  cap_sys_admin
  ```

  A set that contains `cap_sys_admin` and does not contain `cap_sys_rawio`, on a daemon that polls SATA SMART data, is the unambiguous root cause.

- A SMART status block in the daemon's introspection output that does not update. The daemon's command-line client (the per-daemon equivalent of `<daemon>ctl info -b /dev/<device>`) reports a SMART block that is either absent or carries timestamps from before the drop-in deploy. This signal is the slowest to surface — the daemon's polling cycle may take minutes — and is unreliable in isolation, but it confirms the symptom once the journal lines have already pointed at it.

A pre-hardening baseline is the discipline that distinguishes a true regression from a pre-existing condition. The same `journalctl … | grep -iE 'sgio|housekeeping|operation not permitted'` command, run before the hardening drop-in is deployed, captures the baseline count. On a stock host with healthy SATA hardware, the baseline is zero. A non-zero baseline indicates a hardware or firmware condition that predates the hardening, and any post-deploy non-zero count must be compared against it; a count that matches the baseline is not a regression.

## How to mitigate it

Add `CAP_SYS_RAWIO` to the daemon's bounding set, additively to the operations capability the daemon already requires. For a daemon that needs `CAP_SYS_ADMIN` for mount or block-mediation work, the combined directive becomes:

```ini
[Service]
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_RAWIO
```

The directive value is order-insensitive at parse time. `systemctl show -p CapabilityBoundingSet --value <unit>` returns the effective set in alphabetical lower-case form (`cap_sys_admin cap_sys_rawio`), which is the form a verify script's hardcoded expected value should use. A `CapabilityBoundingSet=` line written in capital, source-order form (`CAP_SYS_RAWIO CAP_SYS_ADMIN`) parses identically; only the live-readout normalization differs.

The mitigation is additive. The `CAP_SYS_RAWIO` grant does not weaken the rest of the hardening posture in any non-trivial way: `CAP_SYS_ADMIN` already covers most of what `CAP_SYS_RAWIO` enables (raw block-device IOCTLs, `/dev/mem` open, the broader IO-control surface), so adding `CAP_SYS_RAWIO` on top of `CAP_SYS_ADMIN` widens the bounding set by a small, well-bounded amount. The `systemd-analyze security` score erosion that follows is on the order of 0.2 points and is a deliberate trade-off for SMART-functional storage daemons.

The orthogonal direction — to retain the smaller bounding set and disable SMART polling instead — is available for hosts that genuinely do not need SMART data through this daemon (for example, hosts where a separate SMART-monitoring daemon already covers the SATA drives). The choice between the two paths is a per-host operator-policy decision; this pattern documents the additive mitigation because it preserves the daemon's stock function set.

Edge cases the mitigation does not cover:

- A host with no SATA drives. NVMe-only and SCSI-only hosts do not need `CAP_SYS_RAWIO` for SMART. The decision to keep or drop `CAP_SYS_RAWIO` on such a host is a future-proofing trade-off (a SATA drive added later will silently break) versus a marginal score gain. The conservative posture is to keep `CAP_SYS_RAWIO` in the default profile and let NVMe-only operators drop it deliberately.
- A daemon that uses `SystemCallFilter=` in its subtractive form `~@privileged` to deny privileged syscalls wholesale. `mount(2)` lives in `@privileged`, so the subtractive form already breaks mount-manager daemons (separate from the SMART issue). The additive form `@system-service @mount` is the correct shape; `@raw-io` is unrelated and does not need to be added or removed for SMART.
- A SMART pipeline that polls drives through an out-of-band channel (BMC, network-attached enclosure management, vendor-specific tooling). Those channels do not transit the kernel `SG_IO` path and are not affected by this trap; the `CAP_SYS_RAWIO` grant is unnecessary for them.

## See also

- [PrivateMounts implicit enable](./private-mounts-implicit.md) — A different silent-failure trap that affects mount-manager daemons in the same hardening neighborhood: a process-level sandbox directive flips a namespace mode and breaks the daemon's primary function without a status-level signal.
