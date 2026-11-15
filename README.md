# hvsharma12.sle16_upgrade

Ansible content for upgrading SUSE Linux Enterprise Server 15 to SLES 16 with SUSE's Distribution Migration System
(DMS). The collection contains four roles: `analyse`, `remediate`, `upgrade` and `verify`.

## Role `analyse`

Reports whether a host is ready for the upgrade. It is read-only: it installs, configures and starts nothing on the
host, and check mode gives the same result as a normal run.

What it does:

- Reads the facts the upgrade depends on: product and version, CPU level, registration, repositories, file system
  layout, boot loader, kernels, removed packages, network stack, SSH root login, AppArmor, cgroups, pending patches,
  running guests, cluster and SUSE Manager membership.
- Reads what `verify` compares after the upgrade (`facts.state`): services, failed units, mounts, addresses,
  default routes, listening ports, local accounts, SELinux mode and denials, a migration boot entry.
- Runs the checks of `suse-migration-pre-checks` when that package is installed (the role does not install it),
  keeping each message's check and log level, without writing the tool's log file.
- Sets the fact `analyse_report` and writes `<host>.json`, `<host>.md` and a fleet `summary.md` on the controller;
  in the file names, characters of the inventory host name other than letters, digits, `.`, `_` and `-` become `_`.

Each finding has an `id`, a `severity`, a `title`, what was `found`, a `remediation`, the documented `sources` and
the `check` that produced it (`role`, `dms` or both). Severities:

| severity | meaning |
|---|---|
| `blocker` | the upgrade cannot start or is not supported in this state |
| `needs_action` | the upgrade runs, but something must be done before or after it |
| `info` | worth knowing; nothing to do |

The verdict is `blocked` with any blocker, `needs_action` with any needs-action finding, `ready` otherwise.

Registration is read from the presence of `/etc/zypp/credentials.d/SCCcredentials` and the registration services;
no credential file and no `SUSEConnect --status` output is read. Repository URLs are stored without their query
string and user information.

### Requirements

- Managed host: SLES 15 SP7; Python 3.11; root (`become: true`).
- Controller: ansible-core 2.18 or later.
- For the reboots in `remediate` and `upgrade`: ssh keepalive, see `remediate` below.

### Variables

| variable | default | description |
|---|---|---|
| `analyse_target_version` | `"16.1"` | `16.1` or `16.0`; SUSE documents 15 SP5–SP7 as sources for 16.1 and 15 SP7 for 16.0 |
| `analyse_target_product` | `""` | `SLES`, `SLES_SAP`, or empty to pick `SLES_SAP` for SLES for SAP hosts and `SLES` otherwise; any other value fails |
| `analyse_min_free_mb` | `2048` | free MiB on `/` below which the host is blocked |
| `analyse_run_dms_prechecks` | `true` | run the DMS pre-checks when they are installed |
| `analyse_check_patches` | `true` | count needed patches from the local metadata (no refresh) |
| `analyse_report_dir` | `{{ playbook_dir }}/sle16-upgrade-reports` | controller directory for the reports; empty writes none |
| `analyse_fail_on_blocker` | `false` | fail the host when the verdict is `blocked` |

### Example

```yaml
- name: Check SLES 15 hosts for the SLES 16.1 upgrade
  hosts: sles15
  become: true
  gather_facts: false
  roles:
    - role: hvsharma12.sle16_upgrade.analyse
```

### Checks

Blockers: unsupported source version or product, already SLE 16, transactional host, CPU below x86-64-v2 or
POWER10, not registered, SUSE Manager client, encrypted root, `/var` or `/usr` on a separate file system, no GRUB 2
or systemd-boot entries, Xen dom0, too little free space, dropped file system on `/`, DMS errors (such as no
upgrade path in SCC).

Needs action: SP6 to 16.0 (documented both ways), `migration_product` not set for a 16.1 target, multiversion
kernels, root SSH login, pinned `python3.11` interpreter, third-party and local repositories, packages removed in
SLE 16, modified AppArmor profiles, teamd, running KVM guests, cluster node, cgroup v1, pending patches or reboot,
patches or a reboot that could not be checked, Xen guest, s390x, DMS warnings.

Information: XFS v4, wicked, no snapper snapshot, 32-bit packages, legacy BIOS, public cloud, SLES for SAP,
installed modules, DMS pre-checks not installed.

Not checked: SysV init scripts, consumers of Python 3.6 or 3.11, s390x CPU level.

## Role `remediate`

Fixes the findings of `analyse` that are safe to fix, and the others only when you name them. It refreshes the
repository metadata (not in check mode, which plans from the metadata on the host), runs `analyse` (no report
files; the `analyse_*` variables apply), plans the changes from that report, shows the plan as
`remediate_plan` and makes the changes. Run `analyse` again afterwards to see the result.

- A host with a blocker you have not opted in is left unchanged; the plan names the blocker in `blocked_by`.
- Check mode is the dry run: it shows the plan and changes nothing, whether it comes from `--check` or from
  `check_mode: true` on the role's tasks. With `--check` the plan is also reported as `changed` when it has
  changes.
- Package removal comes last, after the repositories, patches, reboot and kernels. It first runs
  `zypper remove --dry-run` and shows every package the removal takes with it. The role stops there when one of
  them is not in `remediate_remove_packages` or the dry run does not show a listed one, and in check mode.
- A second run on a remediated host plans nothing and changes nothing.
- A run that fails part-way is not rolled back: repositories stay disabled and installed patches stay. The next
  run plans from what is left.
- The reboot needs ssh keepalive where the network can drop a connection without closing it (NAT, qemu user
  networking): set `-o ServerAliveInterval=15` in `ansible_ssh_common_args`. Without it the reboot can hang until
  the task fails after 15 minutes; the next run reboots again only if `zypper needs-rebooting` still asks for it.
- Repositories count as third party unless they come from SCC, a registration service or SUSE Manager: one added
  by hand from an RMT or SMT server is disabled too. Read `disable_repositories` in the check mode plan first.

| finding | what the role does | when |
|---|---|---|
| `migration_product_not_set` | sets `migration_product: <product>/<version>/<arch>` in `/etc/sle-migration-service.yml` | always |
| `dms_prechecks_absent` | installs `suse-migration-pre-checks` | always |
| `repos_third_party`, `repos_local` | disables the enabled repositories (`zypper modifyrepo --disable`); nothing is removed. With none enabled the finding stays, a blocker included, and `reasons` in the plan says why | opt-in |
| `patches_pending`, `patches_unknown` | `zypper patch --with-interactive` until nothing is left, after the repositories above are disabled | opt-in `patches_pending` |
| `reboot_pending`, `reboot_unknown` | reboots when `zypper needs-rebooting` asks for it, also after the patches | opt-in `reboot_pending` |
| `multiversion_kernels` | sets `multiversion.kernels = latest,running` and runs `zypper purge-kernels` | opt-in |
| `removed_package:<name>` | `zypper remove --no-clean-deps <name>` | the name is in `remediate_remove_packages` |
| `ssh_root_login` | writes `/etc/ssh/sshd_config.d/50-permit-root-login.conf` with `PermitRootLogin yes` | opt-in |

Every other finding is left to you, with the remediation `analyse` gives: registration, the source version and
product, CPU, boot loader, file systems and free space, encryption, Xen, guests, clusters, SUSE Manager, AppArmor
profiles, teamd, cgroup v1, the Ansible interpreter, and the DMS pre-check messages. Removed packages with
severity `info` (`dhcp-client`) are never removed.

The tool's own `suse-migration-pre-checks --fix`, which the upgrade also runs, removes old `kernel-default`
packages only; `zypper purge-kernels` covers every kernel flavour. Changing `zypp.conf` leaves a
`zypp.conf.rpmnew` after the upgrade; the role keeps the previous file as a backup.

### Variables

| variable | default | description |
|---|---|---|
| `remediate_opt_in` | `[]` | finding ids to fix beyond the automatic ones: `repos_third_party`, `repos_local`, `patches_pending`, `reboot_pending`, `multiversion_kernels`, `ssh_root_login`; any other value fails |
| `remediate_remove_packages` | `[]` | packages to remove; only those `analyse` reports as `removed_package:<name>` with severity `needs_action`. A package the removal takes with them must be listed too, or the role stops before removing anything |

### Example

```yaml
- name: Prepare SLES 15 hosts for the SLES 16.1 upgrade
  hosts: sles15
  become: true
  gather_facts: false
  tasks:
    - name: Fix what is safe and what is named
      ansible.builtin.include_role:
        name: hvsharma12.sle16_upgrade.remediate
      vars:
        remediate_opt_in: [repos_third_party, patches_pending, reboot_pending, multiversion_kernels]
        remediate_remove_packages: [nscd]

    - name: Report the result
      ansible.builtin.include_role:
        name: hvsharma12.sle16_upgrade.analyse
```

## Role `upgrade`

Upgrades a ready SLES 15 SP7 host to SLES 16.1 the way SUSE documents it: it installs
`suse-migration-sle16-activation` and reboots into the Distribution Migration System, which migrates the host and
boots it into SLES 16. The role does not change the migration's configuration, and it never starts a migration
again by itself.

1. It reads `/etc/os-release` with `raw` and stops on a host that runs neither SLES 15 nor SLES 16, or that runs
   the migration system. A host that already runs SLES 16.1 is only reported (step 5); on SLES 16.0 the role fails
   with `SLES 16.1 not reached`.
2. On SLES 15 it runs `analyse` in the same run for SLES 16.1, with the DMS pre-checks and the patch check on;
   the other `analyse_*` variables apply. Its `<host>.json` in `analyse_report_dir` is the host's state right before
   the migration; a run on SLES 16 does not analyse and leaves it as it is. It refuses unless that analysis is from this run, its
   verdict is `ready` and the host is SLES 15 SP7 on x86_64, the only path the role is tested on. It also refuses
   when the DMS pre-checks did not run, when the number of pending patches is not known, when
   `/var/log/distro_migration.log` exists (an earlier migration left it), and when the root is not btrfs with a
   snapper configuration unless `upgrade_accept_no_rollback` is true. Extra variables that turn the pre-checks or
   the patch check off make it refuse. The message names every reason.
3. It installs the activation package. **From here the host is armed:** the package makes the migration the default
   boot entry, so the next reboot, by anyone, starts the migration with no new analysis.
   `zypper --non-interactive remove suse-migration-sle16-activation SLES16-Migration` disarms it; when only one of
   the two is installed, zypper removes it and exits 104. Without `upgrade_accept_no_rollback`, when the package
   recorded no snapper snapshot, the role runs that command itself and stops before the reboot. When the role stops
   on a host that still has `suse-migration-sle16-activation`, its message says so and gives the command, also when
   the caller ignores errors.
4. It reboots into the migration. root cannot log in during the migration, so the role waits until root can log
   in again, up to `upgrade_reboot_timeout` seconds. Set the ssh keepalive described under `remediate`: without it
   the wait can hang until the task stops 600 seconds after that.
5. It waits for systemd to finish booting and fails unless the host runs SLES 16.1 and the migration log has no
   `failed with` line; on SLES 16.1 with such a line it says `SLES 16.1 reached, but the migration log reports a
   failure.` and quotes it. A degraded state and failed units are reported in `upgrade_result`, not failed. When
   this run rebooted the host, it sets `ansible_python_interpreter: /usr/bin/python3` for the rest of the playbook run,
   because SLES 16 has no python3.11.

`upgrade_result`:

| key | value |
|---|---|
| `upgraded` | true when this run rebooted into the migration |
| `version_id` | the version the host runs, read from `/etc/os-release` |
| `system_state` | `systemctl is-system-running` after boot, for example `running` or `degraded` |
| `failed_units` | the failed systemd units |
| `migration_log` | `/var/log/distro_migration.log`, or null on a host that did not migrate with DMS |
| `rollback_snapshot` | the snapper snapshot recorded before the migration, for a migration that fails (see *After a failed migration*); null without snapper and after a re-run |

Check mode, from `--check` or the `check_mode` keyword, runs steps 1 and 2, says what it would install and reboot
(reported as `changed`) and changes nothing. On a host that already runs the target it reports the result with
`changed=0`.

### When something fails

| where | what the role says | the host after it | what to do |
|---|---|---|---|
| the gate | `Not upgrading:` and each reason | unchanged | fix what it names (`remediate` covers part of it), or set `upgrade_accept_no_rollback: true` after a backup; run the role again |
| no snapper snapshot after the install | `Not upgrading: snapper took no snapshot before the migration, so a failed migration cannot be rolled back; the migration packages were removed again` | not armed | find out why snapper took no snapshot, or set `upgrade_accept_no_rollback: true` after a backup; run the role again |
| the install, or the reboot did not start | `The reboot into the migration did not start (…)`, whether `suse-migration-sle16-activation` is installed, and the disarm command | armed while `suse-migration-sle16-activation` is installed: the next reboot starts the migration | disarm with the command above, fix the cause, run the role again |
| the migration, before it changes packages | `SLES 16.1 not reached: the host runs SUSE Linux Enterprise Server 15 SP7.` and the `failed with` lines of `/var/log/distro_migration.log` | back on SLES 15 SP7 within minutes; DMS removed `suse-migration-sle16-activation`, `SLES16-Migration` and `/migration-image`; the log stays | fix the cause, then `mv /var/log/distro_migration.log /var/log/distro_migration.log.failed` and run the role again; until then it refuses. A failure inside the package transaction also leaves the registration out of step (see *After a failed migration*) |
| the wait (`upgrade_reboot_timeout`, or the connection) | `The host did not come back from the migration in time (…)` | may still be migrating, or may not have come back; a wait shorter than the migration ends this way while the host finishes on its own | when root can log in again, run the role again. After a migration that succeeded it reports `upgrade_result` with `upgraded: false` and starts nothing; after one that failed it refuses on the earlier log (row above). Until then root cannot log in, and an ssh login as the user `migration` with the key root uses is refused |

### After a failed migration

The role does not roll back and does not repair the registration. `rollback_snapshot` recovers a host from a
migration that failed inside the package transaction. It does not recover a host that reached SLES 16.1: rolled
back to it, that host boots SLES 15 SP7 with its network interface down and cannot be reached. Restore such a host
from a backup.

On SLES 15 SP7 with an XFS root (no snapper), after a migration that failed inside the package transaction (an
rpm error on its first package):

- The host is back on SLES 15 SP7 with no package changed, and the role stops with `SLES 16.1 not reached`.
- `SUSEConnect --list-extensions` fails with `Error: Registration server returned 'The requested product
  'SUSE Linux Enterprise Server 15 SP7 x86_64' has not been activated on this system.' (422)`.
- `SUSEConnect --rollback` succeeds, and after it `SUSEConnect --list-extensions` works again.
- With the cause fixed and the log moved aside, the role runs again and upgrades the host to SLES 16.1.

On SLES 15 SP7 with a btrfs root and snapper:

- The gate passes on the snapper configuration alone. `rollback_snapshot` is the `pre` snapshot of the activation
  package's install in this run; DMS adds its own `before offline migration` and `after offline migration`
  snapshots.
- The same failure brings the host back on SLES 15 SP7 with no package changed, and the role stops with
  `SLES 16.1 not reached`. The role does not report `rollback_snapshot` then: `snapper list` shows it as the `pre`
  snapshot before `before offline migration`.
- The host's registration is then out of step. `SUSEConnect --list-extensions` fails with `Error: Registration
  server returned 'The requested product 'SUSE Linux Enterprise Server 15 SP7 x86_64' has not been activated on
  this system.' (422)`, and `SUSEConnect --de-register` with `Error: Registration server returned 'Systems
  Management Module is not yet activated on the system.' (422)`.
- `snapper rollback <rollback_snapshot>` and a reboot boot that snapshot as a working SLES 15 SP7, and
  `SUSEConnect --list-extensions` works again. `SUSEConnect --rollback` then succeeds, and after it
  `SUSEConnect --de-register` works.
- With the cause fixed, the log moved aside and the pending patches installed, a new upgrade is still refused:
  the registration server tells the DMS pre-checks that the SLES 15 SP7 products have not been activated, and the
  role says `analyse says blocked: dms:upgrade_path_against_registration_server`. What clears this on the
  rolled-back host was not established. Such a failure changes no package, so a rollback is not needed for it;
  `SUSEConnect --rollback` without a rollback is the repair measured on XFS, and was not tried on btrfs.

Not tested: a failure after packages have changed (a partly upgraded host) and a rollback from it; UEFI hosts;
hosts much fuller than a minimal image, where the migration takes longer; a reboot into the migration that fails
without rebooting. Without snapper, only your backup restores a host after a failed migration.

### Variables

| variable | default | description |
|---|---|---|
| `upgrade_reboot_timeout` | `3600` | seconds to wait for the host to come back from the migration; a minimal host takes about two minutes. The role does not check the value: a shorter wait, `0` included, stops the role while the host still migrates |
| `upgrade_accept_no_rollback` | `false` | start the upgrade on a host whose root has no snapper configuration (XFS, ext4, btrfs without snapper) |

Not supported by this role: s390x (`run_migration`), SUSE Manager clients, cluster nodes in order, and the
migration settings in `/etc/sle-migration-service.yml` other than the target `remediate` sets. After the upgrade,
updates may be pending; the role does not install them.

### Example

```yaml
- name: Upgrade SLES 15 SP7 hosts to SLES 16.1
  hosts: sles15
  become: true
  gather_facts: false
  serial: 1
  vars:
    ansible_ssh_common_args: -o ServerAliveInterval=15
  roles:
    - role: hvsharma12.sle16_upgrade.upgrade
```

## Role `verify`

Compares a host after the upgrade with what `analyse` read before it, and fails only on what is broken. It is
read-only: it installs, configures and starts nothing on the host, and check mode gives the same result.

The baseline is an `analyse` report from SLES 15 of this host: the `analyse_report` fact of the same playbook run
(the `upgrade` role leaves it), or the `<host>.json` read from `verify_baseline_dir` on the controller. The
`upgrade` role writes that file, from just before the migration, to its `analyse_report_dir`; point
`verify_baseline_dir` there to verify in a later run. Both stay off the host, so the upgrade and a rollback do not
touch them. The role needs root (`become: true`) and stops without it. It refuses without a baseline, with one of
another host, one not read on SLES 15 or one written by an `analyse` without the `state` facts.

It compares:

| area | difference ids |
|---|---|
| release and registration | `not_target` (not SLES 16.1), `not_registered` (no SCC credentials, or no enabled SUSE repository or service of SLES 16.1), `repo_old_release` (a SUSE repository of SLES 15 still enabled), `migration_failed` (`failed with` in `/var/log/distro_migration.log`), `kernel_not_installed` (no installed package provides the running kernel), `repo_missing` (an enabled non-SUSE repository is gone or disabled) |
| services | `service_stopped` (enabled and running before, not running now), `service_disabled` (enabled before, not now), `unit_failed` (failed now, not before), `system_state` (systemd does not report `running`); enabled means enabled, enabled at run time, generated from an init script, indirect or an alias |
| file systems | `mount_missing`, `mount_changed` (file system type); local devices and NFS, CIFS, Ceph, GlusterFS |
| network | `address_missing` (a global address; IPv6 privacy addresses are left out, and a SLAAC address counts as present while one in its prefix is), `default_route_changed` (a default gateway is gone), `port_closed` (a TCP or UDP port no longer listens, or listens on loopback only where it listened on an address) |
| accounts | `user_missing`, `user_changed` (uid, home, shell) for root and uid 1000 and up in `/etc/passwd`; `group_missing`, `group_members` for root and gid 1000 and up |
| security and boot | `selinux_mode`, `selinux_denials` (AVC denials since boot), `reboot_pending`, `kernel_cmdline` (a kernel parameter of the boot before is missing now; values of parameters named `*pass*` are masked), `migration_boot_entry` (a migration entry in `grub.cfg`) |

Each difference is one line, for example:

```text
service_stopped verify-seed.service: running -> not running; the host no longer provides this service (fails)
port_closed tcp/8080: python3.11 on any -> not listening; clients of this port get no answer (fails)
```

Differences every upgrade to SLES 16.1 brings are listed as `expected:` lines and not counted. Measured on SLES 15
SP7 upgraded to 16.1: the release and the kernel; the SUSE repositories replaced by those of 16.1; the wicked
services replaced by `NetworkManager.service` (which must run) and wicked's DHCP port `udp/68` closed;
`apparmor.service` no longer enabled, SELinux enforcing instead (only when it is enforcing; otherwise
`selinux_mode`); `issue-generator.service` no longer enabled. A port from the ephemeral range whose process listens
on another port is listed as expected too.

Not compared: services that ran without being enabled (started by hand, or on demand by D-Bus, a socket or another
unit, such as `snapperd` or `dbus`); new services, ports, users or packages; a port that moves from all addresses
to one; package versions, orphaned packages and `.rpmnew` or `.rpmsave` files; application data and configuration;
DNS; accounts from LDAP or other NSS sources; whether SCC agrees with the host (the role reads the credential file,
the services and the repositories, not `SUSEConnect --status`). The migration log is read only on SLES 16.1.

An area that cannot be read is a `cannot tell:` line, never a pass: it fails when one of its ids is in
`verify_fail_on`, and is reported otherwise. The verdict is `fail` when a difference fails, `cannot_tell` when an
area behind a failing id could not be read, and `pass` otherwise; the role fails unless it is `pass`. A host that
was never upgraded or was rolled back fails on `not_target`; without that id in `verify_fail_on` the role compares
it all the same. Tested on a host rolled back with `snapper rollback <rollback_snapshot>` after a migration that
failed inside the package transaction: `not_target` was the only difference.

`verify_report`: `verdict`, `differences` (`id`, `item`, `before`, `after`, `reason`, `fails`), `counts`
(differences per id), `expected`, `cannot_tell` (`area`, `reason`, `fails`), `lines`, `version_id`, `host`,
`collected_at` and `baseline` (`from`, `collected_at`). The report directory is created `0700` and the file `0600`:
it names accounts, addresses and listening processes.

On a host that runs SLES 16, `ansible_python_interpreter` must not point at `python3.11`; the `upgrade` role sets
`/usr/bin/python3` for the rest of its playbook run.

### Variables

| variable | default | description |
|---|---|---|
| `verify_baseline_dir` | `""` | the upgrade run's `analyse_report_dir`, with `<host>.json` from before the upgrade; empty uses `analyse_report` of this run |
| `verify_fail_on` | `not_target`, `not_registered`, `repo_old_release`, `migration_failed`, `kernel_not_installed`, `service_stopped`, `unit_failed`, `mount_missing`, `address_missing`, `default_route_changed`, `port_closed`, `user_missing`, `migration_boot_entry` | difference ids that fail the host; the others are reported |
| `verify_report_dir` | `{{ playbook_dir }}/sle16-upgrade-reports` | controller directory for `<host>.verify.json`; empty writes none |

### Example

```yaml
- name: Upgrade SLES 15 SP7 hosts to SLES 16.1 and verify them
  hosts: sles15
  become: true
  gather_facts: false
  serial: 1
  vars:
    ansible_ssh_common_args: -o ServerAliveInterval=15
  roles:
    - role: hvsharma12.sle16_upgrade.upgrade
    - role: hvsharma12.sle16_upgrade.verify
```

## Tests

```bash
python -m pytest tests/unit          # findings, remediation plans, URL cleaning, repository origins, mounts, DMS wrapper,
                                     # the probe's state and verify's comparison on facts of measured upgrades
                                     # the role tests skip below ansible-core 2.19
ansible-lint && yamllint .           # production profile
tests/e2e/repeat.sh <inventory> <dir>   # three runs (normal, again, --check): changed=0, same report
```

## License

GPL-3.0-or-later
