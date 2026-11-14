# hvsharma12.sle16_upgrade

Ansible content for upgrading SUSE Linux Enterprise Server 15 to SLES 16 with SUSE's Distribution Migration System
(DMS). The collection contains two roles today: `analyse` and `remediate`.

## Role `analyse`

Reports whether a host is ready for the upgrade. It is read-only: it installs, configures and starts nothing on the
host, and check mode gives the same result as a normal run.

What it does:

- Reads the facts the upgrade depends on: product and version, CPU level, registration, repositories, file system
  layout, boot loader, kernels, removed packages, network stack, SSH root login, AppArmor, cgroups, pending patches,
  running guests, cluster and SUSE Manager membership.
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
- For the reboot in `remediate`: ssh keepalive, see below.

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

## Tests

```bash
python -m pytest tests/unit          # findings, remediation plans, URL cleaning, repository origins, mounts, DMS wrapper
ansible-lint && yamllint .           # production profile
tests/e2e/repeat.sh <inventory> <dir>   # three runs (normal, again, --check): changed=0, same report
```

## License

GPL-3.0-or-later
