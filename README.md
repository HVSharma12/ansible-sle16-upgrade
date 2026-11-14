# hvsharma12.sle16_upgrade

Ansible content for upgrading SUSE Linux Enterprise Server 15 to SLES 16 with SUSE's Distribution Migration System
(DMS). The collection contains one role today: `analyse`.

## Role `analyse`

Reports whether a host is ready for the upgrade. It is read-only: it installs, configures and starts nothing on the
host, and check mode gives the same result as a normal run.

What it does:

- Reads the facts the upgrade depends on: product and version, CPU level, registration, repositories, file system
  layout, boot loader, kernels, removed packages, network stack, SSH root login, AppArmor, cgroups, pending patches,
  running guests, cluster and SUSE Manager membership.
- Runs the checks of `suse-migration-pre-checks` when that package is installed (the role does not install it),
  keeping each message's check and log level, without writing the tool's log file.
- Sets the fact `analyse_report` and writes `<host>.json`, `<host>.md` and a fleet `summary.md` on the controller.

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

- Managed host: SLES 15 SP5, SP6 or SP7; Python 3.11; root (`become: true`).
- Controller: ansible-core 2.18 or later.

### Variables

| variable | default | description |
|---|---|---|
| `analyse_target_version` | `"16.1"` | `16.1` (sources 15 SP5–SP7) or `16.0` (source 15 SP7) |
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
Xen guest, s390x, DMS warnings.

Information: XFS v4, wicked, no snapper snapshot, 32-bit packages, legacy BIOS, public cloud, SLES for SAP,
installed modules, DMS pre-checks not installed.

Not checked: SysV init scripts, consumers of Python 3.6 or 3.11, s390x CPU level.

## Tests

```bash
python -m pytest tests/unit          # findings, URL cleaning, repository origins, mounts, DMS wrapper
ansible-lint && yamllint .           # production profile
tests/e2e/repeat.sh <inventory> <dir>   # three runs (normal, again, --check): changed=0, same report
```

## License

GPL-3.0-or-later
