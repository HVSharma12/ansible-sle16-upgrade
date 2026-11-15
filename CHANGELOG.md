# Changelog

## 0.1.0 (unreleased)

- New role `analyse`: reports whether a SLES 15 SP7 host is ready to upgrade to SLES 16.1 (or 16.0),
  read-only, with the Distribution Migration System pre-checks included when they are installed.
- New role `remediate`: sets the migration target and installs the DMS pre-checks; with an opt-in per finding it
  disables repositories, installs patches, reboots, removes old kernels and named packages, and keeps root SSH
  login. Check mode lists the plan.
- New role `upgrade`: upgrades SLES 15 SP7 x86_64 to SLES 16.1. It refuses unless `analyse` in the same run says
  `ready`, starts the Distribution Migration System (activation package and reboot), waits for the host and
  reports `upgrade_result`. Check mode changes nothing.
- `analyse` reports pending patches or a pending reboot that zypper could not check as `patches_unknown` and
  `reboot_unknown` (needs action), so a host whose patch query fails is no longer `ready`.
