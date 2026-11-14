# Changelog

## 0.1.0 (unreleased)

- New role `analyse`: reports whether a SLES 15 SP5, SP6 or SP7 host is ready to upgrade to SLES 16.1 (or 16.0),
  read-only, with the Distribution Migration System pre-checks included when they are installed.
- New role `remediate`: sets the migration target and installs the DMS pre-checks; with an opt-in per finding it
  disables repositories, installs patches, reboots, removes old kernels and named packages, and keeps root SSH
  login. Check mode lists the plan.
