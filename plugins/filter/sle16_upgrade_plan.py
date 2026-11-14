# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Harshvardhan Sharma <harshvardhan.sharma@suse.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: sle16_upgrade_plan
short_description: Plan the remediation of an upgrade readiness report
version_added: "0.1.0"
description:
  - Returns C(changes) (each planned action with what it acts on), C(blocked_by) (blocker ids not opted in; any of
    them empties the plan), C(left) (blocker and needs-action ids the plan does not cover) and C(reasons) (why an
    opted-in id is not covered).
  - C(repos_local) is covered, and lifts its blocker, only when an enabled local repository exists to disable.
  - C(migration_product_not_set) and C(dms_prechecks_absent) are always planned, the opt-in ids only when listed.
positional: opt_in, remove_packages
options:
  _input:
    description: The C(analyse_report) fact of the C(analyse) role.
    type: dict
    required: true
  opt_in:
    description: Finding ids to fix beyond the automatic ones; other ids are ignored.
    type: list
    elements: str
    required: true
  remove_packages:
    description: Packages to remove; only those the report lists as C(removed_package:<name>) with severity
      C(needs_action) are planned.
    type: list
    elements: str
    required: true
"""

EXAMPLES = r"""
plan: "{{ analyse_report | hvsharma12.sle16_upgrade.sle16_upgrade_plan(['repos_third_party'], ['nscd']) }}"
"""

RETURN = r"""
_value:
  description: C(changes), C(blocked_by), C(left) and C(reasons).
  type: dict
"""

OPT_IN = ("repos_third_party", "repos_local", "patches_pending", "reboot_pending", "multiversion_kernels",
          "ssh_root_login")


def sle16_upgrade_plan(report, opt_in, remove_packages):
    findings = dict((f["id"], f["severity"]) for f in report.get("findings") or [])
    chosen = set(opt_in or []) & set(OPT_IN)
    facts = report.get("facts") or {}
    repos = [r for r in facts.get("repos") or [] if r.get("enabled")]
    aliases = dict((fid, [r["alias"] for r in repos if r.get("origin") == fid[len("repos_"):]])
                   for fid in ("repos_third_party", "repos_local"))
    # the DMS check also reports disabled repositories: a repository finding counts only with something to disable
    fixable = [fid for fid in aliases if fid in chosen and fid in findings and aliases[fid]]
    lifted = (chosen - set(aliases)) | set(fixable)
    blocked_by = sorted(i for i, s in findings.items() if s == "blocker" and i not in lifted)
    reasons = {}
    if "repos_local" in chosen and "repos_local" in findings and "repos_local" not in fixable:
        disabled = [r["alias"] for r in facts.get("repos") or [] if r.get("origin") == "local"]
        reasons["repos_local"] = ("no enabled local repository to disable; disabled: " + ", ".join(disabled)
                                  if disabled else "no repository in /etc/zypp/repos.d to disable")
    changes, covered = {}, set()
    if not blocked_by:
        if fixable:
            changes["disable_repositories"] = [alias for fid in fixable for alias in aliases[fid]]
            covered.update(fixable)
        if "dms_prechecks_absent" in findings:
            changes["install_prechecks"] = "suse-migration-pre-checks"
        # patches_unknown: the count failed, often on a repository disabled above
        unknown = [i for i in ("patches_pending", "patches_unknown") if i in findings]
        if "patches_pending" in chosen and unknown:
            changes["patch"] = "zypper patch --with-interactive until nothing is left"
            covered.update(unknown)
        reboot = [i for i in ("reboot_pending", "reboot_unknown") if i in findings]
        if "reboot_pending" in chosen and (reboot or "patch" in changes):
            changes["reboot"] = "when zypper needs-rebooting asks for it"
            covered.update(reboot)
        if "multiversion_kernels" in chosen and "multiversion_kernels" in findings:
            changes["purge_kernels"] = "all except the latest and the running kernel"
            covered.add("multiversion_kernels")
        names = [i.split(":", 1)[1] for i, s in findings.items() if i.startswith("removed_package:") and s == "needs_action"]
        remove = sorted(set(names) & set(remove_packages or []))
        if remove:
            changes["remove_packages"] = remove
            covered.update("removed_package:" + name for name in remove)
        if "migration_product_not_set" in findings:
            changes["migration_product"] = "/".join([report["target"]["product"], report["target"]["version"],
                                                     report["source"]["arch"]])
            covered.add("migration_product_not_set")
        if "ssh_root_login" in chosen and findings.get("ssh_root_login") == "needs_action":
            changes["ssh_root_login"] = "/etc/ssh/sshd_config.d/50-permit-root-login.conf"
            covered.add("ssh_root_login")
    left = sorted(i for i, s in findings.items() if s != "info" and i not in covered)
    return {"changes": changes, "blocked_by": blocked_by, "left": left, "reasons": reasons}


class FilterModule(object):
    def filters(self):
        return {"sle16_upgrade_plan": sle16_upgrade_plan}
