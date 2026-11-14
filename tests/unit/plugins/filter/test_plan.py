# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "plugins", "filter"))
import sle16_upgrade as plugin  # noqa: E402  pylint: disable=wrong-import-position
import sle16_upgrade_plan as planner  # noqa: E402  pylint: disable=wrong-import-position
from test_sle16_upgrade import READY, SETTINGS, DMS_CLEAN  # noqa: E402  pylint: disable=wrong-import-position

ALL = list(planner.OPT_IN)
THIRD = {"alias": "obs", "enabled": True, "origin": "third_party", "url": "https://download.opensuse.org/x"}
LOCAL = {"alias": "dvd", "enabled": True, "origin": "local", "url": "dvd:/"}


def stock():
    """A registered stock SP7 cloud image as analyse sees it."""
    probe = copy.deepcopy(READY)
    probe["kernels"].update(installed=["kernel-default-base-1", "kernel-default-base-2"],
                            multiversion_kernels="latest,latest-1,running")
    probe["packages"]["removed_installed"] = ["dhcp-client", "salt", "salt-minion"]
    probe["ssh"]["permit_root_login"] = "yes"
    probe["updates"].update(needed_patches=3, needs_reboot=True)
    probe["dms"]["migration_product"] = None
    probe["repos"] = probe["repos"] + [THIRD, LOCAL, dict(THIRD, alias="off", enabled=False)]
    return probe


def plan(probe, opt_in=(), remove=(), dms=None):
    result = plugin.sle16_upgrade_report(probe, {"installed": False} if dms is None else dms, SETTINGS)
    report = dict(result, facts=probe, source={"arch": "x86_64"}, target={"product": "SLES", "version": "16.1"})
    return planner.sle16_upgrade_plan(report, list(opt_in), list(remove))


def test_defaults_change_only_the_two_automatic_items():
    result = plan(stock())
    assert set(result["changes"]) == {"install_prechecks", "migration_product"}
    assert result["changes"]["migration_product"] == "SLES/16.1/x86_64"
    assert result["blocked_by"] == []
    assert result["left"] == ["multiversion_kernels", "patches_pending", "reboot_pending", "removed_package:salt",
                              "removed_package:salt-minion", "repos_local", "repos_third_party", "ssh_root_login"]


def test_every_opt_in_covers_the_stock_host():
    result = plan(stock(), ALL, ["salt", "salt-minion"])
    assert set(result["changes"]) == {"disable_repositories", "install_prechecks", "patch", "reboot",
                                      "purge_kernels", "remove_packages", "migration_product", "ssh_root_login"}
    assert result["changes"]["disable_repositories"] == ["obs", "dvd"]
    assert result["changes"]["remove_packages"] == ["salt", "salt-minion"]
    assert result["changes"]["ssh_root_login"] == "/etc/ssh/sshd_config.d/50-permit-root-login.conf"
    assert result["left"] == []


def test_ready_host_plans_nothing():
    assert plan(READY, ALL, ["salt"], DMS_CLEAN) == {"changes": {}, "blocked_by": [], "left": [], "reasons": {}}


@pytest.mark.parametrize("path,value,blocker", [
    ("storage.free_mb", {"/": 100}, "free_space_low"),
    ("storage.separate", ["/var"], "os_split_partitions"),
    ("registration.services", [], "not_registered"),
])
def test_a_blocker_not_opted_in_leaves_the_host_alone(path, value, blocker):
    probe = stock()
    section, key = path.split(".")
    probe[section][key] = value
    result = plan(probe, ALL, ["salt-minion"])
    assert result["changes"] == {}
    assert result["blocked_by"] == [blocker]
    assert blocker in result["left"] and "patches_pending" in result["left"]


def test_a_blocker_that_is_opted_in_does_not_block():
    dms = dict(DMS_CLEAN, records=[{"check": "for local private repos", "level": "ERROR", "message": "x"}])
    result = plan(stock(), ["repos_local"], [], dms)
    assert result["blocked_by"] == []
    assert result["changes"]["disable_repositories"] == ["dvd"]


@pytest.mark.parametrize("level,blocked_by", [("ERROR", ["repos_local"]), ("WARNING", [])])
def test_a_disabled_local_repo_reported_by_dms_stays(level, blocked_by):
    probe = stock()
    probe["repos"] = [r for r in probe["repos"] if r["alias"] != "dvd"] + [dict(LOCAL, enabled=False)]
    dms = dict(DMS_CLEAN, records=[{"check": "for local private repos", "level": level, "message": "dvd:/"}])
    result = plan(probe, ALL, [], dms)
    assert result["blocked_by"] == blocked_by
    assert "repos_local" in result["left"]
    assert result["changes"].get("disable_repositories") == (None if level == "ERROR" else ["obs"])
    assert result["reasons"] == {"repos_local": "no enabled local repository to disable; disabled: dvd; remove the .repo file"}


def test_an_empty_repos_dir_blocks_with_its_reason():
    probe = stock()
    probe["repos"] = []
    dms = dict(DMS_CLEAN, records=[{"check": "for local private repos", "level": "ERROR",
                                    "message": "No repositories in /etc/zypp/repos.d"}])
    result = plan(probe, ALL, [], dms)
    assert result["blocked_by"] == ["repos_local"] and result["changes"] == {}
    assert result["reasons"] == {"repos_local": "no enabled local repository found; read the DMS message in the finding"}


def test_packages_are_removed_only_when_reported_and_named():
    result = plan(stock(), [], ["salt-minion", "dhcp-client", "vim"])
    assert result["changes"]["remove_packages"] == ["salt-minion"]
    assert "removed_package:salt" in result["left"]
    assert "removed_package:dhcp-client" not in result["left"]


def test_reboot_follows_the_patches_when_opted_in():
    probe = stock()
    probe["updates"]["needs_reboot"] = False
    assert "reboot" in plan(probe, ["patches_pending", "reboot_pending"])["changes"]
    assert "reboot" not in plan(probe, ["reboot_pending"])["changes"]
    assert "reboot" not in plan(probe, ["patches_pending"])["changes"]


def test_an_uncounted_patch_state_is_patched_when_opted_in():
    probe = stock()
    probe["updates"] = {"needed_patches": None, "security_patches": None, "needs_reboot": False,
                        "patches_error": "zypper list-patches exit code 4"}
    assert "patches_unknown" in plan(probe)["left"]
    result = plan(probe, ["patches_pending", "repos_third_party"])
    assert "patch" in result["changes"] and "patches_unknown" not in result["left"]


def test_an_unchecked_reboot_state_is_rechecked_when_opted_in():
    probe = stock()
    probe["updates"] = {"needed_patches": 0, "security_patches": 0, "needs_reboot": None,
                        "reboot_error": "zypper needs-rebooting exit code 7"}
    assert "reboot_unknown" in plan(probe)["left"]
    result = plan(probe, ["reboot_pending"])
    assert "reboot" in result["changes"] and "reboot_unknown" not in result["left"]


def test_root_login_kept_by_a_dropin_is_not_touched():
    probe = stock()
    probe["ssh"]["root_login_dropin"] = True
    assert "ssh_root_login" not in plan(probe, ALL)["changes"]


def test_unknown_opt_in_is_ignored():
    assert plan(stock(), ["free_space_low", "not_registered"]) == plan(stock())
