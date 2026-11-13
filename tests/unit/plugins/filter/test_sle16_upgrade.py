# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "plugins", "filter"))
import sle16_upgrade as plugin  # noqa: E402  pylint: disable=wrong-import-position

SETTINGS = {
    "target_product": "SLES",
    "target_version": "16.1",
    "arch": "x86_64",
    "supported_sources": {"16.0": ["15.7"], "16.1": ["15.5", "15.6", "15.7"]},
    "conflict_sources": {"16.0": ["15.6"]},
    "min_free_mb": "2048",
    "removed_packages": {"salt-minion": {"release": "16.0", "remediation": "x"},
                         "dhcp-client": {"release": "16.0", "severity": "info", "remediation": "z"},
                         "stress-ng": {"release": "16.1", "remediation": "y"}},
    "pinned_interpreter": "",
}

# A registered SP7 host prepared as the upgrade guide asks: nothing to report but information.
READY = {
    "os": {"id": "sles", "version_id": "15.7", "transactional": False},
    "products": [{"name": "SLES", "version": "15.7", "arch": "x86_64", "base": True}],
    "cpu": {"machine": "x86_64", "level": "x86_64_v3", "power_generation": None},
    "registration": {"credentials_file": True, "server": "https://scc.suse.com", "server_configured": False,
                     "services": [{"alias": "SUSE_Linux_Enterprise_Server_15_SP7_x86_64", "host": "scc.suse.com",
                                   "url": "https://scc.suse.com/access/services/1", "enabled": True}]},
    "repos": [{"alias": "SLES:Pool", "enabled": True, "origin": "suse", "url": "https://updates.suse.com/x"}],
    "storage": {"root_fstype": "btrfs", "root_source": "/dev/vda3", "separate": ["/boot"], "root_encrypted": False,
                "xfs_v4": False, "snapper_root": True, "free_mb": {"/": 15000}, "mounts": {"/": "btrfs", "/home": "xfs"}},
    "boot": {"firmware": "efi", "grub2_installed": True, "grub2_cfg": True, "systemd_boot_entries": False},
    "kernels": {"running": "6.4.0-150700.53.87-default", "installed": ["kernel-default-6.4.0-150700.53.87.1"],
                "multiversion": "provides:multiversion(kernel)", "multiversion_kernels": "latest,running"},
    "packages": {"count": 400, "arch32_count": 0, "removed_installed": [], "dms": {}},
    "network": {"wicked": {"enabled": "disabled", "active": "inactive"}, "team": [], "bond": [], "bridge": []},
    "ssh": {"enabled": "enabled", "active": "active", "permit_root_login": "no", "root_login_dropin": False},
    "lsm": {"apparmor_enabled": True, "apparmor_modified_profiles": []},
    "cgroup": {"fs": "cgroup2fs", "cmdline_unified": None},
    "updates": {"needed_patches": 0, "security_patches": 0, "needs_reboot": False},
    "virt": {"running_guests": [], "xen_dom0": False, "virt_type": None},
    "management": {"suse_manager_client": False, "public_cloud": False, "ha_corosync": False},
    "dms": {"host_config": True, "migration_product": "SLES/16.1/x86_64", "migration_image": [], "prechecks_bin": True},
}
DMS_CLEAN = {"installed": True, "version": "2.1.39", "records": [], "error": None}


def report(probe=None, dms=None, settings=None):
    return plugin.sle16_upgrade_report(probe or READY, DMS_CLEAN if dms is None else dms, settings or SETTINGS)


def mutate(path, value):
    probe = copy.deepcopy(READY)
    node = probe
    keys = path.split(".")
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = value
    return probe


def ids(result):
    return dict((f["id"], f["severity"]) for f in result["findings"])


def test_ready_host_is_ready():
    result = report()
    assert result["verdict"] == "ready"
    assert result["counts"] == {"blocker": 0, "needs_action": 0, "info": 0}


@pytest.mark.parametrize("path,value,fid,severity", [
    ("os.version_id", "15.4", "source_version_unsupported", "blocker"),
    ("os.version_id", "16.0", "already_sle16", "blocker"),
    ("os.transactional", True, "transactional_host", "blocker"),
    ("products", [{"name": "SLED", "version": "15.7", "base": True}], "product_unsupported", "blocker"),
    ("cpu.level", "x86_64", "cpu_level", "blocker"),
    ("cpu", {"machine": "ppc64le", "level": None, "power_generation": 9}, "cpu_level", "blocker"),
    ("registration.credentials_file", False, "not_registered", "blocker"),
    ("registration.services", [], "not_registered", "blocker"),
    ("management.suse_manager_client", True, "suse_manager_client", "blocker"),
    ("storage.root_encrypted", True, "root_encrypted", "blocker"),
    ("storage.separate", ["/boot", "/var"], "os_split_partitions", "blocker"),
    ("storage.free_mb", {"/": 1500}, "free_space_low", "blocker"),
    ("storage.mounts", {"/": "reiserfs"}, "filesystem_dropped:/", "blocker"),
    ("storage.mounts", {"/": "btrfs", "/srv": "reiserfs"}, "filesystem_dropped:/srv", "needs_action"),
    ("boot.grub2_cfg", False, "bootloader_not_grub2", "blocker"),
    ("boot.systemd_boot_entries", True, "bootloader_not_grub2", "blocker"),
    ("virt.xen_dom0", True, "xen_host", "blocker"),
    ("virt.virt_type", "xen", "xen_guest", "needs_action"),
    ("virt.running_guests", ["vm1"], "kvm_guests_running", "needs_action"),
    ("dms.migration_product", None, "migration_product_not_set", "needs_action"),
    ("kernels.multiversion_kernels", "latest,latest-1,running", "multiversion_kernels", "needs_action"),
    ("kernels.installed", ["kernel-default-1", "kernel-default-2"], "multiversion_kernels", "needs_action"),
    ("ssh.permit_root_login", "yes", "ssh_root_login", "needs_action"),
    ("repos", [{"alias": "obs", "enabled": True, "origin": "third_party", "url": "https://download.opensuse.org/x"}],
     "repos_third_party", "needs_action"),
    ("repos", [{"alias": "dvd", "enabled": True, "origin": "local", "url": "dvd:/"}], "repos_local", "needs_action"),
    ("packages.removed_installed", ["salt-minion"], "removed_package:salt-minion", "needs_action"),
    ("packages.arch32_count", 3, "packages_32bit", "info"),
    ("packages.removed_installed", ["dhcp-client"], "removed_package:dhcp-client", "info"),
    ("lsm.apparmor_modified_profiles", ["/etc/apparmor.d/usr.sbin.ntpd"], "apparmor_modified", "needs_action"),
    ("network.team", ["team0"], "network_team", "needs_action"),
    ("network.wicked", {"enabled": "enabled", "active": "active"}, "network_wicked", "info"),
    ("cgroup.fs", "tmpfs", "cgroup_v1", "needs_action"),
    ("cgroup.cmdline_unified", "0", "cgroup_v1", "needs_action"),
    ("updates.needed_patches", 4, "patches_pending", "needs_action"),
    ("updates.needs_reboot", True, "reboot_pending", "needs_action"),
    ("management.ha_corosync", True, "ha_cluster", "needs_action"),
    ("management.public_cloud", True, "public_cloud", "info"),
    ("storage.xfs_v4", True, "xfs_v4", "info"),
    ("storage.snapper_root", False, "no_rollback_snapshot", "info"),
    ("boot.firmware", "bios", "bios_legacy", "info"),
    ("cpu", {"machine": "s390x", "level": None, "power_generation": None}, "s390x_run_migration", "needs_action"),
])
def test_seeded_condition_is_reported(path, value, fid, severity):
    found = ids(report(mutate(path, value)))
    assert found.get(fid) == severity
    expected = "blocked" if severity == "blocker" else "needs_action" if severity == "needs_action" else "ready"
    assert report(mutate(path, value))["verdict"] == expected


def test_disabled_third_party_repo_is_not_reported():
    probe = mutate("repos", [{"alias": "obs", "enabled": False, "origin": "third_party", "url": "https://x/"}])
    assert "repos_third_party" not in ids(report(probe))


def test_removed_package_release_picks_its_release_notes():
    finding = report(mutate("packages.removed_installed", ["stress-ng"]))["findings"][0]
    assert finding["sources"][0]["ref"] == "RN161 §13.1"
    assert finding["remediation"] == "y"


def test_root_login_kept_by_dropin_is_information():
    probe = mutate("ssh.permit_root_login", "yes")
    probe["ssh"]["root_login_dropin"] = True
    assert ids(report(probe))["ssh_root_login"] == "info"


def test_pinned_python311_interpreter():
    settings = dict(SETTINGS, pinned_interpreter="/usr/bin/python3.11")
    assert ids(report(settings=settings))["ansible_interpreter_pinned"] == "needs_action"
    settings = dict(SETTINGS, pinned_interpreter="auto_silent")
    assert "ansible_interpreter_pinned" not in ids(report(settings=settings))


def test_sp6_to_16_0_is_the_documented_conflict():
    settings = dict(SETTINGS, target_version="16.0")
    found = ids(report(mutate("os.version_id", "15.6"), settings=settings))
    assert found == {"source_version_conflict": "needs_action"}


def test_sp5_is_a_source_for_16_1_only():
    assert "source_version_unsupported" not in ids(report(mutate("os.version_id", "15.5")))
    settings = dict(SETTINGS, target_version="16.0")
    assert ids(report(mutate("os.version_id", "15.5"), settings=settings))["source_version_unsupported"] == "blocker"


def test_target_16_0_needs_no_migration_product():
    settings = dict(SETTINGS, target_version="16.0")
    assert "migration_product_not_set" not in ids(report(mutate("dms.migration_product", None), settings=settings))


def test_sap_target_matches_sap_migration_product():
    probe = mutate("products", [{"name": "SLES_SAP", "version": "15.7", "base": True}])
    probe["dms"]["migration_product"] = "SLES_SAP/16.1/x86_64"
    settings = dict(SETTINGS, target_product="SLES_SAP")
    assert ids(report(probe, settings=settings)) == {"sap_product": "info"}


def test_extensions_are_listed():
    probe = mutate("products", READY["products"] + [{"name": "sle-module-containers", "base": False}])
    assert ids(report(probe))["extensions_installed"] == "info"


def test_dms_absent_is_information():
    assert ids(report(dms={"installed": False})) == {"dms_prechecks_absent": "info"}


def test_dms_error_from_uncovered_check_blocks():
    dms = dict(DMS_CLEAN, records=[{"check": "upgrade path against registration server", "level": "ERROR",
                                    "message": "No migration available"}])
    result = report(dms=dms)
    assert ids(result) == {"dms:upgrade_path_against_registration_server": "blocker"}
    assert result["findings"][0]["check"] == "dms"


def test_dms_message_for_covered_check_becomes_evidence():
    probe = mutate("ssh.permit_root_login", "yes")
    dms = dict(DMS_CLEAN, records=[{"check": "sshd configuration", "level": "WARNING", "message": "Root login by ssh"}])
    finding = [f for f in report(probe, dms)["findings"] if f["id"] == "ssh_root_login"][0]
    assert finding["check"] == "role+dms"
    assert "DMS: Root login by ssh" in finding["found"]


def test_dms_finding_for_covered_check_the_role_missed_uses_role_id():
    dms = dict(DMS_CLEAN, records=[{"check": "LSM migration", "level": "ERROR", "message": "Modified AppArmor profiles"}])
    assert ids(report(dms=dms)) == {"apparmor_modified": "blocker"}


def test_dms_info_is_dropped_except_wicked2nm_details():
    dms = dict(DMS_CLEAN, records=[
        {"check": "high availability extension", "level": "INFO", "message": "corosync.conf not found."},
        {"check": "wicked to NetworkManager migration", "level": "INFO",
         "message": "wicked2nm can migrate ... [INFO] ipv4_dhcp.update in interface eth0"}])
    assert ids(report(dms=dms)) == {"dms:wicked_to_networkmanager_migration": "info"}


def test_dms_messages_of_one_check_merge_at_the_highest_severity():
    dms = dict(DMS_CLEAN, records=[{"check": "x", "level": "WARNING", "message": "a"},
                                   {"check": "x", "level": "ERROR", "message": "b"}])
    finding = report(dms=dms)["findings"][0]
    assert (finding["severity"], finding["found"]) == ("blocker", "a | b")


def test_dms_stopped_early():
    assert ids(report(dms=dict(DMS_CLEAN, error="KeyError: x")))["dms_prechecks_error"] == "needs_action"


def test_findings_are_sorted_and_carry_sources():
    probe = mutate("packages.arch32_count", 2)
    probe["storage"]["free_mb"] = {"/": 10}
    probe["ssh"]["permit_root_login"] = "yes"
    findings = report(probe)["findings"]
    assert [f["severity"] for f in findings] == ["blocker", "needs_action", "info"]
    for finding in findings:
        assert set(finding) == {"id", "severity", "title", "found", "remediation", "sources", "check"}
        assert finding["sources"] and all(s["url"].startswith("https://") for s in finding["sources"])


def test_same_input_same_report():
    assert report() == report()
