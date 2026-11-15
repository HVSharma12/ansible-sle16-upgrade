# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import json
import os
import sys

import pytest
import yaml

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "plugins", "filter"))
import sle16_upgrade_verify as verifier  # noqa: E402  pylint: disable=wrong-import-position

with open(os.path.join(HERE, "..", "..", "..", "..", "roles", "verify", "vars", "main.yml")) as _handle:
    EXPECTED = yaml.safe_load(_handle)["__verify_expected"]
SETTINGS = {"target_version": "16.1", "fail_on": list(verifier.FAIL_ON), "expected": EXPECTED}


def fixture(name):
    with open(os.path.join(HERE, "fixtures", name + ".json")) as handle:
        return json.load(handle)


def compare(before, after, **settings):
    return verifier.sle16_upgrade_verify(after, {"host": "h", "facts": before}, dict(SETTINGS, **settings))


def ids(result, fails=None):
    return sorted(set(d["id"] for d in result["differences"] if fails is None or d["fails"] == fails))


def areas(result, fails=None):
    return sorted(c["area"] for c in result["cannot_tell"] if fails is None or c["fails"] == fails)


# a measured upgrade: SLES 15 SP7 (XFS) remediated, then upgraded to 16.1 by the upgrade role
CLEAN_BEFORE = fixture("clean-before")
CLEAN_AFTER = fixture("clean-after")


def clean():
    return copy.deepcopy(CLEAN_BEFORE), copy.deepcopy(CLEAN_AFTER)


def test_measured_clean_upgrade_passes():
    result = compare(CLEAN_BEFORE, CLEAN_AFTER)
    assert result["differences"] == [], result["lines"]
    assert result["cannot_tell"] == []
    assert result["verdict"] == "pass"
    assert "release 15.7 -> 16.1" in result["expected"]
    assert "AppArmor -> SELinux enforcing" in result["expected"]


def test_measured_clean_upgrade_without_the_expected_list_shows_what_it_covers():
    result = compare(CLEAN_BEFORE, CLEAN_AFTER, expected={})
    assert result["verdict"] == "fail"
    assert "service_stopped" in ids(result)


def test_measured_seeded_regressions_fail_and_nothing_else():
    # seeded before the upgrade: a service run by python3.11 on port 8080, a file system mounted by hand and a
    # second default route set at run time
    result = compare(fixture("regressions-before"), fixture("regressions-after"))
    assert [(d["id"], d["item"], d["fails"]) for d in result["differences"]] == [
        ("service_stopped", "verify-seed.service", True),
        ("unit_failed", "verify-seed.service", True),
        ("system_state", "systemd", False),
        ("mount_missing", "/mnt/verify-seed", True),
        ("default_route_changed", "default via 192.0.2.3", True),
        ("port_closed", "tcp/8080", True)]
    assert result["cannot_tell"] == []
    assert result["verdict"] == "fail"
    assert result["counts"] == {"service_stopped": 1, "unit_failed": 1, "system_state": 1, "mount_missing": 1,
                                "default_route_changed": 1, "port_closed": 1}


def test_measured_rollback_differs_only_in_the_release():
    # btrfs SP7, a migration failed inside the package transaction, snapper rollback, reboot; snapperd ran on
    # demand when the baseline was read and is not judged
    before, after = fixture("rolled-back-before"), fixture("rolled-back-after")
    assert "snapperd.service" in set(before["state"]["services_running"]) - set(after["state"]["services_running"])
    result = compare(before, after)
    assert [(d["id"], d["before"], d["after"]) for d in result["differences"]] == [
        ("not_target", "sles 15.7", "sles 15.7")]
    assert result["expected"] == []
    assert compare(before, after, fail_on=[i for i in verifier.FAIL_ON if i != "not_target"])["verdict"] == "pass"


def test_a_service_run_on_demand_is_not_judged_but_an_enabled_instance_is():
    before, after = clean()
    before["state"]["services_running"] += ["ondemand.service"]
    after["state"]["services_running"].remove("getty@tty1.service")
    assert [(d["id"], d["item"]) for d in compare(before, after)["differences"]] == [
        ("service_stopped", "getty@tty1.service")]


def test_a_service_from_an_init_script_is_judged():
    # the probe lists generated, runtime, indirect and alias units with the enabled ones
    before, after = clean()
    before["state"]["services_enabled"] += ["legacy-app.service"]
    before["state"]["services_running"] += ["legacy-app.service"]
    assert ids(compare(before, after), fails=True) == ["service_stopped"]


def test_same_host_twice_is_a_pass_except_the_release():
    result = compare(CLEAN_BEFORE, copy.deepcopy(CLEAN_BEFORE))
    assert ids(result) == ["not_target"]
    assert result["expected"] == []


def test_each_broken_change_fails():
    after = copy.deepcopy(CLEAN_AFTER)
    state = after["state"]
    unit = sorted(set(CLEAN_BEFORE["state"]["services_running"]) & set(state["services_running"])
                  & set(CLEAN_BEFORE["state"]["services_enabled"]))[0]
    state["services_running"].remove(unit)
    state["failed_units"].append(unit)
    mount = sorted(CLEAN_BEFORE["state"]["mounts"])[-1]
    del state["mounts"][mount]
    state["addresses"] = [a for a in state["addresses"] if a["family"] != "inet"]
    state["default_routes"] = [r for r in state["default_routes"] if r["family"] != "inet"]
    port = sorted(CLEAN_BEFORE["state"]["listening"])[0]
    state["listening"].pop(port, None)
    state["users"].pop("root")
    state["migration_boot_entry"] = True
    state["migration_log_failures"] = 2
    state["kernel_installed"] = False
    result = compare(CLEAN_BEFORE, after)
    assert ids(result, fails=True) == ["address_missing", "default_route_changed", "kernel_not_installed",
                                       "migration_boot_entry", "migration_failed", "mount_missing", "port_closed",
                                       "service_stopped", "unit_failed", "user_missing"]
    assert result["verdict"] == "fail"
    assert all(line.endswith("(fails)") for line in result["lines"] if not line.startswith("expected: "))


def test_reported_changes_do_not_fail_and_the_verdict_says_pass():
    before, after = clean()
    after["state"]["groups"] = {}
    after["state"]["avc_denials"] = 3
    after["state"]["system_state"] = "degraded"
    after["state"]["users"]["root"] = dict(after["state"]["users"]["root"], shell="/bin/sh")
    after["state"]["services_enabled"] = [u for u in after["state"]["services_enabled"] if u != "sshd.service"]
    after["state"]["mounts"]["/"] = "btrfs"
    after["updates"]["needs_reboot"] = True
    before["state"]["groups"] = {"ops": ["alice"], "root": ["alice"]}
    after["state"]["groups"] = {"root": []}
    before["repos"].append({"alias": "vendor", "enabled": True, "origin": "third_party"})
    result = compare(before, after)
    assert ids(result, fails=False) == ["group_members", "group_missing", "mount_changed", "reboot_pending",
                                        "repo_missing", "selinux_denials", "service_disabled", "system_state",
                                        "user_changed"]
    assert ids(result, fails=True) == []
    assert result["verdict"] == "pass"


def test_fail_on_decides_what_fails():
    before, after = clean()
    after["state"]["mounts"] = {}
    narrowed = [i for i in verifier.FAIL_ON if i != "mount_missing"]
    assert ids(compare(before, after, fail_on=narrowed), fails=True) == []
    assert compare(before, after, fail_on=narrowed)["verdict"] == "pass"
    assert "mount_missing" in ids(compare(before, after, fail_on=narrowed))
    after["updates"]["needs_reboot"] = True
    assert compare(before, after, fail_on=["reboot_pending"])["verdict"] == "fail"


def test_an_unregistered_host_fails():
    after = copy.deepcopy(CLEAN_AFTER)
    after["registration"]["credentials_file"] = False
    assert ids(compare(CLEAN_BEFORE, after), fails=True) == ["not_registered"]
    after = copy.deepcopy(CLEAN_AFTER)
    for repo in after["repos"]:
        repo["enabled"] = False
    after["registration"]["services"] = []
    assert ids(compare(CLEAN_BEFORE, after), fails=True) == ["not_registered"]


def test_a_half_migrated_host_fails():
    # SLES 16.1 in os-release, but the repositories and services of SLES 15 SP7 the host had before
    before, after = clean()
    after["repos"] = copy.deepcopy(before["repos"])
    after["registration"] = copy.deepcopy(before["registration"])
    result = compare(before, after)
    assert ids(result, fails=True) == ["not_registered", "repo_old_release"]
    assert result["counts"]["repo_old_release"] == len([r for r in before["repos"] if r["enabled"]])


def test_a_repository_of_sles_15_left_enabled_on_16_fails():
    before, after = clean()
    left = dict([r for r in before["repos"] if r["enabled"] and "SLES15-SP7-Pool" in r["alias"]][0])
    after["repos"].append(left)
    result = compare(before, after)
    assert [(d["id"], d["item"]) for d in result["differences"]] == [("repo_old_release", left["alias"])]
    assert result["verdict"] == "fail"


def test_the_migration_log_is_judged_on_the_target_only():
    before, after = clean()
    after["state"]["migration_log_failures"] = 1
    assert ids(compare(before, after)) == ["migration_failed"]
    rolled = fixture("rolled-back-after")
    rolled["state"]["migration_log_failures"] = 1
    assert ids(compare(fixture("rolled-back-before"), rolled)) == ["not_target"]


def test_another_distribution_is_not_the_target():
    before, after = clean()
    after["os"]["id"] = "opensuse-leap"
    assert ("not_target", "sles 15.7", "opensuse-leap 16.1") in [
        (d["id"], d["before"], d["after"]) for d in compare(before, after)["differences"]]
    before["os"]["id"] = "opensuse-leap"
    assert areas(compare(before, CLEAN_AFTER), fails=True) == ["baseline"]


def test_a_replacement_that_does_not_run_is_a_stopped_service():
    # what ran at boot before (enabled) and is gone after the measured upgrade
    replaced = sorted(set(CLEAN_BEFORE["state"]["services_running"]) & set(CLEAN_BEFORE["state"]["services_enabled"])
                      - set(CLEAN_AFTER["state"]["services_running"]))
    successors = set(EXPECTED["services"][u] for u in replaced if EXPECTED["services"].get(u))
    assert successors, "the measured upgrade replaced no service"
    after = copy.deepcopy(CLEAN_AFTER)
    after["state"]["services_running"] = [u for u in after["state"]["services_running"] if u not in successors]
    result = compare(CLEAN_BEFORE, after)
    assert set(d["item"] for d in result["differences"] if d["id"] == "service_stopped") >= set(
        u for u in replaced if EXPECTED["services"].get(u))


def test_selinux_is_expected_only_when_enforcing():
    before, after = clean()
    after["state"]["selinux_mode"] = "permissive"
    result = compare(before, after)
    assert [(d["id"], d["before"], d["after"], d["fails"]) for d in result["differences"]] == [
        ("selinux_mode", "disabled", "permissive", False)]
    assert not [e for e in result["expected"] if "SELinux" in e]


def test_a_port_from_the_ephemeral_range_may_move_but_a_fixed_one_may_not():
    before, after = clean()
    before["state"]["listening"]["udp/45678"] = {"processes": ["rpc.statd"], "scope": "any"}
    after["state"]["listening"]["udp/51234"] = {"processes": ["rpc.statd"], "scope": "any"}
    before["state"]["listening"]["tcp/2049"] = {"processes": ["rpc.statd"], "scope": "any"}
    result = compare(before, after)
    assert [(d["id"], d["item"]) for d in result["differences"]] == [("port_closed", "tcp/2049")]
    assert [e for e in result["expected"] if e.startswith("udp/45678 (rpc.statd)")]


def test_a_port_that_narrows_to_loopback_is_closed_to_clients():
    before, after = clean()
    after["state"]["listening"]["tcp/22"] = {"processes": ["sshd"], "scope": "loopback"}
    assert [(d["id"], d["item"], d["after"]) for d in compare(before, after)["differences"]] == [
        ("port_closed", "tcp/22", "loopback only")]
    after["state"]["listening"]["tcp/22"] = {"processes": ["sshd"], "scope": "address"}
    assert compare(before, after)["differences"] == []


def test_a_slaac_address_may_change_within_its_prefix_but_a_static_one_may_not():
    before, after = clean()
    before["state"]["addresses"] += [
        {"dev": "eth0", "address": "2001:db8:1::5054:ff:fe12:3456/64", "family": "inet6", "dynamic": True},
        {"dev": "eth0", "address": "2001:db8:2::10/64", "family": "inet6", "dynamic": False}]
    after["state"]["addresses"] += [
        {"dev": "eth0", "address": "2001:db8:1::8a3c:51d2:9e47:b06f/64", "family": "inet6", "dynamic": True},
        {"dev": "eth0", "address": "2001:db8:2::11/64", "family": "inet6", "dynamic": False}]
    result = compare(before, after)
    assert [(d["id"], d["item"]) for d in result["differences"]] == [("address_missing", "2001:db8:2::10/64")]
    assert "2001:db8:1::5054:ff:fe12:3456/64 -> another address in 2001:db8:1::/64" in result["expected"]


@pytest.mark.parametrize("area", ["services_running", "services_enabled", "addresses", "listening", "users",
                                  "migration_boot_entry", "migration_log_failures", "kernel_installed"])
def test_an_area_behind_a_failing_id_not_read_is_cannot_tell(area):
    after = copy.deepcopy(CLEAN_AFTER)
    after["state"][area] = None
    result = compare(CLEAN_BEFORE, after)
    assert areas(result) == [area]
    assert areas(result, fails=True) == [area]
    assert result["verdict"] == "cannot_tell"
    assert [l for l in result["lines"] if l.startswith("cannot tell: %s: " % area) and l.endswith("(fails)")]


@pytest.mark.parametrize("area", ["avc_denials", "system_state", "selinux_mode", "groups"])
def test_an_area_behind_reported_ids_not_read_is_reported(area):
    after = copy.deepcopy(CLEAN_AFTER)
    after["state"][area] = None
    result = compare(CLEAN_BEFORE, after)
    assert areas(result, fails=False) == [area]
    assert result["verdict"] == "pass"


def test_an_unanswered_reboot_check_and_a_root_less_read_are_never_a_pass():
    after = copy.deepcopy(CLEAN_AFTER)
    after["updates"]["needs_reboot"] = None
    assert areas(compare(CLEAN_BEFORE, after), fails=False) == ["reboot_pending"]
    assert compare(CLEAN_BEFORE, after, fail_on=["reboot_pending"])["verdict"] == "cannot_tell"
    after["registration"]["credentials_file"] = None
    assert areas(compare(CLEAN_BEFORE, after), fails=True) == ["registration"]


def test_a_baseline_without_state_cannot_tell_anything():
    before = copy.deepcopy(CLEAN_BEFORE)
    del before["state"]
    result = compare(before, CLEAN_AFTER)
    assert result["verdict"] == "cannot_tell"
    assert len(areas(result, fails=True)) >= 8


def test_a_baseline_read_on_the_target_cannot_tell():
    result = compare(CLEAN_AFTER, CLEAN_AFTER)
    assert result["cannot_tell"][0] == {"area": "baseline", "fails": True,
                                        "reason": "it was read on sles 16.1, not on SLES 15 before the upgrade"}
    assert result["verdict"] == "cannot_tell"


def test_lines_name_the_reason():
    after = copy.deepcopy(CLEAN_AFTER)
    after["state"]["mounts"] = {}
    line = [l for l in compare(CLEAN_BEFORE, after)["lines"] if l.startswith("mount_missing /: ")][0]
    assert line == "mount_missing /: xfs -> not mounted; data or software on it is not reachable (fails)"


def test_a_lost_kernel_parameter_is_reported_masked_but_the_new_image_is_not():
    before = copy.deepcopy(CLEAN_BEFORE)
    before["boot"]["cmdline"] += " audit=1 rd.iscsi.password=s3cret"
    result = compare(before, CLEAN_AFTER)
    assert [(d["id"], d["item"], d["fails"]) for d in result["differences"]] == [
        ("kernel_cmdline", "audit=1", False), ("kernel_cmdline", "rd.iscsi.password=****", False)]
    assert "s3cret" not in json.dumps(result)
