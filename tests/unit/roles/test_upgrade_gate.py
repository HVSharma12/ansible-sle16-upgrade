# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os

import pytest

from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar

TASKS = os.path.join(os.path.dirname(__file__), "..", "..", "..", "roles", "upgrade", "tasks", "main.yml")

if not hasattr(Templar, "evaluate_conditional"):
    pytest.skip("needs ansible-core 2.19 or later", allow_module_level=True)

# raw output: a terminal is allocated, so every line ends in \r\n
SP7 = 'NAME="SLES"\r\nVERSION="15-SP7"\r\nVERSION_ID="15.7"\r\nPRETTY_NAME="SUSE Linux Enterprise Server 15 SP7"\r\n'
SLE161 = ('NAME="SLES"\r\nVERSION="16.1"\r\nVERSION_ID="16.1"\r\n'
          'PRETTY_NAME="SUSE Linux Enterprise Server 16.1"\r\n')
LOG = "DMS_LOG=present\r\n"
FIX = " (fix these, the remediate role covers some, and run again)"


def tasks():
    return DataLoader().load_from_file(TASKS, trusted_as_template=True)


def find(name, items=None):
    for task in items if items is not None else tasks():
        if task.get("name") == name:
            return task
        found = None
        for key in ("block", "rescue"):
            if task.get(key):
                found = found or find(name, task[key])
        if found:
            return found
    return None


def templar(task, **variables):
    return Templar(loader=DataLoader(), variables=dict(task.get("vars") or {}, **variables))


@pytest.mark.parametrize("stdout, expected", [(SP7, True), (SP7 + LOG, True), (SLE161, False), ("", False),
                                              ('VERSION_ID="12.5"\r\n', False)])
def test_only_a_sles_15_host_is_upgraded(stdout, expected):
    task = find("Upgrade a SLES 15 host")
    assert templar(task, __upgrade_before={"stdout": stdout}).evaluate_conditional(task["when"]) is expected


def report(verdict="ready", findings=(), fstype="xfs", snapper=False):
    return {"verdict": verdict, "findings": list(findings), "source": {"version": "15.7"},
            "target": {"version": "16.1"}, "facts": {"storage": {"root_fstype": fstype, "snapper_root": snapper}}}


def reasons(rep, stdout=SP7, accept=True):
    task = find("Refuse a host that is not ready")
    t = templar(task, analyse_report=rep, __upgrade_before={"stdout": stdout}, upgrade_accept_no_rollback=accept)
    return t.template(task["vars"]["__reasons"])


def test_a_ready_host_passes():
    assert reasons(report()) == []


def test_needs_action_refuses_and_names_the_ids():
    found = [{"id": "migration_product_not_set", "severity": "needs_action"},
             {"id": "patches_pending", "severity": "needs_action"}, {"id": "wicked", "severity": "info"}]
    assert reasons(report("needs_action", found)) == [
        "analyse says needs_action: migration_product_not_set, patches_pending" + FIX]


def test_blocked_refuses():
    out = reasons(report("blocked", [{"id": "free_space_low", "severity": "blocker"}]))
    assert out == ["analyse says blocked: free_space_low" + FIX]


def test_an_earlier_migration_log_refuses():
    out = reasons(report(), SP7 + LOG)
    assert len(out) == 1
    assert "/var/log/distro_migration.log" in out[0]
    assert "move the log aside" in out[0]
    assert "mv /var/log/distro_migration.log /var/log/distro_migration.log.failed" in out[0]


@pytest.mark.parametrize("fstype, snapper, accept, refused", [
    ("xfs", False, False, True), ("btrfs", False, False, True), ("btrfs", True, False, False),
    ("xfs", False, True, False), ("ext4", False, True, False)])
def test_no_rollback_needs_the_opt_in(fstype, snapper, accept, refused):
    out = reasons(report(fstype=fstype, snapper=snapper), accept=accept)
    assert bool(out) is refused
    if refused:
        assert "upgrade_accept_no_rollback: true" in out[0]


def test_every_reason_is_listed():
    assert len(reasons(report("blocked", [{"id": "cpu_level", "severity": "blocker"}]), SP7 + LOG, False)) == 3


def after(stdout, target="16.1"):
    task = find("Stop unless the host runs the target")
    t = templar(task, __upgrade_after={"stdout_lines": stdout.splitlines()}, __upgrade_target_version=target)
    assertion = task["ansible.builtin.assert"]
    return t.evaluate_conditional(assertion["that"]), t.template(assertion["fail_msg"])


def test_the_target_passes():
    assert after(SLE161 + "STATE=running\r\n")[0] is True


def test_a_host_back_on_15_fails_with_the_log():
    # the DMS log of a failed migration on SLES 15 SP7, through the role's grep
    cause = ("Migration failed with: zypper failed with: bash: stderr: (no output on stderr), stdout: flag provided "
             "but not defined: -e2e-unknown-option")
    stdout = SP7 + LOG + "DMS=" + cause + "\r\n"
    ok, msg = after(stdout)
    assert ok is False
    assert "the host runs SUSE Linux Enterprise Server 15 SP7" in msg
    assert cause in msg


@pytest.mark.parametrize("result, expected", [({"unreachable": True, "msg": "Permission denied"}, True),
                                              ({"failed": True, "msg": "Timed out"}, False),
                                              ({"skipped": True}, False), ({"rebooted": True}, False)])
def test_an_unreachable_host_goes_to_the_rescue(result, expected):
    task = find("Stop when the host cannot be reached")
    assert templar(task, __upgrade_reboot=result).evaluate_conditional(task["when"]) is expected


def test_the_wait_has_a_reachable_rescue():
    reboot = find("Reboot into the migration")
    assert reboot["ignore_unreachable"] is True
    rescue = find("Stop when the host does not come back")
    # what the reboot module's last boot check returns while the migration system refuses root (SP7, core 2.20.2)
    refused = ("Task failed: Failed to connect to the host via ssh: Warning: Permanently added '[127.0.0.3]:3551' "
               "(ED25519) to the list of known hosts.\r\nroot@127.0.0.3: Permission denied "
               "(publickey,password,keyboard-interactive).\n")
    msg = templar(rescue, ansible_failed_result={"msg": refused}).template(rescue["ansible.builtin.fail"]["msg"])
    assert "\n" not in msg
    assert msg.startswith("The host did not come back from the migration in time (Task failed: ")
    assert "Permission denied (publickey,password,keyboard-interactive).)." in msg
    assert "run the role again" in msg


@pytest.mark.parametrize("stdout", ["", "garbage\r\n", 'VERSION_ID="16.0"\r\n'])
def test_another_release_or_no_release_fails(stdout):
    assert after(stdout)[0] is False


def test_the_result_lists_the_failed_units():
    task = find("Report the result")
    stdout = SLE161 + "STATE=degraded\r\nFAILED=kdump.service loaded failed failed Load kdump kernel\r\n" + LOG
    t = templar(task, __upgrade_after={"stdout_lines": stdout.splitlines()}, __upgrade_target_version="16.1",
                __upgrade_snapshot={"stdout": "42\n"}, __upgrade_reboot={"rebooted": True})
    result = t.template(task["ansible.builtin.set_fact"]["upgrade_result"])
    assert result == {"upgraded": True, "version_id": "16.1", "system_state": "degraded",
                      "failed_units": ["kdump.service"], "migration_log": "/var/log/distro_migration.log",
                      "rollback_snapshot": "42"}


def test_a_rerun_reports_without_an_upgrade():
    task = find("Report the result")
    t = templar(task, __upgrade_after={"stdout_lines": (SLE161 + "STATE=running\r\n").splitlines()},
                __upgrade_target_version="16.1")
    result = t.template(task["ansible.builtin.set_fact"]["upgrade_result"])
    assert result["upgraded"] is False
    assert result["failed_units"] == []
    assert result["migration_log"] is None
    assert result["rollback_snapshot"] is None
