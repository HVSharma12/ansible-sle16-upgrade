# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os

import pytest

from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar

ROLE = os.path.join(os.path.dirname(__file__), "..", "..", "..", "roles", "upgrade")

if not hasattr(Templar, "evaluate_conditional"):
    pytest.skip("needs ansible-core 2.19 or later", allow_module_level=True)

# raw output: a terminal is allocated, so every line ends in \r\n
SP7 = 'NAME="SLES"\r\nVERSION="15-SP7"\r\nVERSION_ID="15.7"\r\nPRETTY_NAME="SUSE Linux Enterprise Server 15 SP7"\r\n'
SLE161 = ('NAME="SLES"\r\nVERSION="16.1"\r\nVERSION_ID="16.1"\r\n'
          'PRETTY_NAME="SUSE Linux Enterprise Server 16.1"\r\n')
LOG = "DMS_LOG=present\r\n"
MIGRATING = "MIGRATING=yes\r\n"
FIX = " (fix these, the remediate role covers some, and run again)"
TESTED = "this role is tested on SLES 15 SP7 x86_64 to SLES 16.1 only"
STARTED = "2026-11-15T06:00:00Z"


def load(*path):
    return DataLoader().load_from_file(os.path.join(ROLE, *path), trusted_as_template=True)


def find(name, items=None):
    for task in items if items is not None else load("tasks", "main.yml"):
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
    scope = dict(load("vars", "main.yml"), **(task.get("vars") or {}))
    return Templar(loader=DataLoader(), variables=dict(scope, **variables))


def holds(t, conditions):
    # a list of conditions holds when every one does, as in when: and assert's that:
    return all(t.evaluate_conditional(c) for c in ([conditions] if isinstance(conditions, str) else conditions))


def when(name, **variables):
    task = find(name)
    return holds(templar(task, **variables), task["when"])


@pytest.mark.parametrize("stdout, expected", [(SP7, True), (SP7 + LOG, True), (SLE161, False), ("", False),
                                              ('VERSION_ID="12.5"\r\n', False)])
def test_only_a_sles_15_host_is_upgraded(stdout, expected):
    assert when("Upgrade a SLES 15 host", __upgrade_before={"stdout": stdout}) is expected


def first_read(stdout):
    task = find("Stop unless the host runs SLES 15 or 16")
    t = templar(task, __upgrade_before={"stdout": stdout, "stdout_lines": stdout.splitlines()})
    assertion = task["ansible.builtin.assert"]
    return holds(t, assertion["that"]), t.template(assertion["fail_msg"])


@pytest.mark.parametrize("stdout", [SP7, SP7 + LOG, SLE161])
def test_sles_15_and_16_pass_the_first_read(stdout):
    assert first_read(stdout)[0] is True


def test_another_release_is_not_a_sles_15_host():
    ok, msg = first_read('VERSION_ID="12.5"\r\nPRETTY_NAME="SUSE Linux Enterprise Server 12 SP5"\r\n')
    assert ok is False
    assert msg == 'Not a SLES 15 host: PRETTY_NAME="SUSE Linux Enterprise Server 12 SP5"'


def test_the_migration_system_is_refused():
    ok, msg = first_read(SLE161 + MIGRATING)
    assert ok is False
    assert msg.startswith("The host runs the migration system")


def report(verdict="ready", findings=(), fstype="xfs", snapper=False):
    src = {"product": "SLES", "version": "15.7", "arch": "x86_64"}
    return {"verdict": verdict, "findings": list(findings), "source": src, "collected_at": STARTED,
            "target": {"product": "SLES", "version": "16.1"},
            "dms_prechecks": {"installed": True},
            "facts": {"storage": {"root_fstype": fstype, "snapper_root": snapper},
                      "updates": {"needed_patches": 0}}}


def reasons(rep, stdout=SP7, accept=True):
    task = find("Refuse a host that is not ready")
    t = templar(task, analyse_report=rep, __upgrade_before={"stdout": stdout}, upgrade_accept_no_rollback=accept,
                __upgrade_started=STARTED)
    return t.template(task["vars"]["__reasons"])


def test_a_ready_host_passes():
    assert reasons(report()) == []


def test_the_analysis_is_pinned_to_the_tested_target():
    task = find("Analyse the host")
    pins = templar(task).template(task["vars"])
    assert pins["analyse_run_dms_prechecks"] is True
    assert pins["analyse_check_patches"] is True
    assert pins["analyse_target_product"] == "SLES"
    assert pins["analyse_target_version"] == "16.1"


def test_an_unknown_patch_count_refuses():
    rep = report()
    rep["facts"]["updates"]["needed_patches"] = None
    assert reasons(rep) == ["the pending patches are not known: analyse_check_patches is false or zypper "
                            "list-patches failed"]


def test_needs_action_refuses_and_names_the_ids():
    found = [{"id": "migration_product_not_set", "severity": "needs_action"},
             {"id": "patches_pending", "severity": "needs_action"}, {"id": "wicked", "severity": "info"}]
    assert reasons(report("needs_action", found)) == [
        "analyse says needs_action: migration_product_not_set, patches_pending" + FIX]


def test_blocked_refuses():
    out = reasons(report("blocked", [{"id": "free_space_low", "severity": "blocker"}]))
    assert out == ["analyse says blocked: free_space_low" + FIX]


@pytest.mark.parametrize("change", [{"version": "15.6"}, {"version": "15.5"}, {"product": "SLES_SAP"},
                                    {"product": "SLE_RT"}, {"arch": "aarch64"}, {"arch": "ppc64le"},
                                    {"target": "16.0"}, {"target_product": "SLES_SAP"}])
def test_only_sp7_x86_64_to_16_1_is_upgraded(change):
    rep = report()
    for key, value in change.items():
        if key == "target":
            rep["target"]["version"] = value
        elif key == "target_product":
            rep["target"]["product"] = value
        else:
            rep["source"][key] = value
    assert reasons(rep) == [TESTED]


def test_missing_dms_prechecks_refuse():
    rep = report()
    rep["dms_prechecks"]["installed"] = False
    out = reasons(rep)
    assert len(out) == 1
    assert out[0].startswith("the DMS pre-checks did not run: install suse-migration-pre-checks")


def test_an_earlier_migration_log_refuses():
    out = reasons(report(), SP7 + LOG)
    assert len(out) == 1
    assert out[0].startswith("an earlier migration left /var/log/distro_migration.log")
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
    rep = report("blocked", [{"id": "cpu_level", "severity": "blocker"}])
    rep["source"]["version"] = "15.6"
    rep["dms_prechecks"]["installed"] = False
    assert len(reasons(rep, SP7 + LOG, False)) == 5


@pytest.mark.parametrize("collected, expected", [(STARTED, []), ("2026-11-15T06:00:01Z", []),
                                                 ("2026-11-14T23:59:59Z", ["the analysis is not from this run"])])
def test_only_an_analysis_of_this_run_counts(collected, expected):
    rep = report()
    rep["collected_at"] = collected
    assert reasons(rep) == expected


@pytest.mark.parametrize("gate, expected", [({"changed": False}, True), ({"failed": True}, False),
                                            ({"skipped": True}, False)])
def test_a_failed_gate_closes_the_install(gate, expected):
    # a failed gate whose error the caller ignored is still failed
    assert when("Install the migration and reboot into it", __upgrade_gate=gate) is expected


# the command module returns skipped in check mode, from --check or the check_mode keyword alike
CHECK = {"skipped": True, "changed": False, "msg": "Command would have run if not in check mode"}


@pytest.mark.parametrize("install, expected", [(CHECK, True), ({"changed": True}, False)])
def test_only_check_mode_says_what_it_would_do(install, expected):
    assert when("Show what check mode would do", __upgrade_install=install) is expected


def reboot_when(install=None, no_snapshot=None):
    return when("Reboot into the migration", __upgrade_install=install or {"changed": True},
                __upgrade_no_snapshot=no_snapshot or {"skipped": True})


def test_the_reboot_follows_a_good_install():
    assert reboot_when() is True


@pytest.mark.parametrize("install, no_snapshot", [({"failed": True}, None), (None, {"failed": True}), (CHECK, None)])
def test_no_reboot_after_a_failed_step_or_in_check_mode(install, no_snapshot):
    assert reboot_when(install, no_snapshot) is False


@pytest.mark.parametrize("install, snapshot, accept, expected", [
    ({"changed": True}, "", False, True), ({"changed": True}, "42\n", False, False),
    ({"changed": True}, "", True, False), (CHECK, "", False, False), ({"failed": True}, "", False, False)])
def test_no_snapshot_removes_the_migration_before_the_reboot(install, snapshot, accept, expected):
    assert when("Remove the migration again when snapper took no snapshot", __upgrade_install=install,
                __upgrade_snapshot={"stdout": snapshot}, upgrade_accept_no_rollback=accept) is expected


# zypper exits 104 when one of the names is not installed and removes the other (measured on SP7)
@pytest.mark.parametrize("rc, expected", [(0, False), (104, False), (8, True)])
def test_the_removal_fails_only_on_a_zypper_error(rc, expected):
    task = find("Remove the migration again when snapper took no snapshot")
    assert holds(templar(task, __upgrade_disarm={"rc": rc}), task["failed_when"]) is expected


@pytest.mark.parametrize("disarm, expected", [({"skipped": True}, False), ({"changed": True}, True),
                                              ({"failed": True, "changed": True}, True)])
def test_the_stop_follows_the_removal(disarm, expected):
    assert when("Stop when snapper took no snapshot", __upgrade_disarm=disarm) is expected


@pytest.mark.parametrize("disarm, end", [({"changed": True}, "the migration packages were removed again"),
                                         ({"failed": True}, "zypper --non-interactive remove "
                                          "suse-migration-sle16-activation SLES16-Migration")])
def test_the_stop_says_whether_the_host_is_armed(disarm, end):
    task = find("Stop when snapper took no snapshot")
    msg = templar(task, __upgrade_disarm=disarm).template(task["ansible.builtin.fail"]["msg"])
    assert msg.startswith("snapper took no snapshot before the migration, so it cannot be rolled back; ")
    assert msg.endswith(end)


@pytest.mark.parametrize("result, expected", [({"unreachable": True, "msg": "Permission denied"}, True),
                                              ({"failed": True, "msg": "Timed out"}, False),
                                              ({"skipped": True}, False), ({"rebooted": True}, False)])
def test_an_unreachable_host_goes_to_the_rescue(result, expected):
    assert when("Stop when the host cannot be reached", __upgrade_reboot=result) is expected


def rescue(failed, **variables):
    task = find("Stop and say what state the host is in")
    return templar(task, ansible_failed_result=failed, **variables).template(task["ansible.builtin.fail"]["msg"])


def test_a_timed_out_wait_says_the_host_may_still_migrate():
    assert find("Reboot into the migration")["ignore_unreachable"] is True
    # what the reboot module's last boot check returns while the migration system refuses root (SP7, core 2.20.2)
    refused = ("Task failed: Failed to connect to the host via ssh: Warning: Permanently added '[192.0.2.10]:22' "
               "(ED25519) to the list of known hosts.\r\nroot@192.0.2.10: Permission denied "
               "(publickey,password,keyboard-interactive).\n")
    for reboot in ({"unreachable": True, "msg": refused}, {"failed": True, "rebooted": True, "msg": refused}):
        msg = rescue({"msg": refused}, __upgrade_reboot=reboot)
        assert "\n" not in msg
        assert msg.startswith("The host did not come back from the migration in time (Task failed: ")
        assert "Permission denied (publickey,password,keyboard-interactive).)." in msg
        assert "It may still be migrating, or it may not have come back" in msg
        assert "When root can log in again, run the role again" in msg


DISARM = "disarm it with: zypper --non-interactive remove suse-migration-sle16-activation SLES16-Migration"


@pytest.mark.parametrize("install, armed", [({"changed": True}, "suse-migration-sle16-activation is installed, so"),
                                            ({"failed": True}, "If suse-migration-sle16-activation is installed,")])
def test_a_failed_reboot_gives_the_disarm_command(install, armed):
    msg = rescue({"msg": "Reboot command failed"}, __upgrade_install=install,
                 __upgrade_reboot={"failed": True, "rebooted": False})
    assert msg.startswith("The reboot into the migration did not start (Reboot command failed). " + armed)
    assert "the host migrates at its next reboot" in msg
    assert msg.endswith(DISARM)


def test_an_install_that_failed_gives_the_disarm_command_conditionally():
    msg = rescue({"msg": "non-zero return code"})
    assert "If suse-migration-sle16-activation is installed," in msg
    assert msg.endswith(DISARM)


def test_the_no_snapshot_stop_is_passed_on():
    why = "snapper took no snapshot before the migration, so it cannot be rolled back; the migration packages were "
    msg = rescue({"msg": why + "removed again"}, __upgrade_install={"changed": True},
                 __upgrade_no_snapshot={"failed": True, "msg": why + "removed again"})
    assert msg == "Not upgrading: " + why + "removed again"


@pytest.mark.parametrize("stdout, install, expected", [(SP7, CHECK, False), (SP7, {"skipped": True}, False),
                                                       (SP7, {"changed": True}, True), (SLE161, None, True)])
def test_the_result_is_read_unless_nothing_was_installed(stdout, install, expected):
    task = find("Read and report the result")
    variables = {"__upgrade_before": {"stdout": stdout}}
    if install is not None:
        variables["__upgrade_install"] = install
    assert holds(templar(task, **variables), task["when"]) is expected


def after(stdout):
    task = find("Stop unless the host runs the target")
    t = templar(task, __upgrade_after={"stdout_lines": stdout.splitlines()})
    assertion = task["ansible.builtin.assert"]
    return holds(t, assertion["that"]), " ".join(t.template(assertion["fail_msg"]).split())


def test_the_target_passes():
    assert after(SLE161 + "STATE=running\r\n")[0] is True


CAUSE = ("Migration failed with: zypper failed with: bash: stderr: (no output on stderr), stdout: flag provided "
         "but not defined: -e2e-unknown-option")


def test_a_host_back_on_15_fails_with_the_log():
    ok, msg = after(SP7 + LOG + "DMS=" + CAUSE + "\r\n")
    assert ok is False
    assert msg == ("SLES 16.1 not reached: the host runs SUSE Linux Enterprise Server 15 SP7. "
                   "/var/log/distro_migration.log: " + CAUSE)


def test_the_target_with_a_failed_migration_fails_and_says_it_was_reached():
    ok, msg = after(SLE161 + LOG + "DMS=" + CAUSE + "\r\n")
    assert ok is False
    assert msg == "SLES 16.1 reached, but the migration log reports a failure. /var/log/distro_migration.log: " + CAUSE


def test_an_armed_host_is_named_whatever_stopped_the_role():
    ok, msg = after(SP7 + "STATE=running\r\nARMED=yes\r\n")
    assert ok is False
    assert msg == ("SLES 16.1 not reached: the host runs SUSE Linux Enterprise Server 15 SP7. "
                   "suse-migration-sle16-activation is installed, so the next reboot starts the migration; " + DISARM)


@pytest.mark.parametrize("stdout", ["", "garbage\r\n", 'VERSION_ID="16.0"\r\n'])
def test_another_release_or_no_release_fails(stdout):
    assert after(stdout)[0] is False


@pytest.mark.parametrize("reboot, expected", [({"rebooted": True}, True), ({"skipped": True}, False)])
def test_the_interpreter_changes_only_after_the_upgrade(reboot, expected):
    assert when("Use the Python of SLES 16 for the rest of the run", __upgrade_reboot=reboot) is expected


def result(stdout, **variables):
    task = find("Report the result")
    t = templar(task, __upgrade_after={"stdout_lines": stdout.splitlines()}, **variables)
    return t.template(task["ansible.builtin.set_fact"]["upgrade_result"])


def test_the_result_lists_the_failed_units():
    stdout = SLE161 + "STATE=degraded\r\nFAILED=kdump.service loaded failed failed Load kdump kernel\r\n" + LOG
    assert result(stdout, __upgrade_snapshot={"stdout": "42\n"}, __upgrade_reboot={"rebooted": True}) == {
        "upgraded": True, "version_id": "16.1", "system_state": "degraded", "failed_units": ["kdump.service"],
        "migration_log": "/var/log/distro_migration.log", "rollback_snapshot": "42"}


def test_a_rerun_reports_without_an_upgrade():
    out = result(SLE161 + "STATE=running\r\n")
    assert out["upgraded"] is False
    assert out["version_id"] == "16.1"
    assert out["failed_units"] == []
    assert out["migration_log"] is None
    assert out["rollback_snapshot"] is None


def test_the_result_is_one_expression():
    # a mapping of templates turns none into "" before ansible-core 2.19 (measured on 2.18.3)
    assert isinstance(find("Report the result")["ansible.builtin.set_fact"]["upgrade_result"], str)


def test_the_version_comes_from_the_host():
    assert result(SP7 + "STATE=running\r\n")["version_id"] == "15.7"
