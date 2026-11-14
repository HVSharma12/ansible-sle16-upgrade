# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os

import pytest

from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar

TASKS = os.path.join(os.path.dirname(__file__), "..", "..", "..", "roles", "remediate", "tasks", "main.yml")
GATE = "Stop unless the removal takes exactly the listed packages"

if not hasattr(Templar, "evaluate_conditional"):
    pytest.skip("needs ansible-core 2.19 or later", allow_module_level=True)

# zypper --non-interactive remove --dry-run under LC_ALL=C on SLES 15 SP7, without a terminal
ONE = "The following package is going to be REMOVED:\n  nscd\n\n1 package to remove.\n"
THREE = "The following 3 packages are going to be REMOVED:\n  python311-salt salt salt-minion\n\n3 packages to remove.\n"
CLEANDEPS = ("The following 34 packages are going to be REMOVED:\n  "
             + " ".join("pkg%d" % i for i in range(33)) + " salt-minion\n\n34 packages to remove.\n")
WRAPPED = "The following 3 packages are going to be REMOVED:\n  python311-salt salt\n  salt-minion\n\n"
APPLICATION = ("The following application is going to be REMOVED:\n  \"Salt\"\n\n" + THREE)


def gate():
    for task in DataLoader().load_from_file(TASKS, trusted_as_template=True):
        for sub in task.get("block") or []:
            if sub.get("name") == GATE:
                return sub
    raise AssertionError("no task named %r" % GATE)


def run(stdout, planned, listed=None):
    task = gate()
    variables = dict(task["vars"], __remediate_remove_dry={"stdout": stdout},
                     remediate_remove_packages=listed or planned,
                     remediate_plan={"changes": {"remove_packages": planned}})
    templar = Templar(loader=DataLoader(), variables=variables)
    return [templar.evaluate_conditional(that) for that in task["ansible.builtin.assert"]["that"]]


@pytest.mark.parametrize("stdout, planned, listed", [
    (ONE, ["nscd"], None),
    (THREE, ["salt", "salt-minion"], ["salt", "salt-minion", "python311-salt"]),
    (WRAPPED, ["salt", "salt-minion"], ["salt", "salt-minion", "python311-salt"]),
    (APPLICATION, ["salt", "salt-minion"], ["salt", "salt-minion", "python311-salt"]),
])
def test_a_removal_of_the_listed_packages_passes(stdout, planned, listed):
    assert run(stdout, planned, listed) == [True, True]


@pytest.mark.parametrize("stdout, planned", [(THREE, ["salt", "salt-minion"]), (CLEANDEPS, ["salt-minion"])])
def test_an_unlisted_package_stops_the_removal(stdout, planned):
    assert run(stdout, planned) == [False, True]


@pytest.mark.parametrize("stdout", ["", "Nothing to do.\n", ONE.replace("going to be REMOVED", "to be removed")])
def test_an_output_that_does_not_parse_stops_the_removal(stdout):
    assert run(stdout, ["nscd"]) == [True, False]
