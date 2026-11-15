# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import sys

import pytest
import yaml

from test_argument_specs import ROLES, validate

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "plugins", "filter"))
import sle16_upgrade_verify as verifier  # noqa: E402  pylint: disable=wrong-import-position


def test_fail_on_choices_are_the_filter_ids():
    with open(os.path.join(ROLES, "verify", "meta", "argument_specs.yml")) as handle:
        option = yaml.safe_load(handle)["argument_specs"]["main"]["options"]["verify_fail_on"]
    assert sorted(option["choices"]) == sorted(verifier.REASONS)
    assert option["default"] == list(verifier.FAIL_ON)


def test_defaults_match_the_spec():
    with open(os.path.join(ROLES, "verify", "defaults", "main.yml")) as handle:
        defaults = yaml.safe_load(handle)
    assert defaults["verify_fail_on"] == list(verifier.FAIL_ON)
    assert validate(defaults, "verify").error_messages == []


@pytest.mark.parametrize("fail_on", [["services_stopped"], ["all"], ["NOT_TARGET"]])
def test_fail_on_refuses_unknown_ids(fail_on):
    errors = validate({"verify_fail_on": fail_on}, "verify").error_messages
    assert len(errors) == 1
    assert "verify_fail_on" in errors[0]
