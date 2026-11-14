# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os

import pytest
import yaml

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

SPECS = os.path.join(os.path.dirname(__file__), "..", "..", "..", "roles", "analyse", "meta", "argument_specs.yml")


def validate(params):
    with open(SPECS) as handle:
        options = yaml.safe_load(handle)["argument_specs"]["main"]["options"]
    spec = dict((name, dict((k, v) for k, v in option.items() if k != "description"))
                for name, option in options.items())
    return ArgumentSpecValidator(spec).validate(params)


@pytest.mark.parametrize("product", ["", "SLES", "SLES_SAP"])
def test_target_product_accepted(product):
    assert validate({"analyse_target_product": product}).error_messages == []


@pytest.mark.parametrize("product", ["SLED", "sles", "SLES/16.1/x86_64"])
def test_target_product_refused(product):
    errors = validate({"analyse_target_product": product}).error_messages
    assert len(errors) == 1
    assert "analyse_target_product" in errors[0]
    assert "SLES_SAP" in errors[0]
