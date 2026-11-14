# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os

import pytest
import yaml

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

ROLES = os.path.join(os.path.dirname(__file__), "..", "..", "..", "roles")


def validate(params, role="analyse"):
    with open(os.path.join(ROLES, role, "meta", "argument_specs.yml")) as handle:
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


@pytest.mark.parametrize("opt_in", [[], ["repos_third_party", "multiversion_kernels", "ssh_root_login"]])
def test_remediate_opt_in_accepted(opt_in):
    assert validate({"remediate_opt_in": opt_in}, "remediate").error_messages == []


@pytest.mark.parametrize("fid", ["not_registered", "free_space_low", "removed_package:nscd"])
def test_remediate_opt_in_refuses_the_never_ids(fid):
    errors = validate({"remediate_opt_in": [fid]}, "remediate").error_messages
    assert len(errors) == 1
    assert "remediate_opt_in" in errors[0]
    assert fid in errors[0]
