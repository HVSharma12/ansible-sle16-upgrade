#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Harshvardhan Sharma <harshvardhan.sharma@suse.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: sle16_upgrade_dms_prechecks
short_description: Run the Distribution Migration System pre-checks and return their messages with log levels
version_added: "0.1.0"
description:
  - Runs the checks of C(suse-migration-pre-checks) (package C(suse-migration-pre-checks)) without C(--fix), in the
    package's own Python interpreter, and returns every message with the check that wrote it and its log level.
  - The command line tool prints text and exits 0 whatever it finds; this module keeps the levels the tool logs
    with (C(ERROR), C(WARNING), C(INFO)) instead of parsing the text.
  - The tool's log file C(/var/log/distro_migration.log) is not written.
  - When no migration image is installed and C(/etc/sle-migration-service.yml) names no product, the tool falls back
    to a SLES 15 target and skips the SLE 16 checks. The module then sets I(target) as the migration target, as
    the C(migration_product) setting of the tool would.
  - Returns C(installed=false) and runs nothing when the package is not installed.
options:
  target:
    description: Migration target as C(PRODUCT/VERSION/ARCH), for example C(SLES/16.1/x86_64).
    type: str
    required: true
author:
  - Harshvardhan Sharma (@HVSharma12)
attributes:
  check_mode:
    description: Runs the same read-only queries in check mode.
    support: full
  diff_mode:
    description: Returns no diff.
    support: none
"""

EXAMPLES = r"""
- name: Run the DMS pre-checks against SLES 16.1
  hvsharma12.sle16_upgrade.sle16_upgrade_dms_prechecks:
    target: SLES/16.1/x86_64
  register: dms
"""

RETURN = r"""
installed:
  description: Whether C(suse-migration-pre-checks) is installed.
  returned: always
  type: bool
version:
  description: Version of the installed C(suse-migration-pre-checks) package.
  returned: when installed
  type: str
target:
  description: The target the checks ran against and where it came from (C(dms) or C(module)).
  returned: when installed
  type: dict
records:
  description: One entry per message, in order, with C(check), C(level) and C(message).
  returned: when installed
  type: list
  elements: dict
error:
  description: Why the checks could not run to the end, if they could not.
  returned: when installed
  type: str
"""

import json
import os

from ansible.module_utils.basic import AnsibleModule

PRECHECKS = "/usr/bin/suse-migration-pre-checks"

# Runs inside the DMS interpreter. Logger.setup would add the log file handler; it is replaced so that the run
# leaves no trace on the host. Messages are attributed to the check announced by the last "--> Checking" line.
HELPER = r'''
import json, logging, os, sys
from suse_migration_services.defaults import Defaults
from suse_migration_services.migration_target import MigrationTarget
from suse_migration_services.prechecks import pre_checks

records = []
state = {"check": "setup"}

class Collect(logging.Handler):
    def emit(self, record):
        message = record.getMessage()
        if message.startswith("--> Checking"):
            state["check"] = message[len("--> Checking"):].strip(" .")
            return
        if message.strip() in ("Done", "Checking harmful migration conditions") or message.startswith("Running suse-migration-pre-checks"):
            return
        records.append({"check": state["check"], "level": record.levelname, "message": message.strip()})

pre_checks.Logger.setup = staticmethod(lambda *a, **k: None)
log = logging.getLogger(Defaults.get_migration_log_name())
log.setLevel(logging.INFO)
log.propagate = False
log.handlers = [Collect()]

original = MigrationTarget.get_migration_target
wanted = os.environ["SLE16_UPGRADE_TARGET"].split("/")
source = {"value": "dms"}

def target():
    found = original()
    if found.get("version", "").startswith("16"):
        return found
    source["value"] = "module"
    return {"identifier": wanted[0], "version": wanted[1], "arch": wanted[2]}

def quiet_target():
    level = log.level
    log.setLevel(logging.ERROR)
    try:
        return target()
    finally:
        log.setLevel(level)

MigrationTarget.get_migration_target = staticmethod(quiet_target)
sys.argv = ["suse-migration-pre-checks"]
error = None
try:
    pre_checks.main()
except Exception as issue:
    error = "%s: %s" % (type(issue).__name__, issue)
used = quiet_target()
print(json.dumps({"records": records, "error": error,
                  "target": {"product": "%s/%s/%s" % (used["identifier"], used["version"], used["arch"]),
                             "source": source["value"]}}))
'''


def interpreter(path):
    """The interpreter of the tool's own script, where its Python package is installed."""
    try:
        with open(path) as handle:
            first = handle.readline().strip()
    except (IOError, OSError):
        return None
    if not first.startswith("#!"):
        return None
    parts = first[2:].split()
    if parts and os.path.basename(parts[0]) == "env" and len(parts) > 1:
        return parts[1]
    return parts[0] if parts else None


def main():
    module = AnsibleModule(argument_spec=dict(target=dict(type="str", required=True)), supports_check_mode=True)
    target = module.params["target"]
    if len(target.split("/")) != 3:
        module.fail_json(msg="target must be PRODUCT/VERSION/ARCH, got %s" % target)
    if not os.path.exists(PRECHECKS):
        module.exit_json(changed=False, installed=False)

    rc, out, err = module.run_command(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "suse-migration-pre-checks"])
    version = out.strip() if rc == 0 else None
    python = interpreter(PRECHECKS)
    if not python:
        module.exit_json(changed=False, installed=True, version=version, records=[], target={},
                         error="cannot read the interpreter of %s" % PRECHECKS)
    rc, out, err = module.run_command([python, "-"], data=HELPER, binary_data=False,
                                      environ_update={"SLE16_UPGRADE_TARGET": target}, check_rc=False)
    try:
        payload = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        module.exit_json(changed=False, installed=True, version=version, records=[], target={},
                         error="pre-checks did not run (rc %s): %s" % (rc, (err or out).strip()[-500:]))
    module.exit_json(changed=False, installed=True, version=version, records=payload["records"],
                     target=payload["target"], error=payload["error"])


if __name__ == "__main__":
    main()
