# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import importlib.util
import json
import os
import subprocess
import sys
import textwrap

import pytest

MODULES = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "plugins", "modules")


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(MODULES, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load("sle16_upgrade_probe")
dms = load("sle16_upgrade_dms_prechecks")


@pytest.mark.parametrize("url,expected", [
    ("https://updates.suse.com/SUSE/Products/SLE-Product-SLES/15-SP7/x86_64/product?abcTOKENdef",
     "https://updates.suse.com/SUSE/Products/SLE-Product-SLES/15-SP7/x86_64/product"),
    ("https://user:secret@rmt.example.com/repo/x?credentials=SCC", "https://rmt.example.com/repo/x"),
    ("dvd:/?devices=/dev/sr0", "dvd:/"),
    ("", ""),
    (None, None),
])
def test_clean_url_drops_tokens_and_userinfo(url, expected):
    assert probe.clean_url(url) == expected


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text))
    return str(path)


def test_repo_origins(tmp_path, monkeypatch):
    files = [
        write(tmp_path / "a.repo", """
            [SUSE_SLES:SLE-Product-SLES15-SP7-Pool]
            name=SLE-Product-SLES15-SP7-Pool
            enabled=1
            baseurl=https://updates.suse.com/SUSE/Products/x?TOKEN
            service=SUSE_SLES
            """),
        write(tmp_path / "b.repo", """
            [obs]
            name=obs
            enabled=1
            baseurl=https://download.opensuse.org/repositories/x/
            """),
        write(tmp_path / "c.repo", """
            [dvd]
            enabled=0
            baseurl=dvd:/?devices=/dev/sr0
            """),
        write(tmp_path / "d.repo", """
            [rmt-repo]
            baseurl=https://rmt.example.com/repo/SUSE/x
            """),
        write(tmp_path / "e.repo", """
            [susemanager:channels]
            baseurl=plugin:/spacewalk
            """),
    ]
    monkeypatch.setattr(probe.glob, "glob", lambda pattern: files)
    result = probe.Probe(None).repos({"rmt.example.com"})
    origins = dict((r["alias"], (r["origin"], r["enabled"])) for r in result)
    assert origins == {
        "SUSE_SLES:SLE-Product-SLES15-SP7-Pool": ("suse", True),
        "obs": ("third_party", True),
        "dvd": ("local", False),
        "rmt-repo": ("suse", True),
        "susemanager:channels": ("suse_manager", True),
    }
    assert all("TOKEN" not in r["url"] and "?" not in r["url"] for r in result)


def test_interpreter_from_shebang(tmp_path):
    assert dms.interpreter(write(tmp_path / "a", "#!/usr/bin/python3.6\nx\n")) == "/usr/bin/python3.6"
    assert dms.interpreter(write(tmp_path / "b", "#!/usr/bin/env python3\n")) == "python3"
    assert dms.interpreter(write(tmp_path / "c", "no shebang\n")) is None
    assert dms.interpreter(str(tmp_path / "missing")) is None


FAKE_PRECHECKS = """
    import logging, os
    from suse_migration_services.migration_target import MigrationTarget

    class Logger:
        @staticmethod
        def setup(system_root=True):
            logging.getLogger("suse-migration").addHandler(logging.FileHandler(os.environ["FAKE_LOG"]))

    def main():
        Logger.setup()
        log = logging.getLogger("suse-migration")
        log.info("Running suse-migration-pre-checks with options: fix: False")
        log.info("Checking harmful migration conditions")
        log.info("--> Checking sshd configuration...")
        if MigrationTarget.get_migration_target()["version"].startswith("16"):
            log.warning("Root login by ssh will be disabled by default in SLE16.")
        log.info("Done")
        log.info("--> Checking upgrade path against registration server...")
        log.error("No migration available")
        log.info("Done")
        print("stray output of a subprocess")
"""

FAKE_TARGET = """
    import logging

    class MigrationTarget:
        @staticmethod
        def get_migration_target():
            logging.getLogger("suse-migration").warning("Migration target cannot be detected, fallback to SLES 15.7")
            return {"identifier": "SLES", "version": "%s", "arch": "x86_64"}
"""


def fake_dms(tmp_path, image_version):
    root = tmp_path / "site"
    write(root / "suse_migration_services" / "__init__.py", "")
    write(root / "suse_migration_services" / "defaults.py", """
        class Defaults:
            @staticmethod
            def get_migration_log_name():
                return "suse-migration"
    """)
    write(root / "suse_migration_services" / "migration_target.py", FAKE_TARGET % image_version)
    write(root / "suse_migration_services" / "prechecks" / "__init__.py", "")
    write(root / "suse_migration_services" / "prechecks" / "pre_checks.py", FAKE_PRECHECKS)
    return root


def run_helper(tmp_path, image_version):
    root = fake_dms(tmp_path, image_version)
    log = tmp_path / "distro_migration.log"
    env = dict(os.environ, PYTHONPATH=str(root), SLE16_UPGRADE_TARGET="SLES/16.1/x86_64", FAKE_LOG=str(log))
    out = subprocess.run([sys.executable, "-"], input=dms.HELPER, env=env, capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1]), log


def test_helper_keeps_levels_and_checks_and_writes_no_log(tmp_path):
    payload, log = run_helper(tmp_path, "15.7")
    assert payload["records"] == [
        {"check": "sshd configuration", "level": "WARNING", "message": "Root login by ssh will be disabled by default in SLE16."},
        {"check": "upgrade path against registration server", "level": "ERROR", "message": "No migration available"},
    ]
    assert payload["target"] == {"product": "SLES/16.1/x86_64", "source": "module"}
    assert payload["error"] is None
    assert not log.exists()


def test_helper_keeps_a_sle16_target_from_dms(tmp_path):
    payload, dummy = run_helper(tmp_path, "16.0")
    assert payload["target"] == {"product": "SLES/16.0/x86_64", "source": "dms"}


class FakeStat(object):
    f_bavail = 1024
    f_frsize = 1024 * 1024


@pytest.mark.parametrize("lines,separate", [
    (["/dev/vda2 / btrfs rw 0 0", "/dev/vda2 /var btrfs rw,subvol=/@/var 0 0", "/dev/vda1 /boot/efi vfat rw 0 0"], []),
    (["/dev/mapper/system-root / xfs rw 0 0", "/dev/mapper/system-var /var xfs rw 0 0"], ["/var"]),
    (["/dev/vda3 / xfs rw 0 0", "/dev/vda3 /var xfs rw 0 0", "/dev/loop0 /var xfs rw 0 0"], ["/var"]),
    (["/dev/vda3 / xfs rw 0 0", "/dev/vda2 /boot ext4 rw 0 0", "tmpfs /tmp tmpfs rw 0 0"], ["/boot"]),
])
def test_separate_os_mounts(monkeypatch, lines, separate):
    monkeypatch.setattr(probe, "read_text", lambda path: "\n".join(lines) if path == "/proc/self/mounts" else None)
    monkeypatch.setattr(probe.os, "statvfs", lambda path: FakeStat())
    check = probe.Probe(None)
    monkeypatch.setattr(check, "run", lambda args, env=None: (0, "meta-data=/dev/vda3 crc=1", ""))
    data = check.storage()
    assert data["separate"] == separate
    assert data["free_mb"]["/"] == 1024
    assert "/tmp" not in data["mounts"]
