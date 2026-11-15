# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

from test_modules import probe

IP_ADDR = [
    {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
    {"ifname": "eth0", "addr_info": [
        {"family": "inet", "local": "192.0.2.15", "prefixlen": 24, "scope": "global", "dynamic": True},
        {"family": "inet6", "local": "2001:db8::1c2d:3e4f:5a6b:7c8d", "prefixlen": 64, "scope": "global",
         "temporary": True, "dynamic": True},
        {"family": "inet6", "local": "2001:db8::5054:ff:fe12:3456", "prefixlen": 64, "scope": "global",
         "dynamic": True, "mngtmpaddr": True},
        {"family": "inet6", "local": "fe80::5054:ff:fe12:3456", "prefixlen": 64, "scope": "link"}]},
]

SS = """tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=900,fd=3))
tcp   LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=900,fd=4))
udp   UNCONN 0      0          127.0.0.1:323       0.0.0.0:*    users:(("chronyd",pid=800,fd=5))
udp   UNCONN 0      0              [::1]:323          [::]:*    users:(("chronyd",pid=800,fd=6))
udp   UNCONN 0      0       0.0.0.0%eth0:68        0.0.0.0:*    users:(("wickedd-dhcp4",pid=700,fd=7))
tcp   LISTEN 0      5         192.0.2.15:8080          *:*
tcp   LISTEN 0      5          127.0.0.1:631     0.0.0.0:*    users:(("cupsd",pid=600,fd=7))
tcp   LISTEN 0      5               [::]:631        [::]:*    users:(("cupsd",pid=600,fd=8))
"""

PASSWD = """root:x:0:0:root:/root:/bin/bash
messagebus:x:499:499:User for D-Bus:/run/dbus:/usr/sbin/nologin
alice:x:1000:100::/home/alice:/bin/bash
nobody:x:65534:65534:nobody:/var/lib/nobody:/bin/bash
"""

GROUP = """root:x:0:
wheel:x:497:alice
ops:x:1001:alice,bob
nogroup:x:65534:
"""


def test_global_addresses_skip_host_link_scope_and_privacy_addresses():
    assert probe.global_addresses(IP_ADDR) == [
        {"dev": "eth0", "address": "192.0.2.15/24", "family": "inet", "dynamic": True},
        {"dev": "eth0", "address": "2001:db8::5054:ff:fe12:3456/64", "family": "inet6", "dynamic": True}]


def test_default_routes():
    routes = [{"dst": "default", "gateway": "192.0.2.2", "dev": "eth0", "protocol": "dhcp"}]
    assert probe.default_routes(routes, "inet") == [{"family": "inet", "gateway": "192.0.2.2", "dev": "eth0"}]


def test_listening_ports_with_processes_and_the_widest_address():
    assert probe.listening(SS) == {
        "tcp/22": {"processes": ["sshd"], "scope": "any"},
        "udp/323": {"processes": ["chronyd"], "scope": "loopback"},
        "udp/68": {"processes": ["wickedd-dhcp4"], "scope": "any"},
        "tcp/8080": {"processes": [], "scope": "address"},
        "tcp/631": {"processes": ["cupsd"], "scope": "any"}}


def test_kernel_parameters_named_like_a_password_are_masked():
    assert probe.mask_cmdline("root=/dev/vda3 rd.iscsi.password=s3cret PASSWD=x quiet") == (
        "root=/dev/vda3 rd.iscsi.password=**** PASSWD=**** quiet")


def test_local_accounts_keep_root_and_people():
    users, groups = probe.local_accounts(PASSWD, GROUP)
    assert sorted(users) == ["alice", "root"]
    assert users["alice"] == {"uid": 1000, "home": "/home/alice", "shell": "/bin/bash"}
    assert groups == {"root": [], "ops": ["alice", "bob"]}


def fake_host(monkeypatch, files, answers):
    def run(args, env=None):
        if args[0] == "ip" and "route" in args:
            return 0, json.dumps([{"dst": "default", "gateway": "192.0.2.2", "dev": "eth0"}] if "-4" in args else []), ""
        for key, answer in answers.items():
            if key in args:
                return answer
        raise AssertionError(args)

    monkeypatch.setattr(probe, "read_text", files.get)
    monkeypatch.setattr(probe.os.path, "lexists", lambda path: path in files)
    check = probe.Probe(None)
    monkeypatch.setattr(check, "run", run)
    return check.state()


ANSWERS = {
    "list-unit-files": (0, "sshd.service enabled enabled\nlegacy-app.service generated -\n", ""),
    "--state=running": (0, "sshd.service loaded active running OpenSSH Daemon\n", ""),
    "--state=failed": (0, "", ""),
    "is-system-running": (0, "running\n", ""),
    "address": (0, json.dumps(IP_ADDR), ""),
    "-Htlnup": (0, SS, ""),
    "--input-logs": (0, "type=AVC msg=audit(1.1:2): avc:  denied  { read } for pid=1\n"
                        "type=AVC msg=audit(1.1:3): avc:  granted  { setenforce } for pid=2\n", ""),
    "-qf": (0, "kernel-default-base-6.12.0-160100.9.1\n", ""),
}


def test_state_reads_each_area(monkeypatch):
    files = {"/proc/self/mounts": "/dev/vda3 / xfs rw 0 0\nhost:/srv /srv nfs4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n",
             "/etc/passwd": PASSWD, "/etc/group": GROUP, "/boot/grub2/grub.cfg": "menuentry 'SLES 15-SP7' {\n}\n",
             "/sys/fs/selinux/enforce": "1", "/proc/sys/net/ipv4/ip_local_port_range": "32768\t60999\n",
             "/var/log/distro_migration.log": "zypper dup failed with exit code 8\nstep done\n"}
    data = fake_host(monkeypatch, files, ANSWERS)
    # list-unit-files is asked for every state a unit is started from at boot, init scripts included
    assert data["services_enabled"] == ["legacy-app.service", "sshd.service"]
    assert data["services_running"] == ["sshd.service"]
    assert data["failed_units"] == []
    assert data["system_state"] == "running"
    assert data["mounts"] == {"/": "xfs", "/srv": "nfs4"}
    assert data["default_routes"] == [{"family": "inet", "gateway": "192.0.2.2", "dev": "eth0"}]
    assert data["listening"]["tcp/22"] == {"processes": ["sshd"], "scope": "any"}
    assert data["ephemeral_ports"] == [32768, 60999]
    assert sorted(data["users"]) == ["alice", "root"]
    assert data["selinux_mode"] == "enforcing"
    assert data["avc_denials"] == 1
    assert data["migration_boot_entry"] is False
    assert data["migration_log_failures"] == 1
    assert data["kernel_installed"] is True


def test_absent_files_are_facts_not_gaps(monkeypatch):
    files = {"/proc/self/mounts": "/dev/vda3 / xfs rw 0 0\n", "/etc/passwd": PASSWD, "/etc/group": GROUP}
    data = fake_host(monkeypatch, files, dict(ANSWERS, **{"-qf": (1, "file is not owned by any package", "")}))
    assert data["selinux_mode"] == "disabled"
    assert data["migration_boot_entry"] is False
    assert data["migration_log_failures"] == 0
    assert data["kernel_installed"] is False


def test_state_marks_what_it_cannot_read(monkeypatch):
    # every file exists and none can be read, every command fails: as a user without root
    monkeypatch.setattr(probe, "read_text", lambda path: None)
    monkeypatch.setattr(probe.os.path, "lexists", lambda path: True)
    check = probe.Probe(None)
    monkeypatch.setattr(check, "run", lambda args, env=None: (None, "", ""))
    data = check.state()
    for area in ("services_enabled", "services_running", "failed_units", "system_state", "addresses",
                 "default_routes", "listening", "ephemeral_ports", "users", "groups", "selinux_mode", "avc_denials",
                 "migration_boot_entry", "migration_log_failures", "kernel_installed"):
        assert data[area] is None, area
