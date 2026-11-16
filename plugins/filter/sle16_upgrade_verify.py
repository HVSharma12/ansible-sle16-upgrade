# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Harshvardhan Sharma <harshvardhan.sharma@suse.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: sle16_upgrade_verify
short_description: Compare a host after the upgrade with the facts analyse read before it
version_added: "0.1.0"
description:
  - Returns C(verdict) (C(pass), C(fail) or C(cannot_tell)), C(differences) (one entry per difference with
    C(id), C(item), C(before), C(after), C(fails) and C(reason)), C(counts) (differences per id), C(expected)
    (differences SLES 16 brings on every host, not counted), C(cannot_tell) (areas that could not be compared,
    each with C(area), C(fails) and C(reason)) and C(lines), one line per entry.
  - C(fail) when a difference fails, else C(cannot_tell) when an area that backs a failing id could not be read,
    else C(pass). An id fails when it is in C(fail_on).
  - The expected differences apply only from SLES 15 to SLES 16.
positional: baseline, settings
options:
  _input:
    description: The C(probe) result of C(sle16_upgrade_probe) on the host now.
    type: dict
    required: true
  baseline:
    description: The C(analyse_report) fact of the C(analyse) role from before the upgrade.
    type: dict
    required: true
  settings:
    description: C(target_version), C(fail_on) (difference ids that fail) and C(expected) (C(services), a mapping of
      a service to the one that replaces it or null; C(processes), whose ports may close).
    type: dict
    required: true
"""

EXAMPLES = r"""
result: "{{ probe | hvsharma12.sle16_upgrade.sle16_upgrade_verify(analyse_report, settings) }}"
"""

RETURN = r"""
_value:
  description: C(verdict), C(differences), C(counts), C(expected), C(cannot_tell) and C(lines).
  type: dict
"""

import ipaddress
import json
import re

# what each difference means for the operator
REASONS = {
    "not_target": "the upgrade did not reach the target",
    "not_registered": "the host gets no updates for the release it runs",
    "repo_old_release": "a repository of SLES 15 is still enabled on SLES 16",
    "migration_failed": "the migration log reports a failed step",
    "kernel_not_installed": "the running kernel belongs to no installed package; the host did not boot SLES 16",
    "service_stopped": "the host no longer provides this service",
    "unit_failed": "a unit failed that did not fail before",
    "mount_missing": "data or software on it is not reachable",
    "address_missing": "clients using this address cannot reach the host",
    "default_route_changed": "traffic leaves the host another way, or not at all",
    "port_closed": "clients of this port get no answer",
    "user_missing": "this account cannot log in or own files",
    "migration_boot_entry": "the next reboot may start the migration again",
    "service_disabled": "it will not start at the next boot",
    "mount_changed": "the file system type changed",
    "user_changed": "the account's home or shell changed",
    "group_missing": "its members lose the access the group gave",
    "group_members": "these members lose the access the group gave",
    "repo_missing": "packages from it are no longer updated",
    "selinux_mode": "the SELinux mode changed",
    "selinux_denials": "SELinux denied access since boot; a service may lack what it needs",
    "reboot_pending": "updates need a reboot to take effect",
    "kernel_cmdline": "the kernel runs without this parameter now",
    "system_state": "systemd does not report the system as running",
    "packages_old_release": "packages built for SLES 15 are still installed: not replaced, or left over",
}
FAIL_ON = ("not_target", "not_registered", "repo_old_release", "migration_failed", "kernel_not_installed",
           "service_stopped", "unit_failed", "mount_missing", "address_missing", "default_route_changed",
           "port_closed", "user_missing", "migration_boot_entry")
# the ids an area backs: an area that cannot be read fails when one of them does
AREAS = {
    "registration": ("not_registered",), "services_running": ("service_stopped",),
    "services_enabled": ("service_stopped", "service_disabled"), "failed_units": ("unit_failed",),
    "mounts": ("mount_missing", "mount_changed"), "addresses": ("address_missing",),
    "default_routes": ("default_route_changed",), "listening": ("port_closed",),
    "users": ("user_missing", "user_changed"), "groups": ("group_missing", "group_members"),
    "selinux_mode": ("selinux_mode",), "avc_denials": ("selinux_denials",), "reboot_pending": ("reboot_pending",),
    "migration_boot_entry": ("migration_boot_entry",), "migration_log_failures": ("migration_failed",),
    "kernel_installed": ("kernel_not_installed",), "system_state": ("system_state",),
    "packages": ("packages_old_release",),
}
SCOPES = ("loopback", "address", "any")
OLD_RELEASE = re.compile(r"(?<![0-9])15[-_]SP[0-9]+", re.I)


def mask(cmdline):
    return re.sub(r"(\S*pass\S*?=)\S*", r"\1****", cmdline or "", flags=re.I)


def network(address):
    try:
        return ipaddress.ip_interface(u"%s" % address).network
    except ValueError:
        return None


def sle16_upgrade_verify(probe, baseline, settings):
    fail_on = set(settings.get("fail_on", FAIL_ON))
    before_facts = (baseline or {}).get("facts") or {}
    before, after = before_facts.get("state") or {}, probe.get("state") or {}
    os_before, os_after = before_facts.get("os") or {}, probe.get("os") or {}
    version_before, version_after = os_before.get("version_id") or "", os_after.get("version_id") or ""
    target = settings["target_version"]
    on_target = os_after.get("id") == "sles" and version_after == target
    upgraded = os_before.get("id") == "sles" and version_before.startswith("15") and version_after.startswith("16")
    expected_conf = settings.get("expected") or {} if upgraded else {}
    replaced = expected_conf.get("services") or {}
    differences, expected, cannot = [], [], []

    def add(fid, item, was, now):
        differences.append({"id": fid, "item": item, "before": was, "after": now, "fails": fid in fail_on,
                            "reason": REASONS[fid]})

    def cannot_tell(area, reason="it could not be read"):
        cannot.append({"area": area, "fails": any(i in fail_on for i in AREAS.get(area, ())), "reason": reason})

    def both(area):
        if before.get(area) is None or after.get(area) is None:
            cannot_tell(area)
            return False
        return True

    if not on_target:
        add("not_target", "release", "%s %s" % (os_before.get("id"), version_before),
            "%s %s" % (os_after.get("id"), version_after))
    if os_before.get("id") != "sles" or not version_before.startswith("15"):
        cannot.append({"area": "baseline", "fails": True,
                       "reason": "it was read on %s %s, not on SLES 15 before the upgrade" % (
                           os_before.get("id"), version_before)})
    elif upgraded:
        expected.append("release %s -> %s" % (version_before, version_after))

    registration = probe.get("registration") or {}
    suse_repos = [r for r in probe.get("repos") or [] if r.get("enabled") and r.get("origin") == "suse"]
    if on_target:
        # a repository or service of the target, not one the migration left behind
        names_target = re.compile(r"(?<![0-9.])%s(?![0-9])" % re.escape(target))
        current = [r for r in suse_repos if names_target.search(r["alias"])] + [
            s for s in registration.get("services") or [] if s.get("enabled") and names_target.search(s.get("alias") or "")]
        for repo in suse_repos:
            if OLD_RELEASE.search(repo["alias"]):
                add("repo_old_release", repo["alias"], "-", "enabled")
    else:
        current = suse_repos
    if registration.get("credentials_file") is None:
        cannot_tell("registration")
    elif not registration["credentials_file"] or not current:
        add("not_registered", "registration", "registered", "no credentials" if not registration[
            "credentials_file"] else "no enabled SUSE repository or service for %s %s" % (
                os_after.get("id"), version_after))
    old_repos = dict((r["alias"], r) for r in before_facts.get("repos") or [] if r.get("enabled"))
    new_enabled = set(r["alias"] for r in probe.get("repos") or [] if r.get("enabled"))
    for alias in sorted(old_repos):
        if alias in new_enabled or (old_repos[alias].get("origin") == "suse" and upgraded):
            continue
        add("repo_missing", alias, "enabled", "missing or disabled")
    if upgraded:
        expected.append("SUSE repositories: %d enabled before, %d now" % (
            len([r for r in old_repos.values() if r.get("origin") == "suse"]), len(suse_repos)))

    if on_target:
        if after.get("migration_log_failures") is None:
            cannot_tell("migration_log_failures")
        elif after["migration_log_failures"]:
            add("migration_failed", "/var/log/distro_migration.log", "-",
                "%d 'failed with' line(s)" % after["migration_log_failures"])
        # the log can be moved aside; the packages cannot
        packages = probe.get("packages") or {}
        if "old_release" in packages and packages["old_release"] is None:
            cannot_tell("packages", "rpm -qa did not answer")
        else:
            kept = set(expected_conf.get("packages") or [])
            old = [p for p in packages.get("old_release") or [] if p not in kept]
            if old:
                add("packages_old_release", "packages", "-", "%d with a SLES 15 release: %s%s" % (
                    len(old), ", ".join(old[:10]), ", ..." if len(old) > 10 else ""))
            if kept & set(packages.get("old_release") or []):
                expected.append("kept from SLES 15: %s" % ", ".join(sorted(kept & set(packages["old_release"]))))
    if after.get("kernel_installed") is None:
        cannot_tell("kernel_installed")
    elif not after["kernel_installed"]:
        add("kernel_not_installed", (probe.get("kernels") or {}).get("running"), "-", "no package")

    running = set(after.get("services_running") or [])
    enabled_before = set(before.get("services_enabled") or [])
    gone = set()
    if all([both("services_running"), both("services_enabled")]):
        # what the host starts at boot; a service started by hand or on demand (D-Bus, a socket) is not judged
        gone |= set(u for u in before["services_running"]
                    if u in enabled_before or re.sub(r"@[^.]*\.", "@.", u) in enabled_before) - running
        gone |= enabled_before - set(after["services_enabled"])
    for unit in sorted(gone):
        successor = replaced.get(unit)
        if unit in replaced and (successor is None or successor in running):
            expected.append("%s -> %s" % (unit, successor or "not used on SLES 16"))
        elif unit in before["services_running"] and unit not in running:
            add("service_stopped", unit, "running", "not running")
        else:
            add("service_disabled", unit, "enabled", "not enabled")
    if both("failed_units"):
        for unit in sorted(set(after["failed_units"]) - set(before["failed_units"])):
            add("unit_failed", unit, "not failed", "failed")
    if after.get("system_state") is None:
        cannot_tell("system_state")
    elif after["system_state"] != "running":
        add("system_state", "systemd", before.get("system_state"), after["system_state"])

    if both("mounts"):
        for mount in sorted(before["mounts"]):
            if mount not in after["mounts"]:
                add("mount_missing", mount, before["mounts"][mount], "not mounted")
            elif after["mounts"][mount] != before["mounts"][mount]:
                add("mount_changed", mount, before["mounts"][mount], after["mounts"][mount])

    if both("addresses"):
        now = set(a["address"] for a in after["addresses"])
        networks = set(network(a["address"]) for a in after["addresses"] if a.get("family") == "inet6")
        for addr in before["addresses"]:
            if addr["address"] in now:
                continue
            if addr.get("family") == "inet6" and addr.get("dynamic") and network(addr["address"]) in networks:
                # SLAAC: NetworkManager forms the address in the same prefix another way
                expected.append("%s -> another address in %s" % (addr["address"], network(addr["address"])))
                continue
            add("address_missing", addr["address"], addr["dev"], "not configured")
    if both("default_routes"):
        now = set((r["family"], r["gateway"]) for r in after["default_routes"])
        for route in before["default_routes"]:
            if (route["family"], route["gateway"]) not in now:
                add("default_route_changed", "default via %s" % route["gateway"], route["dev"],
                    ", ".join("via %s dev %s" % (r["gateway"], r["dev"]) for r in after["default_routes"]
                              if r["family"] == route["family"]) or "none")
    if both("listening"):
        closing = set(expected_conf.get("processes") or [])
        low, high = after.get("ephemeral_ports") or before.get("ephemeral_ports") or (32768, 60999)
        # ports a process opened in the ephemeral range since the baseline; each one excuses one it lost there
        moved = {}
        for port, entry in after["listening"].items():
            proto, number = port.split("/")
            for p in entry["processes"]:
                if low <= int(number) <= high and p not in (before["listening"].get(port) or {}).get("processes", []):
                    moved[(proto, p)] = moved.get((proto, p), 0) + 1
        for port, was in sorted(before["listening"].items()):
            owners, now = was["processes"], after["listening"].get(port)
            proto, number = port.split("/")
            label = "%s on %s" % (", ".join(owners) or "listening", was["scope"])
            if now is None and owners and set(owners) <= closing:
                expected.append("%s (%s) closed" % (port, ", ".join(owners)))
            elif now is None and owners and low <= int(number) <= high and all(moved.get((proto, p)) for p in owners):
                for p in owners:
                    moved[(proto, p)] -= 1
                expected.append("%s (%s): a port from the ephemeral range; the process moved to another" % (
                    port, ", ".join(owners)))
            elif now is None:
                add("port_closed", port, label, "not listening")
            elif was["scope"] != "loopback" and now["scope"] == "loopback":
                add("port_closed", port, label, "loopback only")

    if both("users"):
        for name, user in sorted(before["users"].items()):
            if name not in after["users"]:
                add("user_missing", name, "uid %s" % user["uid"], "missing")
            elif after["users"][name] != user:
                add("user_changed", name, user, after["users"][name])
    if both("groups"):
        for name, members in sorted(before["groups"].items()):
            if name not in after["groups"]:
                add("group_missing", name, ",".join(members), "missing")
            elif set(members) - set(after["groups"][name]):
                add("group_members", name, ",".join(sorted(set(members) - set(after["groups"][name]))), "removed")

    if both("selinux_mode"):
        mode_before, mode_after = before["selinux_mode"], after["selinux_mode"]
        if upgraded and mode_before == "disabled" and mode_after == "enforcing":
            expected.append("%s -> SELinux enforcing" % (
                "AppArmor" if (before_facts.get("lsm") or {}).get("apparmor_enabled") else "no LSM"))
        elif mode_before != mode_after:
            add("selinux_mode", "SELinux", mode_before, mode_after)
    if after.get("avc_denials") is None:
        cannot_tell("avc_denials")
    elif after["avc_denials"]:
        add("selinux_denials", "AVC denials since boot", "-", after["avc_denials"])

    reboot = (probe.get("updates") or {}).get("needs_reboot")
    if reboot is None:
        cannot_tell("reboot_pending", "zypper needs-rebooting did not answer")
    elif reboot:
        add("reboot_pending", "zypper needs-rebooting", "-", "reboot needed")
    # the boot the host came up with, without the kernel image the upgrade replaces
    params = [mask((facts.get("boot") or {}).get("cmdline")).split() for facts in (before_facts, probe)]
    params = [sorted(p for p in each if not p.startswith("BOOT_IMAGE=")) for each in params]
    for param in sorted(set(params[0]) - set(params[1])):
        add("kernel_cmdline", param, "set", "not set")
    if after.get("migration_boot_entry") is None:
        cannot_tell("migration_boot_entry", "/boot/grub2/grub.cfg could not be read")
    elif after["migration_boot_entry"]:
        add("migration_boot_entry", "/boot/grub2/grub.cfg", "-", "migration entry present")
    if upgraded:
        expected.append("kernel %s -> %s" % ((before_facts.get("kernels") or {}).get("running"),
                                             (probe.get("kernels") or {}).get("running")))

    counts = {}
    for diff in differences:
        counts[diff["id"]] = counts.get(diff["id"], 0) + 1
    verdict = ("fail" if any(d["fails"] for d in differences)
               else "cannot_tell" if any(c["fails"] for c in cannot) else "pass")
    lines = ["%s %s: %s -> %s; %s%s" % (d["id"], d["item"], d["before"], d["after"], d["reason"],
                                        " (fails)" if d["fails"] else "") for d in differences]
    lines += ["cannot tell: %s: %s%s" % (c["area"], c["reason"], " (fails)" if c["fails"] else "") for c in cannot]
    lines += ["expected: %s" % e for e in expected]
    return {"verdict": verdict, "differences": differences, "counts": counts, "expected": expected,
            "cannot_tell": cannot, "lines": lines}


def sle16_upgrade_is_baseline(text, version_id):
    """True when text is an analyse report read on SLES 15 and the host now runs another release."""
    try:
        old = json.loads(text or "")
    except ValueError:
        return False
    os_old = ((old.get("facts") or {}).get("os") or {}) if isinstance(old, dict) else {}
    return (os_old.get("id") == "sles" and str(os_old.get("version_id") or "").startswith("15.")
            and not str(version_id or "").startswith("15."))


class FilterModule(object):
    def filters(self):
        return {"sle16_upgrade_verify": sle16_upgrade_verify, "sle16_upgrade_is_baseline": sle16_upgrade_is_baseline}
