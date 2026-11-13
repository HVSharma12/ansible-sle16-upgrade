#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Harshvardhan Sharma <harshvardhan.sharma@suse.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: sle16_upgrade_probe
short_description: Read the facts a SLES 15 to SLES 16 upgrade depends on
version_added: "0.1.0"
description:
  - Reads files and runs read-only queries (C(rpm), C(zypper --no-refresh), C(sshd -T), C(lsblk), C(xfs_info))
    and returns the raw facts. It changes nothing on the host.
  - Repository and service URLs are returned without user information and query string, which carry
    access tokens on registered hosts. Registration is read from file presence only; no credential
    file and no C(SUSEConnect --status) output is read.
options:
  removed_packages:
    description: Package names to look for; the installed ones are returned in C(packages.removed_installed).
    type: list
    elements: str
    default: []
  check_patches:
    description: Count needed patches with C(zypper --no-refresh list-patches) (local metadata, no refresh).
    type: bool
    default: true
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
- name: Read the upgrade facts
  hvsharma12.sle16_upgrade.sle16_upgrade_probe:
    removed_packages: [salt-minion, xen]
  register: probe
"""

RETURN = r"""
probe:
  description: The facts, one key per area (os, products, cpu, registration, repos, storage, boot, kernels,
    packages, network, ssh, lsm, cgroup, updates, virt, management, dms).
  returned: always
  type: dict
"""

import configparser
import glob
import os
import platform
import re
import sys
import xml.etree.ElementTree as ET

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import urlsplit, urlunsplit

SUSE_HOSTS = ("scc.suse.com", "updates.suse.com", "download.suse.com", "installer-updates.suse.com")
DMS_PACKAGES = ("suse-migration-pre-checks", "suse-migration-sle16-activation", "SLES16-Migration",
                "SLES16-SAP_Migration", "wicked2nm")


def clean_url(url):
    """Drop userinfo and query: SCC repository URLs carry access tokens there."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.split("?", 1)[0]
    netloc = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def url_host(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def read_text(path):
    try:
        with open(path) as handle:
            return handle.read()
    except (IOError, OSError, UnicodeDecodeError):
        return None


def read_ini(path):
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    try:
        parser.read(path)
    except (configparser.Error, UnicodeDecodeError):
        return {}
    return dict((section, dict(parser.items(section))) for section in parser.sections())


def as_bool(value, default=True):
    if value is None:
        return default
    return str(value).strip() in ("1", "yes", "true", "on")


class Probe(object):
    def __init__(self, module):
        self.module = module
        self.errors = []

    def run(self, args, env=None):
        """Run a read-only query; never raises, a missing tool gives rc None."""
        if not os.path.isabs(args[0]):
            exe = self.module.get_bin_path(args[0])
            if not exe:
                return None, "", ""
            args = [exe] + list(args[1:])
        elif not os.path.exists(args[0]):
            return None, "", ""
        rc, out, err = self.module.run_command(args, environ_update=env or {}, check_rc=False)
        return rc, out, err

    def os_release(self):
        data = {}
        for line in (read_text("/etc/os-release") or "").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"')
        return {"id": data.get("ID"), "version_id": data.get("VERSION_ID"), "name": data.get("NAME"),
                "pretty_name": data.get("PRETTY_NAME"), "transactional": os.path.exists("/usr/sbin/transactional-update")}

    def products(self):
        base = os.path.realpath("/etc/products.d/baseproduct") if os.path.lexists("/etc/products.d/baseproduct") else None
        result = []
        for path in sorted(glob.glob("/etc/products.d/*.prod")):
            try:
                tree = ET.parse(path)
            except (ET.ParseError, IOError, OSError):
                continue

            def text(tag, root=tree.getroot()):
                node = root.find(tag)
                return node.text.strip() if node is not None and node.text else None
            result.append({"name": text("name"), "version": text("version"), "arch": text("arch"),
                           "summary": text("summary"), "base": os.path.realpath(path) == base})
        return result

    def cpu(self):
        machine = platform.machine()
        data = {"machine": machine, "level": None, "power_generation": None}
        if machine == "x86_64":
            rc, out, dummy = self.run(["zypper", "--non-interactive", "system-architecture"], env={"ZYPP_READONLY_HACK": "1"})
            if rc == 0:
                data["level"] = out.strip().lower()
        elif machine in ("ppc64", "ppc64le"):
            match = re.search(r"POWER(\d+)", read_text("/proc/cpuinfo") or "")
            data["power_generation"] = int(match.group(1)) if match else None
        return data

    def registration(self):
        services = []
        for path in sorted(glob.glob("/etc/zypp/services.d/*.service")):
            for alias, opts in read_ini(path).items():
                services.append({"alias": alias, "url": clean_url(opts.get("url")),
                                 "host": url_host(opts.get("url", "")), "enabled": as_bool(opts.get("enabled"))})
        server = None
        for line in (read_text("/etc/SUSEConnect") or "").splitlines():
            if line.strip().startswith("url:"):
                server = clean_url(line.split(":", 1)[1].strip().strip("'\""))
        return {"credentials_file": os.path.isfile("/etc/zypp/credentials.d/SCCcredentials"),
                "server": server or "https://scc.suse.com", "server_configured": server is not None,
                "services": services}

    def repos(self, service_hosts):
        result = []
        for path in sorted(glob.glob("/etc/zypp/repos.d/*.repo")):
            for alias, opts in read_ini(path).items():
                raw = opts.get("baseurl") or opts.get("mirrorlist") or ""
                scheme = raw.split(":", 1)[0].lower() if ":" in raw else ""
                host = url_host(raw)
                if alias.startswith("susemanager:"):
                    origin = "suse_manager"
                elif opts.get("service") or host in SUSE_HOSTS or (host and host in service_hosts):
                    origin = "suse"
                elif scheme in ("http", "https", "ftp") or raw.startswith("plugin:/susecloud"):
                    origin = "third_party"
                else:
                    origin = "local"
                result.append({"alias": alias, "name": opts.get("name", alias), "enabled": as_bool(opts.get("enabled")),
                               "url": clean_url(raw), "service": opts.get("service"), "origin": origin})
        return result

    def mounts(self):
        mounts = {}
        for line in (read_text("/proc/self/mounts") or "").splitlines():
            fields = line.split()
            if len(fields) >= 3:
                # the last line for a mount point is the one on top
                mounts[fields[1].replace("\\040", " ")] = {"source": fields[0], "fstype": fields[2]}
        return mounts

    def storage(self):
        mounts = self.mounts()
        root = mounts.get("/", {})
        data = {"root_fstype": root.get("fstype"), "root_source": root.get("source"),
                # btrfs subvolumes (/var on a default SLES install) share the root device and do not count
                "separate": sorted(m for m in ("/usr", "/var", "/boot")
                                   if m in mounts and mounts[m]["source"] != root.get("source")),
                "root_encrypted": False, "xfs_v4": False, "snapper_root": False, "free_mb": {},
                "mounts": dict((m, d["fstype"]) for m, d in mounts.items() if d["source"].startswith("/dev/"))}
        for mount in ("/", "/var", "/boot", "/home"):
            if mount in mounts or mount == "/":
                stat = os.statvfs(mount)
                data["free_mb"][mount] = int(stat.f_bavail * stat.f_frsize // (1024 * 1024))
        source = root.get("source", "")
        if source.startswith("/dev/"):
            # --inverse lists the root device and everything below it (crypt, lvm, part, disk)
            rc, out, dummy = self.run(["lsblk", "--inverse", "--noheadings", "--list", "-o", "TYPE", source])
            data["root_encrypted"] = "crypt" in out.split()
        if root.get("fstype") == "xfs":
            rc, out, dummy = self.run(["xfs_info", "/"])
            data["xfs_v4"] = rc == 0 and (re.search(r"crc=0\b", out) is not None or "crc=" not in out)
        if root.get("fstype") == "btrfs":
            data["snapper_root"] = os.path.isfile("/etc/snapper/configs/root")
        return data

    def boot(self):
        rc, dummy, dummy2 = self.run(["rpm", "-q", "grub2"])
        sdboot = os.path.isdir("/boot/efi/loader/entries") or os.path.isdir("/boot/loader/entries")
        return {"firmware": "efi" if os.path.isdir("/sys/firmware/efi") else "bios",
                "grub2_installed": rc == 0, "grub2_cfg": os.path.isfile("/boot/grub2/grub.cfg"),
                "systemd_boot_entries": sdboot, "cmdline": (read_text("/proc/cmdline") or "").strip()}

    def kernels(self):
        # The package owning each kernel image: minimal images ship kernel-default-base, not kernel-default.
        images = sorted(p for p in glob.glob("/boot/vmlinuz-*") + glob.glob("/boot/Image-*") if not os.path.islink(p))
        installed = []
        if images:
            rc, out, dummy = self.run(["rpm", "-qf", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\\n"] + images)
            installed = sorted(set(line for line in out.split() if line.startswith("kernel-")))
        zypp = read_ini("/etc/zypp/zypp.conf").get("main", {})
        return {"running": platform.release(), "installed": installed,
                "multiversion": zypp.get("multiversion"), "multiversion_kernels": zypp.get("multiversion.kernels")}

    def packages(self, wanted):
        rc, out, dummy = self.run(["rpm", "-qa", "--qf", "%{NAME} %{ARCH}\\n"])
        names, arch32 = set(), 0
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:
                names.add(parts[0])
                arch32 += parts[1] in ("i586", "i686")
        dms = {}
        rc2, out2, dummy = self.run(["rpm", "-q", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\\n"] + list(DMS_PACKAGES))
        for line in out2.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in DMS_PACKAGES:
                dms[parts[0]] = parts[1]
        return {"count": len(names), "arch32_count": arch32, "removed_installed": sorted(set(wanted) & names),
                "dms": dms, "query_ok": rc == 0}

    def unit_state(self, unit):
        rc, out, dummy = self.run(["systemctl", "is-enabled", unit])
        enabled = out.strip() if out else "unknown"
        rc, out, dummy = self.run(["systemctl", "is-active", unit])
        return {"enabled": enabled, "active": out.strip() if out else "unknown"}

    def network(self):
        team, bond, bridge = [], [], []
        for path in sorted(glob.glob("/etc/sysconfig/network/ifcfg-*")):
            text = read_text(path) or ""
            name = os.path.basename(path)[len("ifcfg-"):]
            if re.search(r"^TEAM_RUNNER=", text, re.M):
                team.append(name)
            if re.search(r"^BONDING_MASTER=['\"]?yes", text, re.M):
                bond.append(name)
            if re.search(r"^BRIDGE=['\"]?yes", text, re.M):
                bridge.append(name)
        return {"wicked": self.unit_state("wicked"), "networkmanager": self.unit_state("NetworkManager"),
                "team": team, "bond": bond, "bridge": bridge}

    def ssh(self):
        state = self.unit_state("sshd")
        rc, out, dummy = self.run(["sshd", "-T"])
        match = re.search(r"^permitrootlogin (\S+)", out.lower(), re.M) if rc == 0 else None
        state["permit_root_login"] = match.group(1) if match else None
        state["root_login_dropin"] = os.path.isfile("/etc/ssh/sshd_config.d/50-permit-root-login.conf")
        return state

    def lsm(self):
        enabled = (read_text("/sys/module/apparmor/parameters/enabled") or "").strip() == "Y"
        modified = []
        if enabled:
            rc, out, dummy = self.run(["rpm", "-V", "apparmor-profiles"])
            modified = [line.split()[-1] for line in out.splitlines()
                        if len(line) > 2 and line[2] == "5" and "/etc/apparmor.d" in line]
        profiles = len(glob.glob("/etc/apparmor.d/*")) if enabled else 0
        return {"apparmor_enabled": enabled, "apparmor_modified_profiles": modified, "apparmor_etc_entries": profiles,
                "selinux_enabled": os.path.isdir("/sys/fs/selinux") and os.path.exists("/sys/fs/selinux/enforce")}

    def cgroup(self):
        rc, out, dummy = self.run(["stat", "-f", "-c", "%T", "/sys/fs/cgroup"])
        cmdline = read_text("/proc/cmdline") or ""
        match = re.search(r"systemd\.unified_cgroup_hierarchy=(\S+)", cmdline)
        return {"fs": out.strip() if rc == 0 else None, "cmdline_unified": match.group(1) if match else None}

    def updates(self, check_patches):
        data = {"needed_patches": None, "security_patches": None, "needs_reboot": None}
        rc, dummy, dummy2 = self.run(["zypper", "--non-interactive", "--no-refresh", "needs-rebooting"])
        if rc in (0, 102):
            data["needs_reboot"] = rc == 102
        if check_patches:
            rc, out, dummy = self.run(["zypper", "--non-interactive", "--no-refresh", "--xmlout", "list-patches"])
            if rc in (0, 100, 101):
                try:
                    root = ET.fromstring(out)
                    # status "needed" is what "zypper patch" installs; optional patches are listed as "optional"
                    needed = [u for u in root.iter("update") if u.get("kind") == "patch" and u.get("status") == "needed"]
                    data["needed_patches"] = len(needed)
                    data["security_patches"] = len([u for u in needed if u.get("category") == "security"])
                except ET.ParseError:
                    pass
        return data

    def virt(self):
        running = [os.path.basename(p)[:-4] for p in glob.glob("/run/libvirt/qemu/*.xml")]
        xen = os.path.isdir("/proc/xen") and (read_text("/proc/xen/capabilities") or "").find("control_d") >= 0
        return {"running_guests": sorted(running), "xen_dom0": xen,
                "virt_type": (read_text("/sys/hypervisor/type") or "").strip() or None}

    def management(self):
        suma = any(os.path.isfile(p) for p in ("/etc/salt/minion.d/susemanager.conf",
                                               "/etc/venv-salt-minion/minion.d/susemanager.conf"))
        return {"suse_manager_client": suma, "public_cloud": os.path.exists("/usr/sbin/registercloudguest"),
                "ha_corosync": os.path.isfile("/etc/corosync/corosync.conf")}

    def dms(self):
        product = None
        for line in (read_text("/etc/sle-migration-service.yml") or "").splitlines():
            if line.strip().startswith("migration_product:"):
                product = line.split(":", 1)[1].strip().strip("'\"")
        return {"host_config": os.path.isfile("/etc/sle-migration-service.yml"), "migration_product": product,
                "migration_image": sorted(os.path.basename(p) for p in glob.glob("/migration-image/*.iso")),
                "prechecks_bin": os.path.exists("/usr/bin/suse-migration-pre-checks")}


def main():
    module = AnsibleModule(
        argument_spec=dict(removed_packages=dict(type="list", elements="str", default=[]),
                           check_patches=dict(type="bool", default=True)),
        supports_check_mode=True,
    )
    probe = Probe(module)
    registration = probe.registration()
    service_hosts = set(s["host"] for s in registration["services"])
    if registration["server_configured"]:
        service_hosts.add(url_host(registration["server"]))
    result = {
        "os": probe.os_release(),
        "products": probe.products(),
        "cpu": probe.cpu(),
        "registration": registration,
        "repos": probe.repos(service_hosts),
        "storage": probe.storage(),
        "boot": probe.boot(),
        "kernels": probe.kernels(),
        "packages": probe.packages(module.params["removed_packages"]),
        "network": probe.network(),
        "ssh": probe.ssh(),
        "lsm": probe.lsm(),
        "cgroup": probe.cgroup(),
        "updates": probe.updates(module.params["check_patches"]),
        "virt": probe.virt(),
        "management": probe.management(),
        "dms": probe.dms(),
        "python": {"executable": sys.executable, "version": "%d.%d" % sys.version_info[:2]},
    }
    module.exit_json(changed=False, probe=result)


if __name__ == "__main__":
    main()
