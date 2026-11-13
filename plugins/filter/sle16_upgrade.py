# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Harshvardhan Sharma <harshvardhan.sharma@suse.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: sle16_upgrade_report
short_description: Turn the upgrade probe and the DMS pre-check messages into findings and a verdict
version_added: "0.1.0"
description:
  - Returns C(verdict) (C(blocked), C(needs_action) or C(ready)), C(counts) per severity and C(findings), each with
    C(id), C(severity), C(title), C(found), C(remediation), C(sources) and C(check).
positional: dms, settings
options:
  _input:
    description: The C(probe) result of M(hvsharma12.sle16_upgrade.sle16_upgrade_probe).
    type: dict
    required: true
  dms:
    description: The result of M(hvsharma12.sle16_upgrade.sle16_upgrade_dms_prechecks).
    type: dict
    required: true
  settings:
    description: Target, supported sources, free space threshold, removed packages, pinned interpreter.
    type: dict
    required: true
"""

EXAMPLES = r"""
report: "{{ probe.probe | hvsharma12.sle16_upgrade.sle16_upgrade_report(dms, settings) }}"
"""

RETURN = r"""
_value:
  description: C(verdict), C(counts) and C(findings).
  type: dict
"""

SEVERITIES = ("blocker", "needs_action", "info")

SOURCES = {
    "U161": "https://documentation.suse.com/sles/16.1/html/SLES-upgrading/index.html",
    "U160": "https://documentation.suse.com/sles/16.0/html/SLES-upgrading/index.html",
    "RN161": "https://documentation.suse.com/releasenotes/sles/16.1/index.html",
    "RN160": "https://documentation.suse.com/releasenotes/sles/16.0/index.html",
    "C161": "https://documentation.suse.com/sles/16.1/html/SLE-comparison/",
    "DMS": "https://documentation.suse.com/suse-distribution-migration-system/15/html/distribution-migration-system/index.html",
    "HA161": "https://documentation.suse.com/sle-ha/16.1/html/HA-upgrading/index.html",
    "SAP161": "https://documentation.suse.com/sles-sap/16.1/html/SAP-upgrading/index.html",
    "CODE": "https://github.com/SUSE/suse-migration-services/tree/v2.1.39",
}

# DMS check names (the text after "--> Checking") of checks the role runs itself, mapped to the role's finding id.
DMS_COVERED = {
    "system architecture version": "cpu_level",
    "for local private repos": "repos_local",
    "for encrypted rootfs": "root_encrypted",
    "for XFS v4 filesystems": "xfs_v4",
    "for latest kernel in multiversion kernel system": "multiversion_kernels",
    "LSM migration": "apparmor_modified",
    "sshd configuration": "ssh_root_login",
}
DMS_LEVELS = {"ERROR": "blocker", "CRITICAL": "blocker", "WARNING": "needs_action"}
DROPPED_FS = ("reiserfs", "hfsplus", "ufs", "ocfs2")
SUPPORTED_PRODUCTS = ("SLES", "SLES_SAP", "SLE_RT")


def src(*refs):
    return [{"ref": ref, "url": SOURCES[ref.split()[0]]} for ref in refs]


class Findings(object):
    def __init__(self):
        self.items = []

    def add(self, fid, severity, title, found, remediation, sources, check="role"):
        self.items.append({"id": fid, "severity": severity, "title": title, "found": found,
                           "remediation": remediation, "sources": sources, "check": check})

    def get(self, fid):
        for item in self.items:
            if item["id"] == fid:
                return item
        return None


def base_product(probe):
    products = probe.get("products") or []
    for product in products:
        if product.get("base"):
            return product
    return products[0] if products else {}


def source_checks(f, probe, settings):
    os_info = probe.get("os") or {}
    version = os_info.get("version_id") or ""
    target = settings["target_version"]
    supported = settings["supported_sources"].get(target, [])
    if version.startswith("16"):
        f.add("already_sle16", "blocker", "The host already runs SLE 16",
              "VERSION_ID %s" % version,
              "Minor upgrades within SLE 16 use 'zypper migration', not the Distribution Migration System.",
              src("DMS §1"))
        return
    if version not in supported:
        conflict = settings.get("conflict_sources", {}).get(target, [])
        if version in conflict:
            f.add("source_version_conflict", "needs_action",
                  "SUSE documents %s as a source for %s in the release notes but not in the upgrade guide" % (version, target),
                  "VERSION_ID %s, target %s" % (version, target),
                  "Upgrade to 15 SP7 first or target SLES 16.1, which supports 15 SP5 to SP7.",
                  src("U160 §1.3", "RN160 §5.8"))
        else:
            f.add("source_version_unsupported", "blocker",
                  "SLES %s is not a supported source for SLES %s" % (version, target),
                  "VERSION_ID %s; supported: %s" % (version, ", ".join(supported)),
                  "Upgrade to a supported service pack first (zypper migration), then re-run the analysis.",
                  src("U161 §2", "U160 §1.3"))
    product = base_product(probe)
    name = product.get("name")
    if name and name not in SUPPORTED_PRODUCTS:
        f.add("product_unsupported", "blocker", "Base product %s has no documented upgrade path to SLE 16" % name,
              "/etc/products.d/baseproduct: %s %s" % (name, product.get("version")),
              "Only SLES, SLES for SAP and SLE RT 15 are upgraded by this path.", src("U161 §2"))
    if name == "SLES_SAP":
        f.add("sap_product", "info", "SLES for SAP: the target is SLES for SAP 16",
              "base product SLES_SAP", "Set migration_product: SLES_SAP/%s/<arch>; SAP is supported on x86_64 and ppc64le." % target,
              src("SAP161 §2"))
    if os_info.get("transactional"):
        f.add("transactional_host", "blocker", "Transactional host",
              "/usr/sbin/transactional-update exists",
              "Transactional SLE 15 systems are not upgraded by this path.", src("C161 §5.6"))


def platform_checks(f, probe):
    cpu = probe.get("cpu") or {}
    if cpu.get("machine") == "x86_64" and cpu.get("level") == "x86_64":
        f.add("cpu_level", "blocker", "The CPU is below x86-64-v2",
              "zypper system-architecture: x86_64",
              "SLE 16 needs x86-64-v2; move the host to newer hardware (VMs: pass the host CPU model).",
              src("RN160 §5.42", "CODE package/suse-migration-sle16-activation-spec-template %pre"))
    if cpu.get("power_generation") and cpu["power_generation"] < 10:
        f.add("cpu_level", "blocker", "The CPU is below POWER10",
              "POWER%s" % cpu["power_generation"], "SLE 16 is supported on POWER10 or newer.",
              src("RN160 §5.42", "CODE suse_migration_services/prechecks/cpu_arch.py"))
    if cpu.get("machine") == "s390x":
        f.add("s390x_run_migration", "needs_action", "s390x starts the upgrade with run_migration",
              "machine s390x", "Install the SLES16-Migration package and run 'run_migration' (kexec); not on Xen.",
              src("U161 §6.2"))
    virt = probe.get("virt") or {}
    if virt.get("xen_dom0"):
        f.add("xen_host", "blocker", "The host is a Xen dom0", "/proc/xen/capabilities: control_d",
              "SLE 16 has no Xen hypervisor; move guests to KVM first.", src("RN160 §10.1"))
    elif virt.get("virt_type") == "xen":
        f.add("xen_guest", "needs_action", "The host is a Xen guest", "/sys/hypervisor/type: xen",
              "SLE 16 does not run as a paravirtualized (PV) Xen guest; convert PV guests to HVM.", src("RN160 §10.1"))
    if virt.get("running_guests"):
        f.add("kvm_guests_running", "needs_action", "KVM guests are running",
              ", ".join(virt["running_guests"]), "Shut down all running VM guests before the upgrade.", src("U161 §4"))
    boot = probe.get("boot") or {}
    if cpu.get("machine") != "s390x":
        if not boot.get("grub2_installed") or not boot.get("grub2_cfg"):
            f.add("bootloader_not_grub2", "blocker", "The host does not boot with GRUB 2",
                  "grub2 installed: %s; /boot/grub2/grub.cfg: %s" % (boot.get("grub2_installed"), boot.get("grub2_cfg")),
                  "The activation package adds a GRUB 2 entry for the upgrade image; a host without it cannot start the upgrade.",
                  src("U161 §6.2", "CODE package/suse-migration-sle16-activation-spec-template %post"))
        elif boot.get("systemd_boot_entries"):
            f.add("bootloader_not_grub2", "blocker", "systemd-boot entries are present",
                  "loader/entries exists", "Switching between grub2 and systemd-boot is not supported during an upgrade.",
                  src("RN161 §3.6"))
    if boot.get("firmware") == "bios":
        f.add("bios_legacy", "info", "Legacy BIOS boot", "/sys/firmware/efi absent",
              "Legacy BIOS is deprecated in SLE 16 but kept for upgraded systems.", src("C161 §2.1"))


def registration_checks(f, probe):
    reg = probe.get("registration") or {}
    management = probe.get("management") or {}
    services = [s for s in reg.get("services", []) if s.get("enabled")]
    if not reg.get("credentials_file") or not services:
        f.add("not_registered", "blocker", "The host is not registered",
              "SCC credentials file: %s; enabled registration services: %d" % (reg.get("credentials_file"), len(services)),
              "Register with SCC or RMT (SUSEConnect -r ...) including all modules; the upgrade aborts on unregistered hosts.",
              src("U161 §3.1", "CODE suse_migration_services/units/prepare.py"))
    if management.get("suse_manager_client"):
        f.add("suse_manager_client", "blocker", "The host is a SUSE Manager client",
              "susemanager.conf for the Salt minion exists",
              "Use the upgrade path provided by SUSE Manager for this host.", src("DMS §2"))
    if management.get("public_cloud"):
        f.add("public_cloud", "info", "Public cloud instance",
              "/usr/sbin/registercloudguest exists",
              "Start the upgrade by reboot only; update /etc/motd by hand afterwards; instance metadata keeps the old version.",
              src("DMS §8.1"))
    extensions = [p["name"] for p in probe.get("products") or [] if not p.get("base") and p.get("name")]
    if extensions:
        f.add("extensions_installed", "info", "Modules and extensions must have an upgrade path in SCC",
              ", ".join(sorted(extensions)),
              "SLE 16 has no modules; the SCC upgrade path check (DMS pre-checks) confirms each one is covered.",
              src("U161 §3.2", "C161 §9.3"))


def repo_checks(f, probe):
    repos = [r for r in probe.get("repos") or [] if r.get("enabled")]
    third = [r for r in repos if r.get("origin") == "third_party"]
    local = [r for r in repos if r.get("origin") == "local"]
    if third:
        f.add("repos_third_party", "needs_action", "Enabled repositories outside SCC, RMT and SUSE Manager",
              ", ".join("%s (%s)" % (r["alias"], r["url"]) for r in third),
              "These stay untouched and keep pointing at SLE 15 content: disable them (zypper mr -d <alias>) and re-add SLE 16 versions afterwards.",
              src("DMS §8"))
    if local:
        f.add("repos_local", "needs_action", "Enabled repositories that are not remote",
              ", ".join("%s (%s)" % (r["alias"], r["url"]) for r in local),
              "Local, CD/DVD and ISO repositories may be unavailable during the upgrade: disable them.",
              src("U161 §3.2", "CODE suse_migration_services/prechecks/repos.py"))


def storage_checks(f, probe, settings):
    storage = probe.get("storage") or {}
    if storage.get("root_encrypted"):
        f.add("root_encrypted", "blocker", "The root file system is encrypted",
              "LUKS (crypt) below %s" % storage.get("root_source"),
              "Upgrade is only possible for unencrypted root file systems; reinstall instead.",
              src("DMS §8", "U161 §3.2"))
    split = [m for m in storage.get("separate", []) if m in ("/var", "/usr")]
    if split:
        f.add("os_split_partitions", "blocker", "OS directories on separate file systems",
              "separate mounts: %s" % ", ".join(split),
              "The operating system must reside on one partition (a separate /home works, a separate /var does not).",
              src("U161 §6.1", "DMS §2"))
    free = (storage.get("free_mb") or {}).get("/")
    minimum = int(settings["min_free_mb"])
    if free is not None and free < minimum:
        f.add("free_space_low", "blocker", "Too little free space on /",
              "%d MiB free on /, %d MiB required" % (free, minimum),
              "Free up space or grow the root file system; the upgrade image and the package downloads land on /.",
              src("U161 §4", "CODE package (SLES16-Migration 322 MiB installed)"))
    if storage.get("xfs_v4"):
        f.add("xfs_v4", "info", "The root file system is XFS v4", "xfs_info /: crc=0",
              "XFS v4 is deprecated with no in-place upgrade to v5; plan a re-format before 2030.",
              src("RN161 §7.27", "CODE suse_migration_services/prechecks/xfs.py"))
    if storage.get("root_fstype") != "btrfs" or not storage.get("snapper_root"):
        f.add("no_rollback_snapshot", "info", "No snapper snapshot will protect the upgrade",
              "root %s, snapper root config: %s" % (storage.get("root_fstype"), storage.get("snapper_root")),
              "The upgrade only rewinds on errors before it starts: take a hypervisor, cloud or storage snapshot first.",
              src("U161 §3.1", "CODE suse_migration_services/units/btrfs_snapshot_pre_migration.py"))
    dropped = [(m, t) for m, t in (storage.get("mounts") or {}).items() if t in DROPPED_FS]
    for mount, fstype in sorted(dropped):
        f.add("filesystem_dropped:%s" % mount, "blocker" if mount == "/" else "needs_action",
              "File system %s on %s is dropped in SLE 16" % (fstype, mount), "%s mounted on %s" % (fstype, mount),
              "Move the data to a supported file system (btrfs, xfs, ext4) before the upgrade.", src("C161 §6.2"))


def system_checks(f, probe, settings):
    kernels = probe.get("kernels") or {}
    multi = kernels.get("multiversion") or ""
    setting = kernels.get("multiversion_kernels")
    installed = kernels.get("installed") or []
    wrong_setting = "kernel" in multi and set((setting or "").replace(" ", "").split(",")) != {"latest", "running"}
    if wrong_setting or len(installed) > 1:
        f.add("multiversion_kernels", "needs_action", "Several kernels or a multiversion.kernels setting other than latest,running",
              "multiversion.kernels = %s; installed: %s" % (setting, ", ".join(installed) or "none"),
              "Run 'suse-migration-pre-checks --fix' or set multiversion.kernels = latest,running and remove the old kernels.",
              src("U161 §3.2", "DMS §3"))
    ssh = probe.get("ssh") or {}
    if ssh.get("enabled") == "enabled" and ssh.get("permit_root_login") not in (None, "no"):
        if ssh.get("root_login_dropin"):
            f.add("ssh_root_login", "info", "Root SSH login is kept by a drop-in",
                  "/etc/ssh/sshd_config.d/50-permit-root-login.conf exists",
                  "After the upgrade install openssh-server-config-rootlogin and remove the drop-in.", src("U161 §4"))
        else:
            f.add("ssh_root_login", "needs_action", "Root SSH login will be disabled by SLE 16",
                  "sshd -T: permitrootlogin %s" % ssh["permit_root_login"],
                  "Create /etc/ssh/sshd_config.d/50-permit-root-login.conf with 'PermitRootLogin yes', or log in as a non-root user with sudo.",
                  src("U161 §4"))
    pinned = settings.get("pinned_interpreter")
    if pinned and ("python3.11" in pinned or "python3.6" in pinned):
        f.add("ansible_interpreter_pinned", "needs_action", "The inventory pins a Python that SLE 16 removes",
              "ansible_python_interpreter: %s" % pinned,
              "Set ansible_python_interpreter to /usr/bin/python3 (3.13) or auto for the host after the upgrade.",
              src("RN161 §7.56"))
    for name in (probe.get("packages") or {}).get("removed_installed", []):
        info = settings["removed_packages"].get(name, {})
        f.add("removed_package:%s" % name, "needs_action", "%s is removed in SLE %s" % (name, info.get("release", "16")),
              "package %s installed" % name, info.get("remediation", "Plan a replacement; the package is not on SLE 16."),
              src("RN161 §13.1" if info.get("release") == "16.1" else "RN160 §10.1"))
    arch32 = (probe.get("packages") or {}).get("arch32_count") or 0
    if arch32:
        f.add("packages_32bit", "info", "32-bit packages are installed", "%d i586/i686 packages" % arch32,
              "SLE 16 drops 32-bit binaries by default.", src("RN160 §5.53"))
    lsm = probe.get("lsm") or {}
    if lsm.get("apparmor_modified_profiles"):
        f.add("apparmor_modified", "needs_action", "AppArmor profiles were changed",
              ", ".join(lsm["apparmor_modified_profiles"]),
              "SLE 16 replaces AppArmor with SELinux; changed profiles are not converted. Write SELinux policy for them.",
              src("C161 §4", "CODE suse_migration_services/prechecks/lsm.py"))
    network = probe.get("network") or {}
    if network.get("team"):
        f.add("network_team", "needs_action", "teamd interfaces are configured", ", ".join(network["team"]),
              "teamd is removed in SLE 16; reconfigure as a bond.", src("RN160 §5.24"))
    if (network.get("wicked") or {}).get("active") == "active":
        f.add("network_wicked", "info", "wicked manages the network", "wicked.service active",
              "The upgrade converts the configuration to NetworkManager with wicked2nm; warnings abort it.",
              src("C161 §8", "DMS §5"))
    cgroup = probe.get("cgroup") or {}
    if cgroup.get("fs") not in (None, "cgroup2fs") or cgroup.get("cmdline_unified") in ("0", "false", "no"):
        f.add("cgroup_v1", "needs_action", "cgroup v1 is in use",
              "/sys/fs/cgroup: %s; systemd.unified_cgroup_hierarchy=%s" % (cgroup.get("fs"), cgroup.get("cmdline_unified")),
              "SLE 16 supports only cgroup v2; check workloads that need v1 and drop the kernel parameter.",
              src("RN160 §5.64", "C161 §6.1"))
    updates = probe.get("updates") or {}
    if updates.get("needed_patches"):
        f.add("patches_pending", "needs_action", "Patches are pending",
              "%d needed (%d security)" % (updates["needed_patches"], updates.get("security_patches") or 0),
              "Run 'zypper patch' until nothing is left, then re-run the analysis.", src("U161 §4"))
    if updates.get("needs_reboot"):
        f.add("reboot_pending", "needs_action", "A reboot is pending after updates",
              "zypper needs-rebooting: 102", "Reboot before the upgrade.", src("U161 §4"))
    if (probe.get("management") or {}).get("ha_corosync"):
        f.add("ha_cluster", "needs_action", "The host is a cluster node",
              "/etc/corosync/corosync.conf exists",
              "Run 'crm cluster health sles16', fix [FAIL] items, stop cluster services and upgrade every node.",
              src("HA161 §5"))
    dms = probe.get("dms") or {}
    target = "%s/%s/" % (settings["target_product"], settings["target_version"])
    if settings["target_version"] != "16.0" and not (dms.get("migration_product") or "").startswith(target):
        f.add("migration_product_not_set", "needs_action",
              "The migration tool would upgrade to SLES 16.0, not %s" % settings["target_version"],
              "/etc/sle-migration-service.yml migration_product: %s" % (dms.get("migration_product") or "not set"),
              "Add 'migration_product: %s%s' to /etc/sle-migration-service.yml." % (target, settings["arch"]),
              src("U161 §5.1", "CODE suse_migration_services/migration_target.py"))


def merge_dms(f, dms):
    if not dms.get("installed"):
        f.add("dms_prechecks_absent", "info", "The DMS pre-checks did not run",
              "suse-migration-pre-checks is not installed",
              "Install suse-migration-pre-checks and re-run to add the SCC upgrade path, HA and wicked2nm checks.",
              src("DMS §3"), check="dms")
        return
    if dms.get("error"):
        f.add("dms_prechecks_error", "needs_action", "The DMS pre-checks stopped early", dms["error"],
              "Run suse-migration-pre-checks by hand as root and read its output.", src("DMS §3"), check="dms")
    for record in dms.get("records") or []:
        severity = DMS_LEVELS.get(record.get("level"))
        check = record.get("check", "")
        if record.get("level") == "INFO" and check == "wicked to NetworkManager migration" and "[" in record["message"]:
            severity = "info"
        if not severity:
            continue
        message = record["message"]
        covered = DMS_COVERED.get(check)
        if covered:
            existing = f.get(covered)
            if existing:
                existing["found"] += " | DMS: " + message
                existing["check"] = "role+dms"
                continue
            if covered == "ssh_root_login":
                severity = "needs_action"
            f.add(covered, severity, "DMS pre-check: %s" % check, message,
                  "See the DMS message.", src("DMS §3", "CODE suse_migration_services/prechecks"), check="dms")
            continue
        fid = "dms:" + check.replace(" ", "_").lower()
        existing = f.get(fid)
        if existing:
            existing["found"] += " | " + message
            if SEVERITIES.index(severity) < SEVERITIES.index(existing["severity"]):
                existing["severity"] = severity
            continue
        f.add(fid, severity, "DMS pre-check: %s" % check, message, "Follow the DMS message.",
              src("DMS §3", "CODE suse_migration_services/prechecks"), check="dms")


def sle16_upgrade_report(probe, dms, settings):
    f = Findings()
    source_checks(f, probe, settings)
    platform_checks(f, probe)
    registration_checks(f, probe)
    repo_checks(f, probe)
    storage_checks(f, probe, settings)
    system_checks(f, probe, settings)
    merge_dms(f, dms or {})
    findings = sorted(f.items, key=lambda item: (SEVERITIES.index(item["severity"]), item["id"]))
    counts = dict((s, len([i for i in findings if i["severity"] == s])) for s in SEVERITIES)
    verdict = "blocked" if counts["blocker"] else "needs_action" if counts["needs_action"] else "ready"
    return {"verdict": verdict, "counts": counts, "findings": findings}


class FilterModule(object):
    def filters(self):
        return {"sle16_upgrade_report": sle16_upgrade_report}
