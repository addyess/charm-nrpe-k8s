"""Nrpe helpers module."""
import json
import logging
import glob
import os
from ops.model import RelationData, RelationNotFoundError
import socket
import subprocess

import yaml

logger = logging.getLogger(__name__)


class InvalidCustomCheckException(Exception):
    """Custom exception for Invalid nrpe check."""
    pass


def unit_get(attribute):
    """Get the unit ID for the remote unit"""
    _args = ['unit-get', '--format=json', attribute]
    try:
        return json.loads(subprocess.check_output(_args).decode('UTF-8'))
    except ValueError:
        return None


class Monitors(dict):
    """List of checks that a remote Nagios can query."""

    def __init__(self, version="0.3"):
        """Build monitors structure."""
        self["monitors"] = {"remote": {"nrpe": {}}}
        self["version"] = version

    def add_monitors(self, mdict, monitor_label="default"):
        """Add monitors passed in mdict."""
        if not mdict or not mdict.get("monitors"):
            return

        for checktype in mdict["monitors"].get("remote", []):
            check_details = mdict["monitors"]["remote"][checktype]
            if self["monitors"]["remote"].get(checktype):
                self["monitors"]["remote"][checktype].update(check_details)
            else:
                self["monitors"]["remote"][checktype] = check_details

        for _checktype in mdict["monitors"].get("local", []):
            check_details = self.convert_local_checks(
                mdict["monitors"]["local"],
                monitor_label,
            )
            self["monitors"]["remote"]["nrpe"].update(check_details)

    def add_nrpe_check(self, check_name, command):
        """Add nrpe check to remote monitors."""
        self["monitors"]["remote"]["nrpe"][check_name] = command

    def convert_local_checks(self, monitors, monitor_src):
        """Convert check from local checks to remote nrpe checks.

        monitors -- monitor dict
        monitor_src -- Monitor source principal, subordinate or user
        """
        mons = {}
        for checktype in monitors.keys():
            for checkname in monitors[checktype]:
                try:
                    check_def = NRPECheckCtxt(
                        checktype,
                        monitors[checktype][checkname],
                        monitor_src,
                    )
                    mons[check_def["cmd_name"]] = {"command": check_def["cmd_name"]}
                except InvalidCustomCheckException as e:
                    logger.error(
                        "Error encountered configuring local check " '"%s": %s',
                        checkname,
                        str(e),
                    )
        return mons


def get_local_ingress_address(binding):
    """Get ingress IP address for a binding.

    binding - e.g. 'monitors'
    """
    # using network-get to retrieve the address details if available.
    logger.info("Getting ingress IP address for binding %s", binding.name)
    try:
        network_info = binding.network
        if network_info.ingress_addresses:
            # workaround lp#1897261
            ip_address = network_info.bind_address
            if ip_address not in network_info.ingress_addresses:
                ip_address = network_info.ingress_address
            logger.info("Using ingress-addresses: %s", ip_address)
            return ip_address
    except RelationNotFoundError:
        # We'll fallthrough to the Pre 2.3 code below.
        pass

    # Pre 2.3 output
    ip_address = unit_get("private-address")
    logger.info("Using unit_private_ip: %s", ip_address)
    return ip_address


class RelationContext(dict):
    def __init__(self, charm):
        self.name = None
        self.charm = charm


class MonitorsRelation(RelationContext):
    """Define a monitors relation."""

    def __init__(self, charm):
        """Build superclass and principal relation."""
        super(MonitorsRelation, self).__init__(charm)
        self.name = "monitors"

    def is_ready(self):
        """Return true if the principal relation is ready."""
        return self.charm.principal_relation.is_ready()

    def get_subordinate_monitors(self):
        """Return default monitors defined by this charm."""
        monitors = Monitors()
        for check in self.charm.subordinate_definitions["checks"]:
            if check["cmd_params"]:
                monitors.add_nrpe_check(check["cmd_name"], check["cmd_name"])
        return monitors

    def get_user_defined_monitors(self):
        """Return monitors defined by monitors config option."""
        monitors = Monitors()
        monitors.add_monitors(yaml.safe_load(self.charm.config["monitors"]), "user")
        return monitors

    def get_principal_monitors(self):
        """Return monitors passed by relation with principal."""
        return self.charm.principal_relation.get_monitors()

    def get_monitor_dicts(self):
        """Return all monitor dicts."""
        monitor_dicts = {
            "principal": self.get_principal_monitors(),
            "subordinate": self.get_subordinate_monitors(),
            "user": self.get_user_defined_monitors(),
        }
        return monitor_dicts

    def get_monitors(self):
        """Return monitor dict.

        All monitors merged together and local
        monitors converted to remote nrpe checks.
        """
        all_monitors = Monitors()
        monitors = [
            self.get_principal_monitors(),
            self.get_subordinate_monitors(),
            self.get_user_defined_monitors(),
        ]
        for mon in monitors:
            all_monitors.add_monitors(mon)
        return all_monitors

    def egress_subnets(self, unit_rdata):
        """Return egress subnets.

        This behaves the same as charmhelpers.core.hookenv.egress_subnets().
        If it can't determine the egress subnets it will fall back to
        ingress-address or finally private-address.
        """
        if "egress-subnets" in unit_rdata:
            return unit_rdata["egress-subnets"]
        if "ingress-address" in unit_rdata:
            return unit_rdata["ingress-address"]
        return unit_rdata["private-address"]

    def get_data(self):
        """Get relation data."""
        if not len(self.charm.model.relations[self.name]):
            return
        # self['monitors'] comes from the superclass helpers.RelationContext
        # and contains relation data for each 'monitors' relation (to/from
        # Nagios).
        subnets = [
            self.egress_subnets(unit)
            for relation in self.charm.model.relations[self.name]
            for unit in relation.data.values()
            if "private-address" in unit
        ]
        self["monitor_allowed_hosts"] = ",".join(subnets)
        return self

    def provide_data(self):
        """Return relation info."""
        address = get_local_ingress_address(self.charm.model.get_binding("monitors"))

        relation_info = {
            "target-id": self.charm.principal_relation.nagios_hostname(),
            "monitors": self.get_monitors(),
            "private-address": address,
            "ingress-address": address,
            "machine_id": os.environ["JUJU_MACHINE_ID"],
        }
        return relation_info


class PrincipalRelation(RelationContext):
    """Define a principal relation."""

    def __init__(self, charm):
        """Set name and interface."""
        super(PrincipalRelation, self).__init__(charm)
        if self.charm.model.relations["nrpe-external-master"]:
            self.name = "nrpe-external-master"
        elif self.charm.model.relations["general-info"]:
            self.name = "general-info"
        elif self.charm.model.relations["local-monitors"]:
            self.name = "local-monitors"

    def is_ready(self):
        """Return true if the relation is connected."""
        if self.name not in self:
            return False
        return "__unit__" in self[self.name][0]

    def nagios_hostname(self):
        """Return the string that nagios will use to identify this host."""
        host_context = self.charm.config["nagios_host_context"]
        if host_context:
            host_context += "-"
        hostname_type = self.charm.config["nagios_hostname_type"]
        if hostname_type == "host" or not self.is_ready():
            nagios_hostname = "{}{}".format(host_context, socket.gethostname())
            return nagios_hostname
        else:
            principal_unitname = hookenv.principal_unit()
            # Fallback to using "primary" if it exists.
            if not principal_unitname:
                for relunit in self[self.name]:
                    if relunit.get("primary", "False").lower() == "true":
                        principal_unitname = relunit["__unit__"]
                        break
            nagios_hostname = "{}{}".format(host_context, principal_unitname)
            nagios_hostname = nagios_hostname.replace("/", "-")
            return nagios_hostname

    def get_monitors(self):
        """Return monitors passed by services on the self.interface relation."""
        if not self.is_ready():
            return
        monitors = Monitors()
        for rel in self[self.name]:
            if rel.get("monitors"):
                monitors.add_monitors(yaml.load(rel["monitors"]), "principal")
        return monitors

    def provide_data(self):
        """Return nagios hostname and nagios host context."""
        # Provide this data to principals because get_nagios_hostname expects
        # them in charmhelpers/contrib/charmsupport/nrpe when writing principal
        # service__* files
        return {
            "nagios_hostname": self.nagios_hostname(),
            "nagios_host_context": self.charm.config["nagios_host_context"],
        }


class NagiosInfo(dict):
    """Define a NagiosInfo dict."""

    def __init__(self, charm):
        """Set principal relation and dict values."""
        self["external_nagios_master"] = "127.0.0.1"
        if charm.config["nagios_master"] != "None":
            self["external_nagios_master"] = "{},{}".format(
                self["external_nagios_master"], charm.config["nagios_master"]
            )
        self["nagios_hostname"] = charm.principal_relation.nagios_hostname()

        address = None
        if charm.config["nagios_master"] != "None":
            # Try to work out the correct interface/IP. We can't use both
            # network-get nor 'unit-get private-address' because both can
            # return the wrong IP on systems with more than one interface
            # (LP: #1736050).
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((charm.config["nagios_master"].split(",")[0], 80))
            address = s.getsockname()[0]
            s.close()
        # Fallback to unit-get private-address
        if not address:
            address = unit_get("private-address")

        self["nagios_ipaddress"] = address
        self["nrpe_ipaddress"] = get_local_ingress_address(
            charm.model.get_binding("monitors")
        )
        self["dont_blame_nrpe"] = "1" if charm.config["dont_blame_nrpe"] else "0"
        self["debug"] = "1" if charm.config["debug"] else "0"


class RsyncEnabled(RelationContext):
    """Define a relation context for rsync enabled relation."""

    def __init__(self, *args, **kwargs):
        """Set export_nagios_definitions."""
        super(RsyncEnabled, self).__init__(*args, **kwargs)
        self["export_nagios_definitions"] = self.charm.config[
            "export_nagios_definitions"
        ]
        if (
            self.charm.config["nagios_master"]
            and self.charm.config["nagios_master"] != "None"
        ):
            self["export_nagios_definitions"] = True

    def is_ready(self):
        """Return true if relation is ready."""
        return self["export_nagios_definitions"]


class NRPECheckCtxt(dict):
    """Convert a local monitor definition.

    Create a dict needed for writing the nrpe check definition.
    """

    def __init__(self, checktype, check_opts, monitor_src):
        """Set dict values."""
        plugin_path = "/usr/lib/nagios/plugins"
        if checktype == "procrunning":
            self["cmd_exec"] = plugin_path + "/check_procs"
            self["description"] = "Check process {executable} is running".format(
                **check_opts
            )
            self["cmd_name"] = "check_proc_" + check_opts["executable"]
            self["cmd_params"] = "-w {min} -c {max} -C {executable}".format(
                **check_opts
            )
        elif checktype == "processcount":
            self["cmd_exec"] = plugin_path + "/check_procs"
            self["description"] = "Check process count"
            self["cmd_name"] = "check_proc_principal"
            if "min" in check_opts:
                self["cmd_params"] = "-w {min} -c {max}".format(**check_opts)
            else:
                self["cmd_params"] = "-c {max}".format(**check_opts)
        elif checktype == "disk":
            self["cmd_exec"] = plugin_path + "/check_disk"
            self["description"] = "Check disk usage " + check_opts["path"].replace(
                "/", "_"
            )
            self["cmd_name"] = "check_disk_principal"
            self["cmd_params"] = "-w 20 -c 10 -p " + check_opts["path"]
        elif checktype == "custom":
            custom_path = check_opts.get("plugin_path", plugin_path)
            if not custom_path.startswith(os.path.sep):
                custom_path = os.path.join(os.path.sep, custom_path)
            if not os.path.isdir(custom_path):
                raise InvalidCustomCheckException(
                    'Specified plugin_path "{}" does not exist or is not a '
                    "directory.".format(custom_path)
                )
            check = check_opts["check"]
            self["cmd_exec"] = os.path.join(custom_path, check)
            self["description"] = check_opts.get("desc", "Check %s" % check)
            self["cmd_name"] = check
            self["cmd_params"] = check_opts.get("params", "") or ""
        self["description"] += " ({})".format(monitor_src)
        self["cmd_name"] += "_" + monitor_src


class SubordinateCheckDefinitions(dict):
    """Return dict of checks the charm configures."""

    def __init__(self, charm):
        """Set dict values."""
        procs = self.proc_count()

        if charm.config["procs"] == "auto":
            proc_thresholds = "-k -w {} -c {}".format(
                25 * procs + 100, 50 * procs + 100
            )
        else:
            proc_thresholds = charm.config["procs"]

        disk_root_thresholds = ""
        if charm.config["disk_root"]:
            disk_root_thresholds = charm.config["disk_root"] + " -p / "

        pkg_plugin_dir = "/usr/lib/nagios/plugins/"
        local_plugin_dir = "/usr/local/lib/nagios/plugins/"
        checks = [
            {
                "description": "Root disk",
                "cmd_name": "check_disk_root",
                "cmd_exec": pkg_plugin_dir + "check_disk",
                "cmd_params": disk_root_thresholds,
            },
            {
                "description": "Number of Zombie processes",
                "cmd_name": "check_zombie_procs",
                "cmd_exec": pkg_plugin_dir + "check_procs",
                "cmd_params": charm.config["zombies"],
            },
            {
                "description": "Number of processes",
                "cmd_name": "check_total_procs",
                "cmd_exec": pkg_plugin_dir + "check_procs",
                "cmd_params": proc_thresholds,
            },
            {
                "description": "Number of Users",
                "cmd_name": "check_users",
                "cmd_exec": pkg_plugin_dir + "check_users",
                "cmd_params": charm.config["users"],
            },
            {
                "description": "Connnection tracking table",
                "cmd_name": "check_conntrack",
                "cmd_exec": local_plugin_dir + "check_conntrack.sh",
                "cmd_params": charm.config["conntrack"],
            },
        ]

        self["checks"] = []
        nrpe_config_sub_tmpl = "/etc/nagios/nrpe.d/{}_*.cfg"
        nrpe_config_tmpl = "/etc/nagios/nrpe.d/{}.cfg"
        for check in checks:
            # This can be used to clean up old files before rendering the new
            # ones
            nrpe_configfiles_sub = nrpe_config_sub_tmpl.format(check["cmd_name"])
            nrpe_configfiles = nrpe_config_tmpl.format(check["cmd_name"])
            check["matching_files"] = glob.glob(nrpe_configfiles_sub)
            check["matching_files"].extend(glob.glob(nrpe_configfiles))
            check["description"] += " (sub)"
            self["checks"].append(check)

    def proc_count(self):
        """Return number number of processing units."""
        return int(subprocess.check_output(["nproc", "--all"]))
