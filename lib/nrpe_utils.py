"""Nrpe utils module."""
import logging
import os
import shutil
from pathlib import Path

from nrpe_helpers import (
    MonitorsRelation,
    PrincipalRelation,
    NagiosInfo,
    SubordinateCheckDefinitions,
    NRPECheckCtxt,
)

from jinja2 import Environment, FileSystemLoader
from ops.charm import CharmBase

NRPE_CFG = Path("/etc") / "nagios" / "nrpe.cfg"

import yaml

logger = logging.getLogger(__name__)


class NrpeUtils(CharmBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.monitors_relations = MonitorsRelation(self).get_data()
        self.principal_relation = PrincipalRelation(self)
        self.nagios_info = NagiosInfo(self)
        self.subordinate_definitions = SubordinateCheckDefinitions(self)

    def restart_nrpe(self):
        """Restart nrpe."""
        container = self.unit.get_container("nrpe-server")
        if container.get_service("nrpe-server").is_running():
            container.stop("nrpe-server")
        container.start("nrpe-server")

    def install_charm_files(self):
        """Install files shipped with charm."""
        nag_dirs = [
            "/etc/nagios/nrpe.d/",
            "/usr/local/lib/nagios/plugins",
            "/var/lib/nagios/export/",
        ]
        for nag_dir in nag_dirs:
            path = Path(nag_dir)
            if not path.exists():
                path.mkdir(mode=0o755)
        charm_file_dir = self.charm_dir / "files"
        pkg_plugin_dir = "/usr/lib/nagios/extra/"
        local_plugin_dir = "/usr/local/lib/nagios/plugins/"

        shutil.copy2(
            os.path.join(charm_file_dir, "nagios_plugin.py"),
            pkg_plugin_dir + "/nagios_plugin.py",
        )
        shutil.copy2(
            os.path.join(charm_file_dir, "nagios_plugin3.py"),
            pkg_plugin_dir + "/nagios_plugin3.py",
        )
        for nagios_plugin in ("nagios_plugin.py", "nagios_plugin3.py"):
            if not os.path.exists(local_plugin_dir + nagios_plugin):
                os.symlink(
                    pkg_plugin_dir + nagios_plugin, local_plugin_dir + nagios_plugin
                )

    def render_nrpe_config(self):
        env = Environment(loader=FileSystemLoader(self.charm_dir / "templates"))
        template = env.get_template("nrpe.tmpl")
        file = Path("/etc") / "nagios" / "nrpe.cfg"
        ctxt = {**self.config, **self.monitors_relations, **self.nagios_info}
        logger.debug("nrpe context %s", ctxt)
        with open(file, "w") as f_out:
            f_out.write(template.render(**ctxt))

    def render_nrpe_check_config(self, checkctxt):
        env = Environment(loader=FileSystemLoader(self.charm_dir / "templates"))
        template = env.get_template("nrpe_command.tmpl")

        """Write nrpe check definition."""
        # Only render if we actually have cmd parameters
        if checkctxt["cmd_params"]:
            file = (
                Path("/etc")
                / "nagios"
                / "nrpe.d"
                / "{}.cfg".format(checkctxt["cmd_name"])
            )
            with open(file, "w") as f_out:
                f_out.write(template.render(**checkctxt))

    def render_nrped_files(self):
        """Render each of the predefined checks."""
        for checkctxt in self.subordinate_definitions["checks"]:
            # Clean up existing files
            for fname in checkctxt["matching_files"]:
                try:
                    os.unlink(fname)
                except FileNotFoundError:
                    # Don't clean up non-existent files
                    pass
            self.render_nrpe_check_config(checkctxt)
        self.process_local_monitors()
        self.process_user_monitors()

    def process_user_monitors(self):
        """Collect the user defined local monitors from config."""
        if self.config["monitors"]:
            monitors = yaml.safe_load(self.config["monitors"])
        else:
            return
        try:
            local_user_checks = monitors["monitors"]["local"].keys()
        except KeyError as e:
            logger.info("no local monitors found in monitors config: %s", e)
            return
        for checktype in local_user_checks:
            for check in monitors["monitors"]["local"][checktype].keys():
                check_def = NRPECheckCtxt(
                    checktype, monitors["monitors"]["local"][checktype][check], "user"
                )
                self.render_nrpe_check_config(check_def)

    def process_local_monitors(self):
        """Get all the monitor dicts and write out and local checks."""
        monitor_dicts = self.monitors_relations.get_monitor_dicts()
        for monitor_src in monitor_dicts.keys():
            monitor_dict = monitor_dicts[monitor_src]
            if not (monitor_dict and "local" in monitor_dict["monitors"]):
                continue
            monitors = monitor_dict["monitors"]["local"]
            for checktype in monitors:
                for check in monitors[checktype]:
                    self.render_nrpe_check_config(
                        NRPECheckCtxt(
                            checktype,
                            monitors[checktype][check],
                            monitor_src,
                        )
                    )

    def update_nrpe_external_master_relation(self):
        """Update nrpe external master relation.

        Send updated nagios_hostname to charms attached
        to nrpe_external_master relation.
        """
        principal_relation = self.principal_relation
        for relation in self.model.relations["nrpe-external-master"]:
            for k, v in principal_relation.provide_data().items():
                logger.debug("relation.data[%s][%s] = %s", self.unit, k, v)
                relation.data[self.unit][k] = "{}".format(v)

    def update_monitor_relation(self):
        """Send updated monitor yaml to charms attached to monitor relation."""
        monitor_relation = self.monitors_relations
        for relation in self.model.relations["monitors"]:
            for k, v in monitor_relation.provide_data().items():
                logger.debug("relation.data[%s][%s] = %s", self.unit, k, v)
                relation.data[self.unit][k] = "{}".format(v)

    def has_consumer(self):
        """Check for the monitor relation or external monitor config."""
        return self.config["nagios_master"] not in ["None", "", None] or bool(
            self.model.relations["monitors"]
        )
