#!/usr/bin/env python3
# Copyright 2021 Adam Dyess
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service."""

import logging
from typing import Any, Tuple

from ops.charm import RelationChangedEvent, ConfigChangedEvent, StartEvent
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

from nrpe_utils import NrpeUtils

logger = logging.getLogger(__name__)


class NrpeCharm(NrpeUtils):
    """Charm the service."""

    state = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

        self.framework.observe(
            self.on.monitors_relation_changed, self._on_monitors_relation_changed
        )
        self.framework.observe(
            self.on.monitors_relation_departed, self._on_monitors_relation_departed
        )

        self.state.set_default(nrpe_ssl=False)

    def _on_start(self, _):
        self.unit.status = MaintenanceStatus("starting")

    def _on_install(self, _):
        self.install_charm_files()

    def _on_monitors_relation_joined(self, _):
        self.update_monitor_relation()

    def _on_monitors_relation_changed(self, _):
        self._do_config_change()

    def _on_monitors_relation_departed(self, _):
        self._do_config_change()

    def _on_config_changed(self, _):
        self._do_config_change()

    def _do_config_change(self):
        """Handle the config-changed event"""
        # Get the nrpe-server container so we can configure/manipulate it
        container = self.unit.get_container("nrpe-server")
        # Write config to file
        self.render_nrpe_config()
        self.render_nrped_files()
        self.update_monitor_relation()
        self.update_nrpe_external_master_relation()

        # Create a new config layer
        enabled, layer = self._nrpe_server_layer()
        # Get the current config
        services = container.get_plan().to_dict().get("services", {})
        # Check if there are any changes to services
        if services != layer["services"]:
            # Changes were made, add the new layer
            container.add_layer("nrpe-server", layer, combine=True)
            logging.info("Added updated layer 'nrpe-server' to Pebble plan")
            # Stop the service if it is already running
            if container.get_service("nrpe-server").is_running():
                container.stop("nrpe-server")
            if enabled:
                # Restart it and report a new status to Juju
                container.start("nrpe-server")
                logging.info("Restarted nrpe-server service")
        # All is well, set an ActiveStatus
        if enabled:
            self.unit.status = ActiveStatus("Ready")
        else:
            self.unit.status = BlockedStatus("Nagios server not configured or related")

    def _nrpe_server_layer(self) -> Tuple[bool, Any]:
        """Returns a Pebble configuration layer for nrpe-server"""
        enabled = self.has_consumer()
        allowed_hosts = [
            self.monitors_relations['monitor_allowed_hosts'],
            self.nagios_info["external_nagios_master"]
        ]
        return enabled, {
            "summary": "nrpe-server layer",
            "description": "pebble config layer for nrpe-server",
            "services": {
                "nrpe-server": {
                    "override": "replace",
                    "summary": "nrpe-server",
                    "command": "/nrpe-runner",
                    "startup": "enabled" if enabled else "disabled",
                    "environment": {
                        "ALLOWEDHOSTS": ",".join(allowed_hosts),
                        "PORT": self.config["server_port"],
                        "SSL": "yes" if self.state.nrpe_ssl else "",
                    },
                }
            },
        }


if __name__ == "__main__":
    main(NrpeCharm)
