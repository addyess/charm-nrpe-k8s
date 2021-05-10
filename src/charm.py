#!/usr/bin/env python3
# Copyright 2021 Adam Dyess
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service."""

import logging
import urllib

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus

logger = logging.getLogger(__name__)


class NrpeCharm(CharmBase):
    state = StoredState()

    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.state.set_default(allowed_hosts=[])

    def _on_install(self, _):
        pass

    def _on_config_changed(self, event):
        """Handle the config-changed event"""
        # Get the nrpe-server container so we can configure/manipulate it
        container = self.unit.get_container("nrpe-server")
        # Create a new config layer
        layer = self._nrpe_server_layer()
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
            # Restart it and report a new status to Juju
            container.start("nrpe-server")
            logging.info("Restarted nrpe-server service")
        # All is well, set an ActiveStatus
        self.unit.status = ActiveStatus()

    def _nrpe_server_layer(self):
        """Returns a Pebble configuration layer for nrpe-server"""
        return {
            "summary": "nrpe-server layer",
            "description": "pebble config layer for nrpe-server",
            "services": {
                "nrpe-server": {
                    "override": "replace",
                    "summary": "nrpe-server",
                    "command": "/nrpe-runner",
                    "startup": "enabled",
                    "environment": {
                        "ALLOWEDHOSTS": ",".join(self.state.allowed_hosts),
                        "PORT": self.config["server_port"],
                        "SSL": False,
                    },
                }
            },
        }


if __name__ == "__main__":
    main(NrpeCharm)
