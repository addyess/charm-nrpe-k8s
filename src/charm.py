#!/usr/bin/env python3
# Copyright 2021 Adam Dyess
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service."""

import logging
import urllib

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus

logger = logging.getLogger(__name__)


class NrpeCharm(CharmBase):
    """Charm the service."""
    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    def _on_install(self, _):
        pass

    def _on_config_changed(self, event):
        """Handle the config-changed event"""



if __name__ == "__main__":
    main(NrpeCharm)
