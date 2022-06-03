"""Main loop for monitor role"""

import logging

import helpers

def start(conf):
    """Main loop"""
    log = logging.getLogger(__name__)
    log.debug("Starting monitor loop with conf: \n%s\n", helpers.to_json(conf))
