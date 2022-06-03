"""Helper functions"""

import json

def to_json(dct):
    """Convert to dict to pretty json for output"""
    return json.dumps(json.loads(str(dct).replace('\'', '"')), indent=2)
