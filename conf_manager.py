"""Functions for reading and parsing config files"""

import logging

import helpers

log = logging.getLogger(__name__)

def load(path):
    """Read config file"""
    log.debug("Opening config file %s", path)
    try:
        with open(path, 'r', encoding='utf-8') as file:
            conf = file.readlines()
    except OSError:
        log.critical("Can't open config file %s", path)
    log.debug("Read config: \n%s\n", helpers.to_json(conf))
    return conf

def parse(conf):
    """Parse config string"""
    parsed = {}
    key = ""
    cookies = None
    reading_cookie = False
    for line in conf:
        line = line.strip()
        log.debug("Reading line %s", line)
        if line:
            if line[0] == '[' and line[-1] == ']':
                key = line[1:-1].strip().lower()
                log.debug("Key found %s", key)
            else:
                if not key:
                    log.error("Expected line [key] first, found %s, skipping",
                            line)
                    continue
                try:
                    param, val = line.split("=")
                except ValueError:
                    log.warning("Too many values in %s, skipping", line)
                    continue
                param = param.strip().lower()
                if param == "cookie":
                    log.debug("Cookies start")
                    reading_cookie = True
                    cookies = {}
                    continue
                val = val.strip().lower()
                if not param:
                    log.error("Parameter missed %s, skipping", param)
                    continue
                if not val:
                    log.error("Parameter %s requares a value, skipping",
                            param)
                    continue
                if reading_cookie:
                    cookies[param] = val
                    log.debug("Cookie added %s=%s", param, val)
                else:
                    parsed.setdefault(key, {})[param] = val
                    log.debug("Add pair (%s, %s) to conf dict", param, val)
                    log.debug("Pairs in dict %s",
                            helpers.to_json(parsed[key]))
        elif reading_cookie:
            reading_cookie = False
            parsed.setdefault(key,{})['cookie'] = cookies
            cookies = None
            log.debug("Cookies end")
            log.debug("Read cookies: \n%s\n",
                    helpers.to_json(parsed[key]['cookie']))
    log.debug("Done parsing conf, conf: \n%s\n", helpers.to_json(parsed))
    return parsed
