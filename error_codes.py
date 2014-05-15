"""
* error_codes.py
* Author: stal, stqism; April 2014
* Copyright (c) 2014 Zodiac Labs.
* Further licensing information: see LICENSE.
"""

ERROR_OK = {"c": 0}

# Client didn't POST to /api
ERROR_METHOD_UNSUPPORTED = {"c": -1}

# Client is not using a secure connection
ERROR_NOTSECURE = {"c": -2}

# Bad encrypted payload (not encrypted with our key)
ERROR_BAD_PAYLOAD = {"c": -3}

# Name is taken.
ERROR_NAME_TAKEN = {"c": -25}

# The public key given is bound to a name already.
ERROR_DUPE_ID = {"c": -26}

# Lookup failed because of an error on the other domain's side.
ERROR_LOOKUP_FAILED = {"c": -41}

# Lookup failed because that user doesn't exist on the domain
ERROR_NO_USER = {"c": -42}

# Lookup failed because of an error on our side.
ERROR_LOOKUP_INTERNAL = {"c": -43}

# Client is publishing IDs too fast
ERROR_RATE_LIMIT = {"c": -4}