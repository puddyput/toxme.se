"""
* error_codes.py
* Author: stal, stqism; April 2014
* Copyright (c) 2014 Zodiac Labs.
* Further licensing information: see LICENSE.
"""

ERROR_OK = {"c": 0}

# Client didn't POST to /api
ERROR_METHOD_UNSUPPORTED = {"c": -1, "f" : "Client didn't POST to /api"}

# Client is not using a secure connection
ERROR_NOTSECURE = {"c": -2, "f" : "Client is not using a secure connection"}

# Bad encrypted payload (not encrypted with our key)
ERROR_BAD_PAYLOAD = {"c": -3, "f" : "Bad encrypted payload (not encrypted with our key)"}

# Name is taken.
ERROR_NAME_TAKEN = {"c": -25, "f" : "Name is taken"}

# The public key given is bound to a name already.
ERROR_DUPE_ID = {"c": -26, "f" : "The public key given is bound to a name already."}

# Lookup failed because of an error on the other domain's side.
ERROR_LOOKUP_FAILED = {"c": -41, "f" : "Lookup failed because of an error on the other domain's side."}

# Lookup failed because that user doesn't exist on the domain
ERROR_NO_USER = {"c": -42, "f" : "Lookup failed because that user doesn't exist on the domain"}

# Lookup failed because of an error on our side.
ERROR_LOOKUP_INTERNAL = {"c": -43, "f" : "Lookup failed because of an error on our side."}

# Client is publishing IDs too fast
ERROR_RATE_LIMIT = {"c": -4, "f" : "Client is publishing IDs too fast"}