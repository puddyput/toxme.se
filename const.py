import re
import nacl.encoding
import logging

ID_HEX = re.compile(r"([A-F0-9][A-F0-9])")
RECORD_DEFAULT = 0
RECORD_TOXV1   = 1
RECORD_TOXV2   = 2

# How many users to cache in the existence cache (max).
PRESENCE_CACHE_CEILING = 1000

SIGNATURE_ENC = nacl.encoding.Base64Encoder
KEY_ENC = nacl.encoding.HexEncoder
STORE_ENC = nacl.encoding.HexEncoder

ERROR_OK = {"c": 0}
# Client didn't POST to /api
ERROR_METHOD_UNSUPPORTED = {"c": -1}
# Client is not using a secure connection
ERROR_NOTSECURE = {"c": -2}
# Bad encrypted payload (not encrypted with our key)
ERROR_BAD_PAYLOAD = {"c": -3}
ERROR_NAME_TAKEN = {"c": -25}
ERROR_DUPE_ID = {"c": -26}
ERROR_LOOKUP_FAILED = {"c": -41}
ERROR_NO_USER = {"c": -42}
ERROR_LOOKUP_INTERNAL = {"c": -43}

ACTION_PUBLISH   = 1
ACTION_UNPUBLISH = 2
ACTION_LOOKUP    = 3

VALID_KEY = re.compile(r"^[A-Fa-f0-9]{64}$")
VALID_ID  = re.compile(r"^[A-Fa-f0-9]{68}$")
DJB_SPECIAL = re.compile(r"([;=])")

DISALLOWED_CHARS = set(" ./")
DISALLOWED_NAMES = {"lookup", "pk", "api", "__yuu_cache"}
NAME_LIMIT_HARD  = 63 # DNS requirement

SIGNSTATUS_GOOD      = 1
SIGNSTATUS_BAD       = 2
SIGNSTATUS_UNDECIDED = 3

SOURCE_LOCAL  = 1
SOURCE_REMOTE = 2

#pragma mark - logging

LOGGER = logging.getLogger("yuu")
