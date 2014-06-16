### How to read:
- JSON is inlined between { }.
- <> denotes substitution.
- [] denotes optionality.
- Everything else is taken literally.

Assume all requests are POSTed to /api.

### Anonymous APIs:
```
lookup (3): {
    "a": 3,
    "name": <name>
}
```
Where <name> is a name[@domain.com] ID. If the domain part is omittted, the 
server decides where to look up.

### "Authenticated" APIs:

"Authenticated" API payloads have the following format.
```
{
    "a": <action id>,
    "k": <the public key of the private key used to encrypt "e">,
    "e": <action-dependent payload, encrypted with crypto_box: see below (base64)>,
    "r": <a 24-byte nonce (base64)>
}
```
The following payloads are JSON strings encrypted with crypto_box, then encoded
to base64.

push (1): 
```
{
    "s": <public key + checksum (hex), which should be 68 characters>
    "n": <name>
    "l": <looseness level; if it's > 1 it appears in /friends>
    "b": <a bio string (cf https://toxme.se/friends/0, the bio appears in the speech bubbles)>
    "t": <the current UTC time as unix timestamp>
}
```

delete (2): 
```
{
    "p": <public key (64 chars hex)>
    "t": <the current UTC time as unix timestamp>
}
```

### Return values:

Returns take the form 
```
{
    "c": <error code>
}
```

Possible codes:
```
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
```

For lookup, information is included about the ID: 
```
{
    "version": "Tox V2 (local; requires PIN)",
    "source": 1, 
    "public_key": "56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE51855", 
    "c": 0, 
    "url": "tox://groupbot@toxme.se", 
    "name": "groupbot", 
    "regdomain": "toxme.se", 
    "verify": {
        "status": 1,
        "detail": "Good (signed by local authority)"
    }
}```
