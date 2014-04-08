#!/usr/bin/env python
# coding: utf8
"""
* Tox DNS Discovery Management Daemon - draft API server for Tox ID publishing.
* Since "Tox DNS Discovery Management Daemon" is a mouthful, just call it "yuu"
*
* Author: stal, stqism; April 2014
* Copyright (c) 2014 Zodiac Labs.
* You are free to do whatever you want with this file -- provided that this
* notice is retained.
"""
from __future__ import print_function
import traceback
import sys
import requests
import json
import nacl.public as crypto
import nacl.encoding as crypto_encode
import os

ENDPOINT = "https://[::1]:8000"

def err_notexist(s):
    print("\033[31mError\033[0m: test [{0}] does not exist.".format(s))

def err_fail(s):
    print("\033[31mError\033[0m: test [{0}] failed!".format(s))

###

def harutest_badpayload():
    payload = json.dumps({"test": "hello world"})
    r = requests.post(ENDPOINT + "/api", data=payload, verify=False)
    print(r.text)
    assert r.json()["c"] == -3, "unexpected response"

def _hexkey(k):
    return k.public_key.encode(crypto_encode.HexEncoder).decode("utf8")

def harutest_publish():
    pkr = requests.get(ENDPOINT + "/pk", verify=False)
    sk = pkr.json()["key"]
    
    k = crypto.PrivateKey.generate()
    inner = json.dumps({
        "s": "00000000",
        "n": "test",
        "l": 0
    })
    nonce = os.urandom(crypto.Box.NONCE_SIZE)
    b = crypto.Box(k, crypto.PublicKey(sk, crypto_encode.HexEncoder))
    msg = b.encrypt(inner.encode("utf8"), nonce, crypto_encode.Base64Encoder)
    
    payload = json.dumps({
        "a": 1,
        "k": _hexkey(k)[:64],
        "e": msg.ciphertext.decode("utf8"),
        "r": crypto_encode.Base64Encoder.encode(nonce).decode("utf8")
    })
    requests.post(ENDPOINT + "/api", data=payload, verify=False)

def harutest_bad_ep():
    pkr = requests.get(ENDPOINT + "/pk", verify=False)
    sk = pkr.json()["key"]
    print("Server:", sk)

    print("1/3: non-ascii in e")
    payload = json.dumps({
        "a": 1,
        "k": "0" * 64,
        "e": u"あああああああぁぁぁぁぁ。。。",
        "r": u"1QUhJIffiMMfrGqf6nMatxeIfGTywnzT"
    })
    rsp = requests.post(ENDPOINT + "/api", data=payload, verify=False)
    if rsp.json()["c"] != -3 or rsp.status_code != 400:
        raise Exception("server did not properly fail the request")

    print("2/3: bad nonce length")
    payload = json.dumps({
        "a": 1,
        "k": "0" * 64,
        "e": u"aabababababababababa",
        "r": u"aaaa"
    })
    rsp = requests.post(ENDPOINT + "/api", data=payload, verify=False)
    if rsp.json()["c"] != -3 or rsp.status_code != 400:
        raise Exception("server did not properly fail the request")

    print("3/3: missing values")
    payload = json.dumps({
        "a": 1,
        "e": u"aabababababababababa",
        "r": u"aaaa"
    })
    rsp = requests.post(ENDPOINT + "/api", data=payload, verify=False)
    if rsp.json()["c"] != -3 or rsp.status_code != 400:
        raise Exception("server did not properly fail the request")

###

def haruka():
    for s in sys.argv[1:]:
        print("Running test [{0}]...".format(s))
        try:
            runner = globals().get("harutest_{0}".format(s))
            if not runner:
                err_notexist(s)
                continue
            runner()
        except Exception:
            err_fail(s)
            print("Post-mortem: {0}".format(traceback.format_exc()))
        else:
            print("\033[32mPass\033[0m: {0}".format(s))

if __name__ == "__main__":
    haruka()