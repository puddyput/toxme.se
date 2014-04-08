#!/usr/bin/env python3
"""
* Tox DNS Discovery Management Daemon - draft API server for Tox ID publishing.
* Since "Tox DNS Discovery Management Daemon" is a mouthful, just call it "yuu"
*
* Author: stal, stqism; April 2014
* Copyright (c) 2014 Zodiac Labs.
* You are free to do whatever you want with this file -- provided that this
* notice is retained.
"""
import tornado.escape
import tornado.ioloop
import tornado.httpserver
import tornado.web
import tornado.log
import tornado.template
import os
import json
import nacl.public as public
import nacl.encoding
import nacl.signing as signing
import nacl.exceptions
import nacl.utils
import logging
import database
import re

SIGNATURE_ENC = nacl.encoding.Base64Encoder
KEY_ENC = nacl.encoding.HexEncoder
STORE_ENC = nacl.encoding.HexEncoder

#pragma mark - constants

# Client didn't POST to /api
ERROR_METHOD_UNSUPPORTED = {"c": -1}
# Client is not using a secure connection
ERROR_NOTSECURE = {"c": -2}
# Bad encrypted payload (not encrypted with our key)
ERROR_BAD_PAYLOAD = {"c": -3}

ACTION_PUBLISH   = 1
ACTION_UNPUBLISH = 2

VALID_KEY = re.compile(r"[A-Fa-f0-9]{64}")

#pragma mark - logging

LOGGER = logging.getLogger("yuu")
tornado.log.enable_pretty_logging()

#pragma mark - crypto

class CryptoCore(object):
    def __init__(self):
        """Load or initialize crypto keys."""
        try:
            with open("key", "rb") as keys_file:
                keys = keys_file.read()
        except IOError:
            keys = None
        if keys:
            self.pkey = public.PrivateKey(keys, STORE_ENC)
            self.skey = signing.SigningKey(keys, STORE_ENC)
        else:
            kp = public.PrivateKey.generate()
            with open("key", "wb") as keys_file:
                keys_file.write(kp.encode(STORE_ENC))
            self.pkey = kp
            self.skey = signing.SigningKey(bytes(self.pkey),
                                           nacl.encoding.RawEncoder)

    def sign(self, text):
        return self.skey.sign(text, encoder=SIGNATURE_ENC).decode("utf8")

    @property
    def public_key(self):
        return self.pkey.public_key.encode(KEY_ENC).decode("utf8").upper()

#pragma mark - web

class OpaqueAPIEndpoint(tornado.web.RequestHandler):
    def get(self):
        self.write(ERROR_METHOD_UNSUPPORTED)

    def post(self):
        if self.request.protocol != "https":
            self.set_status(400)
            self.write(ERROR_NOTSECURE)
            return

        try:
            envelope = self.request.body.decode("utf8")
            envelope = json.loads(envelope)
        except (UnicodeDecodeError, TypeError):
            LOGGER.warn("did fail req because json decode failed")
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            return

        LOGGER.info("Notice: {0}".format(envelope))
        
        action = envelope.get("a")
        if action is None:
            LOGGER.warn("did fail req because there is no a param")
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            return
        elif action == ACTION_PUBLISH:
            for key in ("k", "r", "e"):
                if key not in envelope:
                    LOGGER.warn("did fail req because json contents are bad")
                    self.set_status(400)
                    self.write(ERROR_BAD_PAYLOAD)
                    return
            
            if not VALID_KEY.match(envelope.get("k", "")):
                LOGGER.warn("did fail req because pk was bad")
                self.set_status(400)
                self.write(ERROR_BAD_PAYLOAD)
                return
            
            other_key = public.PublicKey(envelope["k"], KEY_ENC)
            box = public.Box(self.settings["cryptocore"].pkey,
                             other_key)
            
            try:
                nonce = nacl.encoding.Base64Encoder.decode(envelope["r"])
                ciphertext = nacl.encoding.Base64Encoder.decode(envelope["e"])
                if len(nonce) != public.Box.NONCE_SIZE:
                    raise ValueError("bad nonce")
            except (ValueError, TypeError):
                LOGGER.warn("did fail req because a base64 value was bad")
                self.set_status(400)
                self.write(ERROR_BAD_PAYLOAD)
                return
            
            try:
                clear = box.decrypt(ciphertext, nonce, nacl.encoding.RawEncoder)
            except nacl.exceptions.CryptoError:
                LOGGER.warn("did fail req because decrypting e failed")
                self.set_status(400)
                self.write(ERROR_BAD_PAYLOAD)
                return

            LOGGER.info("Notice: {0}".format(clear))
            

class PublicKey(tornado.web.RequestHandler):
    def get(self):
        if self.request.protocol != "https":
            self.write(ERROR_NOTSECURE)
        else:
            self.write({
                "c": 0,
                "key": self.settings["cryptocore"].public_key
            })

def main():
    with open("config.json", "r") as config_file:
        cfg = json.load(config_file)
    
    crypto = CryptoCore()
    dbh = database.Database(cfg["database_url"])
    LOGGER.info("Notice: PK: {0}".format(
        crypto.public_key
    ))
    
    ioloop = tornado.ioloop.IOLoop.instance()
    app = tornado.web.Application(
        [("/api", OpaqueAPIEndpoint),
         ("/pk", PublicKey),
         ],
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        cryptocore=crypto,
        database=dbh
    )
    if "ssl_options" in cfg:
        server = tornado.httpserver.HTTPServer(app,
                                               ssl_options=cfg["ssl_options"],
                                               xheaders=cfg.get("is_proxied"))
    else:
        server = tornado.httpserver.HTTPServer(app,
                                               xheaders=cfg.get("is_proxied"))
    server.listen(cfg["server_port"], cfg["server_addr"])
    if "pid_file" in cfg:
        with open(cfg["pid_file"], "w") as pid:
            pid.write(str(os.getpid()))
    LOGGER.info("Notice: listening on {0}:{1}".format(
        cfg["server_addr"], cfg["server_port"]
    ))
    
    try:
        ioloop.start()
    finally:
        os.remove(cfg["pid_file"])

if __name__ == "__main__":
    main()
