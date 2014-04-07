#!/usr/bin/env python3
"""
* Tox DNS Discovery Management Daemon - draft API server for Tox ID publishing.
* Since "Tox DNS Discovery Management Daemon" is a mouthful, just call it "yuu"
*
* Author: stal, April 2014
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
import nacl.public
import nacl.encoding
import nacl.signing
import nacl.utils
import logging
import database

#pragma mark - constants

# Client didn't POST to /api
ERROR_METHOD_UNSUPPORTED = {"c": -1}
# Client is not using a secure connection
ERROR_NOTSECURE = {"c": -2}
# Bad encrypted payload (not encrypted with our key)
ERROR_BAD_PAYLOAD = {"c": -3}

#pragma mark - logging

LOGGER = logging.getLogger("yuu")
tornado.log.enable_pretty_logging()

#pragma mark - crypto

class crypto():
    def init(self):
        """Load or initialize crypto keys."""
        try:
            with open("key", "rb") as keys_file:
                keys = keys_file.read()
        except IOError:
            keys = None
        if keys:
            return nacl.public.PrivateKey(keys, nacl.encoding.RawEncoder)
        else:
            kp = nacl.public.PrivateKey.generate()
            with open("key", "wb") as keys_file:
                keys_file.write(bytes(kp))
            return kp

    def sign(self,publickey, check=None):
        #Check if tox1 or tox2
        if check:
           text = self.publickey + self.check
        else:
           text = self.publickey

        signkey = nacl.signing.SigningKey(cfg["secretkey"], encoder=nacl.encoding.HexEncoder) 
        record = ";sign:" + signkey.sign(text, encoder=nacl.encoding.Base64Encoder)

        return record

    def sign_getpub(self):

        signkey = nacl.signing.SigningKey(cfg["secretkey"], encoder=nacl.encoding.HexEncoder)
        return signkey.verify_key(encoder=nacl.encoding.HexEncoder)

#pragma mark - web

class recorddata:

    def gentox1(self, toxid):
        entry = "v=tox1;id=" + self.toxid + crypto.sign(self.toxid)
        return entry

    def gentox2(self, publickey, check):
        entry = "v=tox2;pub=" + self.publickey + ";check=" + self.check + crypto.sign(self.publickey, self.check)
        return entry

    def gensigning(self):
        entry = crypto.sign_getpub()

class OpaqueAPIEndpoint(tornado.web.RequestHandler):
    def get(self):
        self.write(ERROR_METHOD_UNSUPPORTED)

    def post(self):
        if self.request.protocol != "https":
            self.write(ERROR_NOTSECURE)
        

class PublicKey(tornado.web.RequestHandler):
    def get(self):
        if self.request.protocol != "https":
            self.write(ERROR_NOTSECURE)
        else:
            self.write({
                "c": 0,
                "key": self.settings["yuu_key"].encode(nacl.encoding.HexEncoder)
                                               .decode("ascii")
            })

def main():
    with open("config.json", "r") as config_file:
        cfg = json.load(config_file)
    
    key = crypto().init
    dbh = database.Database(cfg["database_url"])
    LOGGER.info("Notice: PK: {0}".format(
        key.encode(nacl.encoding.HexEncoder).decode("ascii"))
    )
    
    ioloop = tornado.ioloop.IOLoop.instance()
    app = tornado.web.Application(
        [("/api", OpaqueAPIEndpoint),
         ("/pk", PublicKey),
         ],
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        yuu_key=key
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
