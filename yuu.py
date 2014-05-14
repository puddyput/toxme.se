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
import tornado.ioloop
import tornado.httpserver
import tornado.web
import tornado.log
import os
import json
import nacl.public as public
import nacl.signing as signing
import nacl.encoding
import nacl.exceptions
import database
import datetime
import time
import logging
import re
import urllib.parse as parse
from collections import Counter, defaultdict

import error_codes
import barcode
import dns_discovery
import hooks

tornado.log.enable_pretty_logging()
LOGGER = logging.getLogger("yuu")

ACTION_PUBLISH   = 1
ACTION_UNPUBLISH = 2
ACTION_LOOKUP    = 3
INVOKABLE_ACTIONS = {ACTION_PUBLISH, ACTION_UNPUBLISH, ACTION_LOOKUP}
THROTTLE_THRESHOLD = 5

VALID_KEY = re.compile(r"^[A-Fa-f0-9]{64}$")
VALID_ID  = re.compile(r"^[A-Fa-f0-9]{68}$")
VALID_ANY = re.compile(r"^[A-Fa-f0-9]+$")
REMOVE_NEWLINES = re.compile("[\r\n]+")
DISALLOWED_CHARS = set(" @/:;()\"'")
DISALLOWED_NAMES = {}
NAME_LIMIT_HARD  = 63
BIO_LIMIT        = 250 # fixme this should be configurable

ENTRIES_PER_PAGE = 10

#pragma mark - crypto

SIGNATURE_ENC = nacl.encoding.Base64Encoder
KEY_ENC = nacl.encoding.HexEncoder
STORE_ENC = nacl.encoding.HexEncoder

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

    def sign(self, uobj):
        e = nacl.encoding.HexEncoder
        pubkey = e.decode(uobj.public_key)
        checksum = e.decode(uobj.checksum)
        name = uobj.name.encode("utf8")

        text = b"".join((name, pubkey, checksum))
        return self.skey.sign(text, encoder=SIGNATURE_ENC).decode("utf8")

    @property
    def public_key(self):
        return self.pkey.public_key.encode(KEY_ENC).decode("utf8").upper()

    @property
    def verify_key(self):
        return self.skey.verify_key.encode(KEY_ENC).decode("utf8").upper()

#pragma mark - web

class HTTPSPolicyEnforcer(tornado.web.RequestHandler):
    def _fail(self):
        self.set_status(400)
        self.write(error_codes.ERROR_NOTSECURE)
        return ""

    post = get = _fail

class APIHandler(tornado.web.RequestHandler):
    @staticmethod
    def _typecheck_dict(envelope, expect):
        for key, value in expect.items():
            if not isinstance(envelope.get(key), value):
                LOGGER.warn("typecheck failed on json")
                return 0
        return 1

    def _encrypted_payload_prologue(self, envelope):
        if not self._typecheck_dict(envelope, {"k": str, "r": str, "e": str}):
            self.set_status(400)
            self.write(error_codes.ERROR_BAD_PAYLOAD)
            return
        try:
            other_key = public.PublicKey(envelope["k"], KEY_ENC)
        except nacl.exceptions.CryptoError:
            LOGGER.warn("did fail req because other pk was bad")
            self.set_status(400)
            self.write(error_codes.ERROR_BAD_PAYLOAD)
            return

        box = public.Box(self.settings["crypto_core"].pkey, other_key)

        try:
            nonce = nacl.encoding.Base64Encoder.decode(envelope["r"])
            ciphertext = nacl.encoding.Base64Encoder.decode(envelope["e"])
            clear = box.decrypt(ciphertext, nonce, nacl.encoding.RawEncoder)
        except (ValueError, TypeError, nacl.exceptions.CryptoError):
            LOGGER.warn("did fail req because a base64 value was bad")
            self.set_status(400)
            self.write(error_codes.ERROR_BAD_PAYLOAD)
            return

        try:
            clear = json.loads(clear.decode("utf8"))
        except (UnicodeDecodeError, TypeError):
            LOGGER.warn("did fail req because inner json decode failed")
            self.set_status(400)
            self.write(error_codes.ERROR_BAD_PAYLOAD)
            return
        return clear

    def update_db_entry(self, auth, name, pub, bio, check, privacy, pin=None):
        dbc = self.settings["local_store"]
        with dbc.lock:
            session, owner_of_cid = dbc.get_by_id_ig(pub)
            if owner_of_cid and owner_of_cid.name != name:
                session.close()
                self.set_status(400)
                self.write(error_codes.ERROR_DUPE_ID)
                return 0
        
            session, mus = dbc.get_ig(name, session)
            if not mus:
                mus = database.User()
            elif mus.public_key != auth:
                session.close()
                self.set_status(400)
                self.write(error_codes.ERROR_NAME_TAKEN)
                return 0
        
            mus.name = name
            mus.public_key = pub
            mus.checksum = check
            mus.privacy = privacy
            mus.timestamp = datetime.datetime.now()
            mus.sig = self.settings["crypto_core"].sign(mus)
            mus.bio = bio
            mus.pin = pin
            ok = dbc.update_atomic(mus, session)
            if not ok:
                session.close()
                self.set_status(400)
                self.write(error_codes.ERROR_DUPE_ID)
                return 0
            hooks.did_update_record(database.StaleUser(mus))
            session.close()
        return 1


class APIUpdateName(APIHandler):
    def initialize(self, envelope):
        self.envelope = envelope

    def post(self):
        ctr = self.settings["address_ctr"][ACTION_PUBLISH]
        if ctr["clear_date"][self.request.remote_ip] < time.time():
            del ctr["counter"][self.request.remote_ip]
            del ctr["clear_date"][self.request.remote_ip]
        ctr["counter"][self.request.remote_ip] += 1
        # Clears in one hour
        ctr["clear_date"][self.request.remote_ip] = time.time() + 3600
        
        if ctr["counter"][self.request.remote_ip] > THROTTLE_THRESHOLD:
            self.set_status(400)
            self.write(error_codes.ERROR_RATE_LIMIT)
            return
        
        clear = self._encrypted_payload_prologue(self.envelope)
        if not clear:
            return

        if not self._typecheck_dict(clear, {"s": str, "n": str,
                                            "t": int, "l": int, "b": str}):
            self.set_status(400)
            self.write(error_codes.ERROR_BAD_PAYLOAD)
            return

        auth = self.envelope["k"].upper()
        id_ = clear["s"].upper()
        name = clear["n"].lower()
        bio = REMOVE_NEWLINES.sub(" ", clear["b"].strip())
        ctime = int(time.time())

        if (not VALID_ID.match(id_)
            or not set(name).isdisjoint(DISALLOWED_CHARS)
            or abs(ctime - clear["t"]) > 300 or name in DISALLOWED_NAMES
            or len(name) > NAME_LIMIT_HARD
            or len(bio) > BIO_LIMIT):
            self.set_status(400)
            self.write(error_codes.ERROR_BAD_PAYLOAD)
            return

        pub, check = id_[:64], id_[64:]

        if self.update_db_entry(auth, name, pub, bio, check, max(clear["l"], 0)):
            self.write(error_codes.ERROR_OK)
        return

class APIReleaseName(APIHandler):
    def initialize(self, envelope):
        self.envelope = envelope

    def post(self):
        clear = self._encrypted_payload_prologue(self.envelope)
        if not clear:
            return

        ctime = int(time.time())
        pk = clear.get("p", "").upper()
        if not VALID_KEY.match(pk) or abs(ctime - clear.get("t", 0)) > 300:
            self.set_status(400)
            self.write(error_codes.ERROR_BAD_PAYLOAD)
            return

        rec = self.settings["local_store"].get_by_id_ig(pk)[1]
        old = database.StaleUser(rec)
        self.settings["local_store"].delete_pk(pk)
        self.write(error_codes.ERROR_OK)
        hooks.did_delete_record(old)
        return

class APILookupID(tornado.web.RequestHandler):
    def initialize(self, envelope):
        self.envelope = envelope

    def _results(self, result):
        self.set_status(200 if result["c"] == 0 else 400)
        self.write(result)
        self.finish()

    def _build_local_result(self, name):
        rec = self.settings["local_store"].get(name)
        if not rec:
            return error_codes.ERROR_NO_USER
        base_ret = {
            "c": 0,
            "name": rec.name,
            "regdomain": self.settings["home"],
            "public_key": rec.public_key,
            "url": "tox://{0}@{1}".format(rec.name, self.settings["home"]),
            "verify": {
                "status": dns_discovery.SIGNSTATUS_GOOD,
                "detail": "Good (signed by local authority)",
            },
            "source": dns_discovery.SOURCE_LOCAL,
            "version": "Tox V2 (local; requires PIN)"
        }
        return base_ret

    @tornado.web.asynchronous
    def post(self):
        name = self.envelope.get("name").lower()
        if not name or name.endswith("@") or name.startswith("@"):
            self.set_status(400)
            self.write(error_codes.ERROR_BAD_PAYLOAD)
            self.finish()
            return
        if "@" not in name:
            name = "@".join((name, self.settings["home"]))
        user, domain = name.rsplit("@", 1)
        if domain == self.settings["home"]:
            self._results(self._build_local_result(user))
            return
        else:
            self.settings["lookup_core"].dispatch_lookup(name, self._results)

class APIFailure(tornado.web.RequestHandler):
    def post(self):
        self.set_status(400)
        self.write(error_codes.ERROR_BAD_PAYLOAD)
        return

def _make_handler_for_api_method(application, request, **kwargs):
    if request.protocol != "https":
        return HTTPSPolicyEnforcer(application, request, **kwargs)

    try:
        envelope = request.body.decode("utf8")
        envelope = json.loads(envelope)
        if envelope.get("a", -1) not in INVOKABLE_ACTIONS:
            raise TypeError("blah blah blah exceptions are flow control")
    except (UnicodeDecodeError, TypeError):
        LOGGER.warn("failing request because of an invalid first payload")
        return APIFailure(application, request, **kwargs)

    action = envelope.get("a")
    if action == ACTION_PUBLISH:
        return APIUpdateName(application, request, envelope=envelope)
    elif action == ACTION_UNPUBLISH:
        return APIReleaseName(application, request, envelope=envelope)
    elif action == ACTION_LOOKUP:
        return APILookupID(application, request, envelope=envelope)

class PublicKey(tornado.web.RequestHandler):
    def get(self):
        if self.request.protocol != "https":
            self.write(error_codes.ERROR_NOTSECURE)
        else:
            self.write({
                "c": 0,
                "key": self.settings["crypto_core"].public_key
            })

class CreateQR(tornado.web.RequestHandler):
    def _fail(self):
        self.set_status(404)
        return

    def get(self, path_id):
        if self.request.protocol != "https":
            self.write(error_codes.ERROR_NOTSECURE)
            return
        name = (parse.unquote(path_id) if path_id else "").lower()
        if not name or not set(name).isdisjoint(DISALLOWED_CHARS):
            return self._fail()
        rec = self.settings["local_store"].get(name)
        if not rec:
            return self._fail()

        self.set_header("Cache-Control", "public; max-age=86400")
        self.set_header("Content-Type", "image/svg+xml; charset=utf-8")
        self.write(barcode.QRImage.get("@".join((name, self.settings["home"]))))
        return

class LookupAndOpenUser(tornado.web.RequestHandler):
    def _user_id(self):
        spl = self.request.host.rsplit(".", 1)[0]
        if spl == self.request.host:
            return None
        else:
            return spl

    def _render_open_user(self, name):
        if not name or not set(name).isdisjoint(DISALLOWED_CHARS):
            self.set_status(404)
            self.render("fourohfour.html", record=name,
                        realm=self.settings["home"])
            return

        rec = self.settings["local_store"].get(name)
        if not rec:
            self.set_status(404)
            self.render("fourohfour.html", record=name,
                        realm=self.settings["home"])
            return

        self.render("onemomentplease.html", record=rec,
                    realm=self.settings["home"])

    def _lookup_home(self):
        self.render("lookup_home.html")

    def get(self, path_id=None):
        if self.request.protocol != "https":
            self.write(error_codes.ERROR_NOTSECURE)
            return
        name = (parse.unquote(path_id) if path_id else "").lower()
        if name:
            return self._render_open_user(name)
        else:
            return self._lookup_home()

class FindFriends(tornado.web.RequestHandler):
    def _render_page(self, num):
        num = int(num)
        results = self.settings["local_store"].get_page(num,
                                                        ENTRIES_PER_PAGE)
        if not results:
            self.set_status(404)
            self.render("fourohfour.html", record="",
                        realm=self.settings["home"])
            return
        self.render("public_userlist.html", results_set=results,
                    realm=self.settings["home"],
                    next_page=(None if len(results) < ENTRIES_PER_PAGE
                                    else num + 1),
                    previous_page=(num - 1) if num > 0 else None)
    
    def get(self, page):
        if self.request.protocol != "https":
            self.write(error_codes.ERROR_NOTSECURE)
            return
        
        return self._render_page(page)

class AddKeyWeb(APIHandler):
    def get(self):
        if self.request.protocol != "https":
            self.write(error_codes.ERROR_NOTSECURE)
            return
        self.render("add_ui.html")

    def post(self):
        if self.request.protocol != "https":
            self.write(error_codes.ERROR_NOTSECURE)
            return

        ctr = self.settings["address_ctr"][ACTION_PUBLISH]
        if ctr["clear_date"][self.request.remote_ip] < time.time():
            del ctr["counter"][self.request.remote_ip]
            del ctr["clear_date"][self.request.remote_ip]
        ctr["counter"][self.request.remote_ip] += 1
        # Clears in one hour
        ctr["clear_date"][self.request.remote_ip] = time.time() + 3600

        if ctr["counter"][self.request.remote_ip] > THROTTLE_THRESHOLD:
            self.set_status(400)
            return

        name = self.get_body_argument("name").lower()
        if (not DISALLOWED_CHARS.isdisjoint(set(name))
            or name in DISALLOWED_NAMES):
            print("1")
            self.set_status(400)
            return

        bio = self.get_body_argument("bio")
        if len(bio) > BIO_LIMIT:
            print("2")
            self.set_status(400)
            return

        toxid = self.get_body_argument("tox_id").upper()
        if (not VALID_ANY.match(toxid)
            or len(toxid) not in {68, 76}):
            print("3")
            self.set_status(400)
            return
        
        if len(toxid) == 68:
            pkey = toxid[:64]
            pin = None
            check = toxid[64:]
        else:
            pkey = toxid[:64]
            pin = (toxid[64:72] if self.get_body_argument("is_public", 0)
                                else None)
            check = toxid[72:]

        if self.update_db_entry(None, name, pkey, bio, check, 1, pin):
            self.redirect("/friends/0")
        return

def main():
    with open("config.json", "r") as config_file:
        cfg = json.load(config_file)

    ioloop = tornado.ioloop.IOLoop.instance()
    crypto_core = CryptoCore()
    local_store = database.Database(cfg["database_url"])
    lookup_core = dns_discovery.DNSCore(cfg["number_of_workers"])
    lookup_core.callback_dispatcher = lambda cb, r: ioloop.add_callback(cb, r)
    hooks.init(cfg, local_store)

    # an interesting object structure
    address_ctr = {ACTION_PUBLISH: {"counter": Counter(),
                                    "clear_date": defaultdict(lambda: 0)}}

    LOGGER.info("API public key: {0}".format(crypto_core.public_key))
    LOGGER.info("Record sign key: {0}".format(crypto_core.verify_key))

    templates_dir = "_".join(("templates", cfg["templates"]))
    handlers = [("/api", _make_handler_for_api_method),
        ("/pk", PublicKey),
        (r"/barcode/(.+)\.svg$", CreateQR),
        (r"/u/(.+)?$", LookupAndOpenUser),
        (r"^/$", LookupAndOpenUser)
    ]
    if cfg["findfriends_enabled"]:
        handlers.append((r"/friends/([0-9]+)$", FindFriends))
        handlers.append((r"/add_ui", AddKeyWeb))
    app = tornado.web.Application(
        handlers,
        template_path=os.path.join(os.path.dirname(__file__), templates_dir),
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        crypto_core=crypto_core,
        local_store=local_store,
        lookup_core=lookup_core,
        address_ctr=address_ctr,
        home=cfg["registration_domain"],
    )
    server = tornado.httpserver.HTTPServer(app, **{
        "ssl_options": cfg.get("ssl_options"),
        "xheaders": cfg.get("is_proxied")
    })
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
