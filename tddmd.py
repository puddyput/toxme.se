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
import nacl.utils
import database
import datetime
import time
import urllib.parse as parse
import dns.resolver
import dns.exception
import threading
import queue
import qrcode
import qrcode.image.svg
import xml.etree.ElementTree as ET
import djb
from const import *

tornado.log.enable_pretty_logging()

INTERPRET_TOX2 = lambda r: {
    "public_key": r["pub"],
    "check": r["check"],
    "version": "Tox V2 (PIN required)",
}

INTERPRET_TOX1 = lambda r: {
    "public_key": r["id"],
    "check": r["id"][-4:],
    "version": "Tox V1",
}

INTERPRET_DELEGATES = {
    "tox1": INTERPRET_TOX1,
    "tox2": INTERPRET_TOX2,
}

class DNSCore(object):
    def __init__(self, local_store, wc, home, dnsroot, ttl):
        self.home = home
        self.local_store = local_store
        self.lookup_cache = {}
        self.keying_cache = {}
        self.dispatch_queue = queue.Queue()
        self.workers = []
        for n in range(wc):
            thread = threading.Thread(target=self._worker_thread_run, kwargs={
                "dqueue": self.dispatch_queue,
                "io_loop": tornado.ioloop.IOLoop.instance(),
            })
            thread.daemon = True
            thread.start()
            self.workers.append(thread)
        
        self.root = dnsroot
        self.ttl = ttl
        self.dirty = 1

    @staticmethod
    def _parse_rec(rec):
        return {k: v for k, v in (pair.split("=", 1) for pair in rec.split(";") if pair)}

    def _cache_key(self, regdomain):
        if regdomain in self.keying_cache:
            ttd = self.keying_cache[regdomain][1]
            if ttd > time.time():
                return self.keying_cache[regdomain][0]
            else:
                del self.keying_cache[regdomain]
        # search key
        try:
            ans = dns.resolver.query("_tox.{0}".format(regdomain), "TXT")
        except dns.exception.DNSException:
            return None
        for txt in ans:
            try:
                values = self._parse_rec("".join(txt.strings))
            except ValueError:
                continue

            if values.get("v") != "tox" or values.get("pub") is None:
                continue

            try:
                k = signing.VerifyKey(values.get("pub"), KEY_ENC)
            except (TypeError, nacl.exceptions.CryptoError):
                return None
            else:
                self.keying_cache[regdomain] = (k, int(time.time() + ans.ttl))
                return k
        else:
            return None

    def _versig(self, name, kc, sig, regdomain):
        key = self._cache_key(regdomain)
        if not key:
            return {
                "status": SIGNSTATUS_UNDECIDED,
                "detail": "? (no authority key found for {0})".format(regdomain)
            }
        try:
            e = nacl.encoding.Base64Encoder
            dec = key.verify(sig, encoder=e)
            if dec != name.encode("utf8") + nacl.encoding.HexEncoder.decode(kc):
                raise nacl.exceptions.BadSignatureError("wrong key signed, lol")
        except nacl.exceptions.BadSignatureError as e:
            print(e)
            return {
                "status": SIGNSTATUS_BAD,
                "detail": "Bad (validation failed; probably NSA MITM)",
            }
        except Exception as e:
            return {
                "status": SIGNSTATUS_BAD,
                "detail": "Bad (internal error occurred during verification; "
                          "trust at your own risk)",
            }
        else:
            return {
                "status": SIGNSTATUS_GOOD,
                "detail": "Good (signed by publisher {0})".format(regdomain),
            }

    def _worker_actually_run(self, name, regdomain):
        try:
            ans = dns.resolver.query("{0}._tox.{1}".format(name, regdomain),
                                     "TXT")
        except dns.exception.DNSException:
            return ERROR_NO_USER

        for opaque in ans:
            try:
                values = self._parse_rec("".join(opaque.strings))
            except ValueError:
                continue
            v = values.get("v", None)
            if v not in {"tox1", "tox2"}:
                return ERROR_LOOKUP_FAILED

            oaddr = "@".join((name, regdomain))
            base_ret = {
                "c": 0,
                "name": name,
                "regdomain": regdomain,
                "url": "".join(("tox://", oaddr)),
                "source": SOURCE_REMOTE
            }

            try:
                base_ret.update(INTERPRET_DELEGATES[v](values))
            except KeyError:
                return ERROR_LOOKUP_FAILED

            if "sign" in values:
                if values["v"] == "tox1":
                    check_text = base_ret["public_key"]
                else:
                    check_text = "".join((base_ret["public_key"][:64],
                                          base_ret["check"]))
                base_ret["verify"] = (self._versig(name, check_text,
                                      values["sign"], regdomain))
            else:
                base_ret["verify"] = {
                    "status": SIGNSTATUS_UNDECIDED,
                    "detail": "? (record doesn't have a signature)",
                }
            self.lookup_cache[oaddr] = (base_ret, int(time.time()) + ans.ttl)
            return base_ret
        else:
            return ERROR_LOOKUP_FAILED

    def _worker_thread_run(self, dqueue, io_loop):
        while 1:
            action, args, cb = dqueue.get()
            try:
                result = action(*args)
            except Exception:
                LOGGER.error("exception caught; too layz to print; continuing")
                result = ERROR_LOOKUP_INTERNAL
                raise
            if cb:
                io_loop.add_callback(cb, result)

    def dispatch_lookup(self, addr, cb):
        name, regdomain = addr.rsplit("@", 1)
        if not set(name).isdisjoint(DISALLOWED_CHARS):
            return cb(ERROR_BAD_PAYLOAD)
        regdomain = regdomain.lower()

        if regdomain == self.home:
            rec = self.local_store.get(name.lower())
            if not rec:
                return cb(ERROR_NO_USER)
            if not rec.is_searchable():
                return cb(ERROR_NO_USER)
            base_ret = {
                "c": 0,
                "name": rec.name,
                "regdomain": regdomain.lower(),
                "public_key": rec.public_key,
                "url": "tox://{0}@{1}".format(rec.name, regdomain),
                "verify": {
                    "status": SIGNSTATUS_GOOD,
                    "detail": "Good (signed by local authority)",
                },
                "source": SOURCE_LOCAL
            }
            if rec.is_public():
                base_ret["version"] = "Tox V1 (local; public)"
                base_ret["public_key"] = (rec.public_key + rec.nospam
                                          + rec.checksum())
            else:
                base_ret["version"] = "Tox V2 (local; requires PIN)"
            return cb(base_ret)

        normal = "@".join((name, regdomain))
        if normal in self.lookup_cache:
            ttd = self.lookup_cache[normal][1]
            if ttd > time.time():
                return cb(self.lookup_cache[normal][0])

        self.dispatch_queue.put((self._worker_actually_run, (name, regdomain),
                                 cb))

    def write_if_needed(self):
        if self.dirty:
            self.dispatch_queue.put((djb.djbdns_write_file,
                                    (self.root, self.local_store, self.ttl,
                                     self.home), None))
            self.dirty = 0

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

class OpaqueAPIEndpoint(tornado.web.RequestHandler):
    def get(self):
        self.write(ERROR_METHOD_UNSUPPORTED)

    def typecheck_dict(self, envelope, expect):
        for key, value in expect.items():
            if not isinstance(envelope.get(key), value):
                print(key, value)
                LOGGER.warn("typecheck failed on json")
                return 0
        return 1

    def _action_lookup_tail(self, result):
        self.set_status(200 if result["c"] == 0 else 400)
        self.write(result)
        self.finish()

    def action_lookup(self, envelope):
        LOGGER.info(envelope)
        name = envelope.get("name")
        if not name or name.endswith("@") or name.startswith("@"):
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            self.finish()
            return
        if "@" not in name:
            name = "@".join((name, self.settings["home"]))
        self.settings["dnscore"].dispatch_lookup(name,
                                                 self._action_lookup_tail)

    def _encrypted_payload_prologue(self, envelope):
        if not self.typecheck_dict(envelope, {"k": str, "r": str, "e": str}):
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            return
        try:
            other_key = public.PublicKey(envelope["k"], KEY_ENC)
        except nacl.exceptions.CryptoError:
            LOGGER.warn("did fail req because other pk was bad")
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            return
        
        box = public.Box(self.settings["cryptocore"].pkey, other_key)
        
        try:
            nonce = nacl.encoding.Base64Encoder.decode(envelope["r"])
            ciphertext = nacl.encoding.Base64Encoder.decode(envelope["e"])
            clear = box.decrypt(ciphertext, nonce, nacl.encoding.RawEncoder)
        except (ValueError, TypeError, nacl.exceptions.CryptoError):
            LOGGER.warn("did fail req because a base64 value was bad")
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            return
        
        try:
            clear = json.loads(clear.decode("utf8"))
        except (UnicodeDecodeError, TypeError):
            LOGGER.warn("did fail req because inner json decode failed")
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            return
        return clear

    def action_push(self, envelope):
        clear = self._encrypted_payload_prologue(envelope)
        if not clear:
            return

        if not self.typecheck_dict(clear,
                                   {"s": str, "n": str, "t": int, "l": int}):
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            return

        auth = envelope["k"].upper()
        id_ = clear["s"].upper()
        name = clear["n"].lower()
        ctime = int(time.time())

        if (not VALID_ID.match(id_) or not set(name).isdisjoint(DISALLOWED_CHARS)
            or abs(ctime - clear["t"]) > 300 or name in DISALLOWED_NAMES
            or len(name) > NAME_LIMIT_HARD):
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            return

        pub, check = id_[:64], id_[64:]

        dbc = self.settings["database"]
        with dbc.lock:
            session, owner_of_cid = dbc.get_by_id_ig(pub)
            if owner_of_cid and owner_of_cid.name != name:
                session.close()
                self.set_status(400)
                self.write(ERROR_DUPE_ID)
                return

            session, mus = dbc.get_ig(clear["n"], session)
            if not mus:
                mus = database.User()
            elif mus.public_key != auth:
                session.close()
                self.set_status(400)
                self.write(ERROR_NAME_TAKEN)
                return

            mus.name = name
            mus.public_key = pub
            mus.checksum = check
            mus.privacy = min(clear["l"], 2)
            mus.timestamp = datetime.datetime.now()
            mus.sig = self.settings["cryptocore"].sign(mus)
            ok = dbc.update_atomic(mus, session)
            if not ok:
                session.close()
                self.set_status(400)
                self.write(ERROR_DUPE_ID)
                return
            session.close()

        self.write(ERROR_OK)
        self.settings["dnscore"].dirty = 1
        LOGGER.info("Notice: done")
        return

    def action_unpublish(self, envelope):
        clear = self._encrypted_payload_prologue(envelope)
        if not clear:
            return
        
        ctime = int(time.time())
        pk = clear.get("p", "").upper()
        if not VALID_KEY.match(pk) or abs(ctime - clear.get("t", 0)) > 300:
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            return
        
        self.settings["database"].delete_pk(pk)
        self.settings["dnscore"].dirty = 1
        self.write(ERROR_OK)
        return

    @tornado.web.asynchronous
    def post(self):
        if self.request.protocol != "https":
            self.set_status(400)
            self.write(ERROR_NOTSECURE)
            self.finish()
            return

        try:
            envelope = self.request.body.decode("utf8")
            envelope = json.loads(envelope)
        except (UnicodeDecodeError, TypeError):
            LOGGER.warn("did fail req because json decode failed")
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            self.finish()
            return

        action = envelope.get("a")
        if action is None:
            LOGGER.warn("did fail req because there is no a param")
            self.set_status(400)
            self.write(ERROR_BAD_PAYLOAD)
            return
        elif action == ACTION_PUBLISH:
            self.action_push(envelope)
            self.finish()
        elif action == ACTION_UNPUBLISH:
            self.action_unpublish(envelope)
            self.finish()
        elif action == ACTION_LOOKUP:
            self.action_lookup(envelope)

class PublicKey(tornado.web.RequestHandler):
    def get(self):
        if self.request.protocol != "https":
            self.write(ERROR_NOTSECURE)
        else:
            self.write({
                "c": 0,
                "key": self.settings["cryptocore"].public_key
            })

class _yuuQRImage(qrcode.image.svg.SvgPathFillImage):
    QR_PATH_STYLE = "fill:#000;fill-opacity:1;fill-rule:nonzero;stroke:none"
    background = "rgba(255,255,255,0.9)"
    
    def _svg(self, tag="svg", **kwargs):
        svg = super(qrcode.image.svg.SvgImage, self)._svg(tag=tag, **kwargs)
        svg.set("xmlns", self._SVG_namespace)
        if self.background:
            svg.append(
                ET.Element("rect", fill=self.background, x="0", y="0",
                           rx="8", ry="8", width="100%", height="100%")
            )
        return svg
    
    def units(self, units, text=True):
        # Override: specify units in pixels for sharpness.
        if not text:
            return units
        return "{0}px".format(units)

class CreateQR(tornado.web.RequestHandler):
    def _gen_qr(self, name):
        text = "tox://" + "@".join((name, self.settings["home"]))
        code = qrcode.QRCode(
            version=3,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=5,
            border=3,
            image_factory=_yuuQRImage
        )
        code.add_data(text)
        svg = code.make_image()
        self.set_header("Content-Type", "image/svg+xml; charset=utf-8")
        svg.save(self)
    
    def get(self, path_id):
        if self.request.protocol != "https":
            self.write(ERROR_NOTSECURE)
            return
        name = (parse.unquote(path_id) if path_id else "").lower()
        if not name or not set(name).isdisjoint(DISALLOWED_CHARS):
            self.set_status(404)
            return ""
        rec = self.settings["database"].get(name)
        if not rec:
            self.set_status(404)
            return ""
        self._gen_qr(name)

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

        rec = self.settings["database"].get(name)
        if not rec:
            self.set_status(404)
            self.render("fourohfour.html", record=name,
                        realm=self.settings["home"])
            return

        self.render("onemomentplease.html", record=name,
                    realm=self.settings["home"])

    def _lookup_home(self):
        self.render("lookup_home.html")

    def get(self, path_id):
        if self.request.protocol != "https":
            self.write(ERROR_NOTSECURE)
            return
        name = (parse.unquote(path_id) if path_id else "").lower()
        if name:
            return self._render_open_user(name)
        else:
            return self._lookup_home()

def main():
    with open("config.json", "r") as config_file:
        cfg = json.load(config_file)

    crypto = CryptoCore()
    dbh = database.Database(cfg["database_url"])
    dns = DNSCore(dbh, cfg["number_of_workers"], cfg["registration_domain"],
                  cfg["djbdns_root"], cfg["dns_record_ttl"])
    
    LOGGER.info("Notice: API public key: {0}".format(
        crypto.public_key
    ))
    LOGGER.info("Notice: Record sign key: {0}".format(
        crypto.verify_key
    ))

    ioloop = tornado.ioloop.IOLoop.instance()
    app = tornado.web.Application(
        [("/api", OpaqueAPIEndpoint),
         ("/pk", PublicKey),
         (r"/barcode/(.+)\.svg$", CreateQR),
         (r"/(.+)?$", LookupAndOpenUser),
         ],
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        cryptocore=crypto,
        database=dbh,
        dnscore=dns,
        home=cfg["registration_domain"]
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
    
    callback = tornado.ioloop.PeriodicCallback(dns.write_if_needed, 60 * 1000)
    callback.start()

    try:
        ioloop.start()
    finally:
        os.remove(cfg["pid_file"])

if __name__ == "__main__":
    main()