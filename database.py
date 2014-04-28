"""
* Tox DNS Discovery Management Daemon - draft API server for Tox ID publishing.
* Since "Tox DNS Discovery Management Daemon" is a mouthful, just call it "yuu"
*
* Author: stal, stqism; April 2014
* Copyright (c) 2014 Zodiac Labs.
* You are free to do whatever you want with this file -- provided that this
* notice is retained.
"""
import sqlalchemy
import sqlalchemy.exc
from sqlalchemy import Integer, DateTime, Unicode, Column, String
from sqlalchemy.ext.declarative import declarative_base
from string import printable
import re
import threading
from const import *

Base = declarative_base()

class User(Base):
    __tablename__ = "records"
    user_id = Column(Integer, primary_key=True)
    name = Column(Unicode, unique=True)
    bio = Column(Unicode)
    public_key = Column(String, unique=True) # 64
    checksum = Column(String) # 4
    privacy = Column(Integer)
    timestamp = Column(DateTime)
    sig = Column(String)
    
    def is_searchable(self):
        """Whether searching will find this user."""
        return self.privacy > 0
    
    def is_public(self):
        """Whether to publish as toxv1 rec.
           (Deprecated. this flag is ignored)"""
        return self.privacy > 1
    
    def _encode_two(self):
        rec = "v=tox2;pub={0};check={1};sign={2}".format(self.public_key,
                                                         self.checksum,
                                                         self.sig)
        return DJB_SPECIAL.sub(lambda c: "\\" + "{0:o}".format(ord(c.group(0)))
                                                       .zfill(3), rec)
    
    def record(self, vers=RECORD_DEFAULT):
        return self._encode_two()

    def fqdn(self, suffix):
        o = []
        rep = lambda char: ("\\" + "{0:o}".format(char).zfill(3)
                            if chr(char) not in printable else chr(char))
        for ch in self.name.encode("utf8"):
            o.append(rep(ch))
        return "._tox.".join(("".join(o), suffix))

class StaleUser(object):
    def __init__(self, u):
        self.user_id = u.user_id
        self.name = u.name
        self.bio = u.bio
        self.public_key = u.public_key
        self.checksum = u.checksum
        self.privacy = u.privacy
        self.timestamp = u.timestamp
        self.sig = u.sig
    
    def is_searchable(self):
        return User.is_searchable(self)
    
    def is_public(self):
        return User.is_public(self)
    
    def record(self, vers=RECORD_DEFAULT):
        return User.record(self, vers)
    
    def fqdn(self, suffix):
        return User.fqdn(self, suffix)

class Database(object):
    def __init__(self, backing="sqlite:///:memory:", should_echo=1):
        self.presence_cache = {}
        self.dbc = sqlalchemy.create_engine(backing, echo=should_echo)
        Base.metadata.create_all(self.dbc)
        self.gs = sqlalchemy.orm.sessionmaker(bind=self.dbc)
        self.lock = threading.RLock()

    def _cache_entity_ins(self, name, prefetch):
        if len(self.presence_cache) > PRESENCE_CACHE_CEILING:
            self.presence_cache.popitem()
        u = StaleUser(prefetch)
        self.presence_cache[name] = u
        return u

    def _cache_entity_sel(self, name):
        sess = self.gs()
        ex = sess.query(User).filter_by(name=name).first()
        if len(self.presence_cache) > PRESENCE_CACHE_CEILING:
            self.presence_cache.popitem()
        u = StaleUser(ex) if ex else None
        self.presence_cache[name] = u
        sess.close()
        return u

    def _cache_entity_rem(self, name, prefetch):
        self.presence_cache[name] = -1
        return prefetch

    def get(self, name):
        e = self.presence_cache.get(name, -1)
        return e if e != -1 else self._cache_entity_sel(name)

    def contains(self, name):
        e = self.presence_cache.get(name, -1)
        return 1 if e != -1 else bool(self._cache_entity_sel(name))

    def update_atomic(self, object_, s=None):
        s = s or self.gs()
        s.add(object_)
        try:
            s.commit()
            self._cache_entity_ins(object_.name, object_)
        except sqlalchemy.exc.IntegrityError as e:
            print(e)
            return 0
        finally:
            s.close()
        return 1

    def get_ig(self, name, sess=None):
        sess = sess or self.gs()
        ex = sess.query(User).filter_by(name=name).first()
        return sess, ex

    def get_by_id_ig(self, id, sess=None):
        sess = sess or self.gs()
        ex = sess.query(User).filter_by(public_key=id).first()
        return sess, ex

    def iterate_all_users(self):
        sess = self.gs()
        results = sess.query(User)
        for obj in results:
            yield obj
        sess.close()

    def delete_pk(self, pk):
        sess = self.gs()
        results = sess.query(User).filter_by(public_key=pk)
        for obj in results:
            sess.delete(obj)
        sess.commit()
        sess.close()
