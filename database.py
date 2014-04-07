"""
* Tox DNS Discovery Management Daemon - draft API server for Tox ID publishing.
* Since "Tox DNS Discovery Management Daemon" is a mouthful, just call it "yuu"
*
* Author: stal, April 2014
* Copyright (c) 2014 Zodiac Labs.
* You are free to do whatever you want with this file -- provided that this
* notice is retained.
"""
import sqlalchemy
from sqlalchemy import Integer, String, Binary, Unicode, Boolean, Column, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
import re

ID_HEX = re.compile(r"([A-F0-9][A-F0-9])")

Base = declarative_base()

class User(Base):
    __tablename__ = "records"
    user_id = Column(Integer, primary_key=True)
    name = Column(Unicode, unique=True)
    tox_id = Column(Integer) # 72
    privacy = Column(Integer)
    timestamp = Column(DateTime)

    def is_searchable(self):
        """Whether searching will find this user."""
        return self.privacy > 0

    def is_public(self):
        """Whether to publish as toxv1 rec."""
        return self.privacy > 1

    def public_key(self):
        return self.tox_id[:64]

    def checksum(self, iv=(0, 0)):
        cks = list(iv)
        for i, v in re.findall(ID_HEX, self.tox_id):
            cks[i % 2] ^= hex(v, 16)
        return "".join(hex(byte)[2:] for byte in cks).upper()

class Database(object):
    """The object coordinator is just a fancy way of saying database"""
    def __init__(self, backing="sqlite:///:memory:", should_echo=1):
        self._backing_store = sqlalchemy.create_engine(backing, echo=should_echo)
        Base.metadata.create_all(self._backing_store)
        self.session_maker = sqlalchemy.orm.sessionmaker(bind=self._backing_store)
