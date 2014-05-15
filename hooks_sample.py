"""
* This file is released into the public domain.
"""
import logging

def init(config, database):
    """Called once on yuu's initialization.
       The return value of this function is passed on every call to hooks.
       Therefore, you can initialize a state class here and access it
       in did_update_record/did_delete_record.
       Arguments:
       - config: The contents of config.json (dict)
       - database: A Database object. It's safe to query objects from it
                   at this point.
       """
    logger = logging.getLogger("my_useless_hooks")
    logger.info("Hello world, this is init().")
    return logger

def did_update_record(userdata, rec):
    """This is called when a user is added, or user data is updated,
       and her DNS record should be refreshed.
       Arguments:
       - userdata: The object returned by init().
       - rec: The StaleUser object that need updating. See database.py's
              User class for properties/methods."""
    userdata.info("did_update_record called for {0}".format(rec))
    userdata.info("dns: {0}".format(rec.record()))

def did_delete_record(userdata, rec):
    """This is called when a user is deleted from the database,
       and her record should be removed from DNS.
       See did_update_record for argument descriptions."""
    userdata.info("did_delete_record called for {0}".format(rec))
    userdata.info("dns: {0}".format(rec.record()))
