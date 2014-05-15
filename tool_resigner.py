#!/usr/bin/env python3
import yuu
import database
import hooks
import json

with open("config.json", "r") as config_file:
    cfg = json.load(config_file)

crypto_core = yuu.CryptoCore()
local_store = database.Database(cfg["database_url"])
hooks_state = hooks.init(cfg, local_store)

for record in local_store.iterate_all_users(mutates=1):
    print("Signing record for {0}.".format(record.name))
    record.sig = crypto_core.sign(record)
    hooks.did_update_record(hooks_state, record)