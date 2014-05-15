#!/usr/bin/env python3
import requests
import sys
import os
import json

WIKI_URL = ("https://wiki.tox.im/api.php?format=json&action=query"
            "&titles=Domain_keys&prop=revisions&rvprop=content")

def parse_and_write_out(blob, filename, json_=1):
    print("got here")
    blob = blob.replace("\n", "")
    start_ptr = blob[blob.find("|-"):blob.find("|}")]
    servers = []
    aggr = []
    for bit in start_ptr.split("|")[1:]:
        if bit.startswith("-"):
            servers.append(aggr)
            aggr = [bit]
        else:
            aggr.append(bit)
    servers.append(aggr)
    servers = list(filter(bool, servers))
    if json_:
        sos = {serv[1].strip(): {
            "dnssec": serv[2] == "Valid",
            "pubkey": serv[3].upper()
        } for serv in servers}
        with open(os.path.join(filename), "w") as jf:
            json.dump(sos, jf)

def main():
    resp = requests.get(WIKI_URL, verify=False)
    if resp.status_code != 200:
        print("Bad status code: {0}. Exit.".format(resp.status_code))
        return
    else:
        payload = resp.json()
        for key in payload["query"]["pages"]:
            if payload["query"]["pages"][key]["title"] == "Domain keys":
                content = payload["query"]["pages"][key]["revisions"][0]["*"]
                parse_and_write_out(content, sys.argv[1]
                                    if len(sys.argv) > 1 else "keybag.json")
                break

if __name__ == '__main__':
    main()
