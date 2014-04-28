from const import *
import os
import subprocess

def djbdns_write_file(root, database, ttl, home):
    data_name = os.path.join(root, "data")
    master = open(data_name, "w")
    header_name = os.path.join(root, "header.yuu")
    with open(header_name, "r") as header:
        h = header.read()
        master.write(h)
        master.write("\n")
    
    master.write("# This data automatically updated by yuu. Please edit"
                  " header.yuu instead.\n")
    for obj in database.iterate_all_users():
        master.write("'{0}:{1}:{2}\n".format(obj.fqdn(home), obj.record(), ttl))
    master.close()
    
    prev = os.getcwd()
    os.chdir(root)
    subprocess.check_output(["make"])
    os.chdir(prev)
    LOGGER.info("Update succeeded.")
