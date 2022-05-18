#!/usr/local/bin/ python3
import os, sys, time, subprocess, threading

from pprint import pprint
from datetime import datetime
from pymongo import MongoClient, ReturnDocument

# Create a connection using MongoClient. You can import MongoClient or use pymongo.MongoClient
# Provide the mongodb atlas url to connect python to mongodb using pymongo
CONNECTION_STRING = "mongodb://127.0.0.1:27017/test"
client = MongoClient(CONNECTION_STRING)
db = client["test"]

r = db.datas.find()  # returns an object of class 'Cursor'
l = list(r)          # returns a 'list' of 'dict' objects

# ping_result = subprocess.run("ping -c 1 %s &> /dev/null && echo 'up' || echo 'down' | head -n1" % (ipaddress)
def snmp_get(ipaddress, community, port, vers, oid):
    result = subprocess.run('snmpget -Ln -ObsqUuv -Ih -r1 -t5 -c %s -%s %s:%s %s' % (community, vers, ipaddress, port, oid),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True,  encoding='utf-8')

    time.sleep(2) # Sleep for 2 seconds
    now = datetime.now() # dd/mm/YY H:M:S
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    # print(dt_string)	
    # print(result.returncode)
    # print(result,result.stdout)

    if result.returncode == 0:
        sysname = result.stdout
        db.datas.find_one_and_update({"ipaddress": ipaddress}, {"$set": {"snmp_status": "up"}})
        db.datas.find_one_and_update({"ipaddress": ipaddress}, {"$set": {"sysname": sysname}})
        db.datas.find_one_and_update({"ipaddress": ipaddress}, {"$set": {"last_poll_date": dt_string}})
        ReturnDocument.AFTER # Return the modified document rather than the original

    elif result.returncode == 1:
        db.datas.find_one_and_update({"ipaddress": ipaddress}, {"$set": {"snmp_status": "down"}})
        db.datas.find_one_and_update({"ipaddress": ipaddress}, {"$set": {"sysname": "unknown"}})
        ReturnDocument.AFTER
    else:
        db.datas.find_one_and_update({"ipaddress": ipaddress}, {"$set": {"snmp_status": "unknown"}})
        db.datas.find_one_and_update({"ipaddress": ipaddress}, {"$set": {"sysname": "unknown"}})
        ReturnDocument.AFTER

    raw_icmp_result = subprocess.run("./public/raw_icmp %s" % (ipaddress),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True,  encoding='utf-8')

    if raw_icmp_result.returncode == 0:
        print("raw_icmp_result.stdout",raw_icmp_result.stdout)

    ping_result = subprocess.run("ping -c 1 %s &> /dev/null && echo 'up' || echo 'down' | head -n1" % (ipaddress),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True,  encoding='utf-8')

    # print(ping_result)
    # print(ping_result.returncode)
    
    if ping_result.stdout == 'up\n':
        db.datas.find_one_and_update({"ipaddress": ipaddress}, {"$set": {"status": "up"}})

    elif ping_result.stdout == 'down\n':
        db.datas.find_one_and_update({"ipaddress": ipaddress}, {"$set": {"status": "down"}})

def th_snmp_get(ipaddress, community, port, vers, oid): # threading
    th = threading.Thread(target=snmp_get, args=(ipaddress, community, port, vers, oid))
    th.start()

def control():
    for item in l: # iterate through the list
        print(item['status'],item['ipaddress'])
        ipaddress = item['ipaddress']
        community = item['community']
        port = item['port']
        vers = item['vers']
        oid = item['oid']
        th_snmp_get(ipaddress, community, port, vers, oid)

if __name__ == '__main__':
    process_id = os.getpid() # get the process id
    thread_counter_t0 = threading.active_count() # get the number of active threads
    control()