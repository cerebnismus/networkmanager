#!/usr/local/bin/ python3
import io, requests
import os, sys, time, subprocess, threading

from pprint import pprint
from datetime import datetime
from pymongo import MongoClient, ReturnDocument

# Create a connection using MongoClient. You can import MongoClient or use pymongo.MongoClient
# Provide the mongodb atlas url to connect python to mongodb using pymongo
CONNECTION_STRING = "mongodb://127.0.0.1:27017/test"
client = MongoClient(CONNECTION_STRING)
db = client["test"]

p = db.discos.find()  # returns an object of class 'Cursor'
k = list(p)          # returns a 'list' of 'dict' objects

r = db.datas.find()  # returns an object of class 'Cursor'
l = list(r)          # returns a 'list' of 'dict' objects

def fping(disco_subnet, disco_community, disco_port, disco_vers, disco_oid):
    result = subprocess.run('fping -a -g %s > temp-discos-ip' % (disco_subnet),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True,  encoding='utf-8')
    # print("\nresult.stdout:\n",result.stdout) // ofc empty 

    now = datetime.now() # dd/mm/YY H:M:S
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S") # "01/01/2019 10:00:00" 
    # print("\ndt_string:",dt_string)
  
    subprocess.run('rm -rf temp-datas-ip', shell=True)
    for item in l:
        stripped_ip = item['ipaddress'].strip('\n')
        subprocess.run('echo %s >> temp-datas-ip' % (stripped_ip),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True,  encoding='utf-8')

    # Using readlines()
    temp_datas_ip_file = open('temp-datas-ip', 'r')
    datas_lines = temp_datas_ip_file.readlines()

    temp_datas_ip_file = open('temp-discos-ip', 'r')
    discos_lines = temp_datas_ip_file.readlines()

    # differences between two lists, datas_lines and discos_lines
    #diff1 = list(set(datas_lines) - set(discos_lines))
    #print("datas - discos diff:",diff1)

    # these nodes will be add
    diff2 = list(set(discos_lines) - set(datas_lines))
    print("discovered:",diff2)
    for item in diff2:
        print (item.rstrip('\n'))
        # post request
        url = "http://localhost:6660/data"
        payload={'ipaddress': item.rstrip("\n"),
                 'community': disco_community,
                 'type': 'discovered'}
        headers = {}
        response = requests.post(url, data=payload, headers=headers)
        print("POST request:\n",response.text)
        #print("\n")

    subprocess.run('rm -rf temp-d*', shell=True)

    # read file and POST req, line by line
    # with open('temp-discos-ip', 'r') as f:
    #     for line in f:
    #         print("Discovered:",line.rstrip("\n"),disco_community)
    #        # post request
    #        url = "http://localhost:6660/data"
    #        payload={'ipaddress': line.rstrip("\n"),
    #        'community': disco_community,
    #        'type': 'discovered',}
    #        files=[ ]
    #        headers = {}
    #        response = requests.request("POST", url, headers=headers, data=payload, files=files)
    #        print(response.text)
            # print(response.json())
            # print(response.status_code)
            # print(response.headers)
            # print(response.encoding)
            # print(response.content)
            # print(response.raw)
            # print(response.reason)
            # print(response.url)
            # print(response.history)
            # print(response.elapsed)
            # print(response.request)
            # print(response.connection)
            # print(response.cookies)

    # alternative:
    # temp_discos_ip_file = open('temp-discos-ip', 'r')
    # discos_lines = temp_discos_ip_file.readlines()
    # for line in discos_lines:
    #    print("long-line:", line.rstrip("\n"))

    # subprocess.run('rm -rf temp-datas-ip', shell=True)
    # for item in l:
    #    stripped_ip = item['ipaddress'].strip('\n')
    #    subprocess.run('echo %s >> temp-datas-ip' % (stripped_ip),
    #        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True,  encoding='utf-8')

    # Using readlines()
    # temp_datas_ip_file = open('temp-datas-ip', 'r')
    # datas_lines = temp_datas_ip_file.readlines()

    # differences between two lists, datas_lines and discos_lines
    # diff1 = list(set(datas_lines) - set(discos_lines))
    # print("datas - discos diff:" + str(diff1))

    # diff2 = list(set(discos_lines) - set(datas_lines))
    # print("discos - datas diff:" + str(diff2))

    #    if str(firstone) != "None":
    #        print(str(firstone) + "Node already exists")
    #    else:
    #        print("Discovered: " + str(firstone))
    #        ipaddress = str(firstone)
    #        # add node
    #        db.datas.insert_one({
    #                    "nodename": "newbie", 
    #                    "ipaddress": ipaddress, 
    #                    "community": disco_community, 
    #                    "port": "161", 
    #                    "vers": "v2c", 
    #                    "type": "discovery", 
    #                    "subnet": disco_subnet, 
    #                    "status": "up", 
    #                    "snmp_status": "----", 
    #                    "oid": "1.3.6.1.2.1.1.5.0", 
    #                    "created_date": dt_string,
    #                    "last_poll_date": dt_string
    #        })
    #        ReturnDocument.AFTER

def temp_data_ip_update():
    subprocess.run('rm -rf temp-datas-ip', shell=True)
    for item in l:
        temp_data_ip_result = subprocess.run('echo %s >> temp-data-ip' % (item['ipaddress']),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True,  encoding='utf-8')
        # print(item['ipaddress'])

def discos_control():
    for item in k:
        print(item['disco_subnet'],item['disco_community'])
        disco_subnet = item['disco_subnet']
        disco_community = item['disco_community']
        disco_port = item['disco_port']
        disco_vers = item['disco_vers']
        disco_oid = item['disco_oid']
        fping(disco_subnet, disco_community, disco_port, disco_vers, disco_oid)

if __name__ == '__main__':
    process_id = os.getpid()
    thread_counter_t0 = threading.active_count()
    #tmp_data_ip_update()
    discos_control()