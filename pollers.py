import socket
import requests
import os
from ftplib import FTP
import json
import ast
import subprocess
import hashlib
import random
from nslookup import Nslookup
import smtplib
import re
import mysql.connector

"""
Name: pollPort
Description: Will poll for a specific port and see if it is online
Parameters: ip - ip address to poll, port - port number
"""

def pollPort(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    result = s.connect_ex((ip,int(port)))
    if result == 0:
      return True
    else:
      return False

"""
Name: pollHTTP
Description: Will query a url and verify that it is reachable and the md5 content of the page is what is expected
Parameters: url - complete url of the page to query (ex. https://192.168.0.1/login.html), pageHash - expected md5 hash of the page
"""

def pollHTTP(url, pageHash):
    try:
        if(hashlib.md5(requests.get(url, timeout=3).content).hexdigest() == pageHash):
            return True
        else:
            return False
    except:
        return False

"""
Name: pollSSH
Description: Will verify that the SSH service is running on the specific port
Parameters: ip - ip address to poll, port - port number to poll, users - Array of strings of format "username:password" to verify are valid
"""

def pollSSH(ip, port, users):
    try:
        for user in users:
            if ":" not in user:
                continue
            username = user.split(":")[0]
            password = user.split(":")[1]
            pollCommand = "sshpass -p \"" + password + "\" ssh -q -o \"UserKnownHostsFile=/dev/null\" -o \"StrictHostKeyChecking=no\" " + username + "@" + ip + " -p " + port + " exit"
            if(subprocess.call(pollCommand, shell=True) != 0):
                    return False
        return True
    except:
        return False

"""
Name: pollFTP
Description: Will verify that the FTP service is running on the specific port
Parameters: ip - ip address to poll, port - port number to poll, users - Array of strings of format "username:password" to verify are valid
"""

def pollFTP(ip, port, users):
    try:
        ftp = FTP()
        ftp.connect(ip, int(port))
        ftp.set_pasv(False)
        for user in users:
            if ":" not in user:
                continue
            username = user.split(":")[0]
            password = user.split(":")[1]
        ftp.login(username, password)
        ftp.close()
        return True
    except:
        return False

"""
Name: pollDNS
Description: Will verify that the DNS service is running on the specific port
Parameters: dnsServer - the server to perform DNS query from
Records: a dictionary of FQDNs and IP addresses of all hosts on the network
"""

records = {
    "sol.orbitalweapons.eu": "['192.168.200.25']",
    "terra.orbitalweapons.eu": "['192.168.200.18']",
    "luna.orbitalweapons.eu": "['192.168.200.4']"
}

key_list = list(records)

def pollDNS(dnsServer):
    try:
        dns_query = Nslookup(dns_servers=[dnsServer])
        rand = random.randint(0,2)
        ips_record = dns_query.dns_lookup(key_list[rand])

        if ips_record.answer == []:
            return False
        elif ips_record.answer == ast.literal_eval(records[key_list[rand]]):
                return True
        return False
    except Exception as e:
        print(e)
        return False

"""
Name: pollSMTP
Description: Will verify that the SMTP service is running on the specific port
Parameters: ip - ip address to poll, from_addr - mail address to send from, to_addr - mail address to send to
"""

def pollSMTP(ip, from_addr, to_addr):
    try:
        with smtplib.SMTP(ip, 25) as server:
            server.sendmail(from_addr, to_addr, 'Hey there!')
        return True
    except:
        return False

"""
Name: pollRDP
Description: Will verify that the RDP service is running on the specific port by checking if authentication to RDP service is successful
Parameters: ip - ip address to poll, port - port number to poll, user - user to connect with
"""

def pollRDP(ip, port, users):
    rdp_list = []
    for user in users:
        username = user.split(":")[0]
        password = user.split(":")[1]
        cmd = ['xfreerdp', '--ignore-certificate', '--authonly', '-u', username, '-p', password, f'{ip}:{port}']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = proc.communicate()

        if (str(output)[-5]) == "0":
            rdp_list.append(0)
        else:
            rdp_list.append(1)

    if 1 in rdp_list:
        return False
    else:
        return True

"""
Name: pollmySQL
Description: Will verify that the mySQL service is running on the specific port by checking if authentication to mySQL service is successful, and database matches hard-coded hash
Parameters: ip - ip address to poll, port - port number to poll, users - list of users to connect with, databaseName - name of database to use, tableName - name of table to use, tableHash - hash of table
"""

def pollmySQL(ip, port, users, databaseName, tableName, tableHash):
    try:
        for user in users:
            if ":" not in user:
                continue
            username = user.split(":")[0]
            password = user.split(":")[1]

        mydb = mysql.connector.connect(
            host = ip,
            user = username,
            password = password,
            database = databaseName
        )

        mycursor = mydb.cursor()
        mycursor.execute("SELECT * FROM " + tableName)
        output = []
        for x in mycursor:
            output.append(x)
        output = str(output).encode("utf-8")
        
        if(hashlib.md5(output).hexdigest() == tableHash):
            return True
        else:
            return False
    except:
        return False