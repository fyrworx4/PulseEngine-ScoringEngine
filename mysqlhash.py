import sys
import mysql.connector
import hashlib

ip = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
databaseName = sys.argv[4]
tableName = sys.argv[5]

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
        
print(hashlib.md5(output).hexdigest() == tableHash)