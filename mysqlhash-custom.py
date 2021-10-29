import sys
import mysql.connector
import hashlib

ip = "172.16.100.239"
username = "ultimatedeathstarplansuser"
password = "b_uLLg5?sSUG!KVFFSac-StXtnNjUrNGbA&FRa^hJ^$V7?nmSRN#f6W4hy9vZnXtA?uvkTF=qVbqZ9mh"
databaseName = "DeathStarPlans"
tableName = "plans"

mydb = mysql.connector.connect(
    host = ip,
    user = username,
    password = password,
    database = databaseName
)

mycursor = mydb.cursor()
mycursor.execute("SELECT * FROM " + tableName + ";")
output = []
for x in mycursor:
    output.append(x)
output = str(output).encode("utf-8")
        
print(hashlib.md5(output).hexdigest())