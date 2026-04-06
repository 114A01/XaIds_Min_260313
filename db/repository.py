import mysql.connector

mydb = mysql.connector.connect(
    host="localhost",
    user="allen",
    password="allen",
    database="xaids"
)

print(mydb)