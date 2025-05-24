import sqlite3 as sql

conn = sql.connect("users.db")

def createTable(category):
    query = f"""CREATE TABLE IF NOT EXISTS {category} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE, 
                password TEXT,
                email TEXT UNIQUE
            )"""
    conn.execute(query)
    conn.commit()

createTable("users")