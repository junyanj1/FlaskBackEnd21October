import sqlite3
from sqlite3 import Error

def init_db():
    # Create database
    conn = None
    try:
        conn = sqlite3.connect("user.db")
        conn.execute('CREATE TABLE IF NOT EXISTS user(id INTEGER PRIMARY KEY,'+
                     'name TEXT, role TEXT, permissions TEXT)')
    except Error as e:
        print(e)
    if conn:
        conn.close()
