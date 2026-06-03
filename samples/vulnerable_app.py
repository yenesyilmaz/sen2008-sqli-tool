"""
Sample vulnerable code for the SAST demo. It intentionally contains SQL injection
bugs and should not be used as real code.
"""

import sqlite3


class FakeRequest:
    args = {"user_id": "1", "name": "admin"}
    form = {"username": "admin", "password": "pass123"}

request = FakeRequest()


def get_user_vulnerable_1(user_id):
    # string concatenation
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchall()


def get_user_vulnerable_2(username):
    # % formatting
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
    return cursor.fetchall()


def get_user_vulnerable_3(name):
    # f-string
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()


def get_user_vulnerable_4(email):
    # .format()
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = '{}'".format(email))
    return cursor.fetchall()


def get_user_safe(user_id):
    # parameterized query: the input never becomes part of the SQL text
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()
