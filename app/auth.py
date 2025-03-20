from flask import request, jsonify
from app import app
from ldap3 import Server, Connection, ALL
import os

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    domain = os.getenv('DOMAIN')

    server = Server(domain, get_info=ALL)
    conn = Connection(server, user=f'{domain}\\{username}', password=password, authentication='NTLM')

    if conn.bind():
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401
