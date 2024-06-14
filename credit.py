from flask import Flask, request, jsonify, send_from_directory
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import boto3
import os

app = Flask(__name__)

# AWS Secrets Manager configuration
aws_secret_name = "your_secret_name"
aws_region_name = "your_region_name"

def get_secret():
    client = boto3.client('secretsmanager', region_name=aws_region_name)
    get_secret_value_response = client.get_secret_value(SecretId=aws_secret_name)
    return get_secret_value_response['SecretString']

# Retrieve the encryption key from AWS Secrets Manager
encryption_key = get_secret()

# Encryption and decryption functions
def encrypt_credit_card(data, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    cipher = AES.new(key, AES.MODE_GCM)
    cipher_text, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    encrypted_data = base64.b64encode(salt + cipher.nonce + tag + cipher_text).decode('utf-8')
    return encrypted_data

def decrypt_credit_card(encrypted_data, password):
    decoded_data = base64.b64decode(encrypted_data)
    salt = decoded_data[:16]
    nonce = decoded_data[16:32]
    tag = decoded_data[32:48]
    cipher_text = decoded_data[48:]
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(cipher_text, tag).decode('utf-8')
    return decrypted_data

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json['data']
    password = request.json['password']
    encrypted_data = encrypt_credit_card(data, password)
    return jsonify({'encrypted_data': encrypted_data})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_data = request.json['encrypted_data']
    password = request.json['password']
    try:
        decrypted_data = decrypt_credit_card(encrypted_data, password)
        return jsonify({'decrypted_data': decrypted_data})
    except Exception as e:
        return jsonify({'error': 'Decryption failed'}), 400

if __name__ == '__main__':
    app.run(debug=True)
