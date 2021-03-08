#coding=utf-8

import os
import sys
import shutil
import sqlite3
import win32crypt
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def GetString(LocalState):
    with open(LocalState,'r',encoding='utf-8') as f:
        s = json.load(f)['os_crypt']['encrypted_key']
    return s

def PullKey(base64_encrypted_key):
    encrypted_key_with_header = base64.b64decode(base64_encrypted_key)
    encrypted_key = encrypted_key_with_header[5:]
    key = win32crypt.CryptUnprotectData(encrypted_key,None,None,None,0)[1]
    return key

def DecryptString(key,data):
    nonce,cipherbytes = data[3:15],data[15:]
    aesgcm = AESGCM(key)
    plainbytes = aesgcm.decrypt(nonce,cipherbytes,None)
    plaintext = plainbytes.decode('utf-8')
    return plaintext

if __name__ == '__main__':
    local_state = os.path.join(os.environ['LOCALAPPDATA'],r'Google\Chrome\User Data\Local State')
    print(local_state)
    login_db = os.path.join(os.environ['LOCALAPPDATA'],r'Google\Chrome\User Data\Default\Login Data')
    print(login_db)
    tmp_file = os.path.join(os.path.dirname(sys.executable),'__tmp__')

    Key = PullKey(GetString(local_state))
    print("Key = %s"%Key)

    if os.path.exists(tmp_file):
        os.remove(tmp_file)

    shutil.copyfile(login_db,tmp_file)
    conn = sqlite3.connect(tmp_file)
    fail = 0
    num = 0
    for row in conn.execute('select signon_realm,username_value,password_value from logins'):
        num += 1
        url,usr,pwd = row[0],row[1],row[2]
        try: # old version decrypt
            decrypy_pwd = win32crypt.CryptUnprotectData(pwd,None,None,None,0)[1].decode('gbk')
            print('网站：%-50s，用户名：%-20s，密码：%s'%(url,usr,decrypy_pwd))
        except:
            print("旧版Chrome加密方式解码失败，尝试新版加密方式....")
            try: # new version decrypt
                decrypy_pwd = DecryptString(Key,pwd)
                print('网站：%-50s，用户名：%-20s，密码：%s'%(url,usr,decrypy_pwd))
            except:
                fail += 1
                print('网站：%-50s，用户名：%-20s，获取Chrome密码失败'%(url,usr))
    conn.close()
    os.remove(tmp_file)
    input('共解析 %s 条信息，失败 %s 条(按回车键退出)'%(num,fail))