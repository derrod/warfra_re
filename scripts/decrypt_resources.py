import os
from Crypto.Cipher import AES

res_path = '/path/to/app/Resources'

# key and IV as echo'd by the frida script
key = [-113,-36,80,-3,-127,50,109,31,100,28,-37,-109,3,54,75,114]
iv = [97,-43,-73,63,83,-17,-56,-27,-52,43,-66,-78,-128,-109,20,112]

# convert key/iv to unsigned int
keyp = [(i if i >= 0 else i + 256) for i in key]
ivp = [(i if i >= 0 else i + 256) for i in iv]
# convert keys to bytes
keyb = b''.join((i).to_bytes(1, 'big') for i in keyp)
ivb = b''.join((i).to_bytes(1, 'big') for i in ivp)

# finally, decrypt all `.bin` files in the resources folder
for path, _, files in os.walk(res_path):
    for _file in files:
        if _file.endswith('bin'):
            cipher = AES.new(keyb, AES.MODE_CBC, iv=ivb)
            fc = open(os.path.join(path, _file), 'rb').read()
            fd = cipher.decrypt(fc)
            open(os.path.join(path, _file.replace('.bin', '')), 'wb').write(fd)