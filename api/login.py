import requests
import json
import webbrowser
import time

from whirlpool import Whirlpool
from getpass import getpass
from binascii import hexlify, unhexlify

SALT = '7714ae5c45fd1c5991daada98fbbe4e41d907323d7375120cb111d2b3f4a3502'


def get_unique_id():
    import math
    from uuid import uuid4
    
    uuid = str(uuid4()).replace('-', '')
    date = int(uuid, 16)
    shave = math.floor(math.log(date) / math.log(10)) -15
    if shave > 0:
        date = math.floor(date / 10**shave)
    
    return date


def main(twofa=False, kick=False):
    s = requests.session()
    # s.proxies = dict(http='192.168.178.32:8888', https='192.168.178.32:8888')
    # s.verify = False
    s.headers['Content-Type'] = 'application/octet-stream'
    s.headers['user-agent'] = ''
    
    try:
        creds = json.load(open('credentials.json', 'r'))
    except:
        creds = dict()
    
    uuid = creds.get('uuid')
    if not uuid:
        creds['uuid'] = get_unique_id()
    
    email = creds.get('email')
    if not email:
        email = input('Email: ').strip()
        creds['email'] = email
    
    pwhash = creds.get('pwhash')
    if not pwhash:
        pw = getpass()
        creds['pwhash'] = Whirlpool(pw).hexdigest()
    
    json.dump(creds, open('credentials.json', 'w'), indent=2, sort_keys=True)
    
    cookie = creds.get('cookie')
    if not cookie:
        buf = unhexlify(SALT)
        buf += '{}/{}'.format(creds['email'], creds['pwhash']).encode('utf-8')
        _hash = Whirlpool(buf).hexdigest()
        webbrowser.open('https://mobile.warframe.com/api/mobileCaptcha/mblCaptcha.php?input=' + _hash)
        cookie = input('Value of "wfarggdsh" cookie: ').strip()
        creds['cookie'] = cookie

    json.dump(creds, open('credentials.json', 'w'), indent=2, sort_keys=True)
    
    params = dict(email=creds['email'], password=creds['pwhash'], date=creds['uuid'], appVersion='4.15.3.0', c=creds['cookie'], os='android', time=int(time.time()))
    if kick:
        params['kick'] = 1
    
    r = s.post('https://mobile.warframe.com/api/login.php', json=params)
    
    if r.status_code == 200:
        print('Login success!')
        json.dump(r.json(), open('login.json', 'w'), indent=2, sort_keys=True)
        print('Fetching "Inventory" data...')
        r = s.post('https://mobile.warframe.com/api/inventory.php?accountId={}&nonce={}'.format(r.json()['id'], r.json()['Nonce']), json=dict())
        json.dump(r.json(), open('inventory.json', 'w'), indent=2, sort_keys=True)
        return
    elif r.status_code == 403:
        print('Whoopsie!')
        print('Response body:\n\n', r.content)
    elif r.status_code == 400 and r.text == 'new hardware detected':
        if twofa:
            print('Error: too many recursions')
            return            
        _twofa = input('2FA code: ').strip()
        r = s.post('https://mobile.warframe.com/api/authorizeNewHwid.php?code=' + _twofa, json=dict())
        return main(twofa=True)
    elif r.status_code == 409 and 'nonce still set' in r.text:
        print('Session still active, retrying with kick...')
        return main(kick=True)
    else:
        print('Unknown Response status:', r.status_code)
        print('Response body:\n\n', r.content)


if __name__ == '__main__':
    main()
