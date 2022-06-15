import hashlib
import requests
import json
import webbrowser
import time

from sign_request import sign
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


def main(twofa=False, kick=False, do_logout=True, allow_kick=False, logout=False):
    s = requests.session()
    # s.proxies = dict(http='192.168.178.32:8888', https='192.168.178.32:8888')
    # s.verify = False
    s.headers['Content-Type'] = 'application/octet-stream'
    s.headers['user-agent'] = ''
    
    if logout:
        try:
            user = json.load(open('user.json'))
        except:
            print('No user data to be loaded?')
            return
        
        params = dict(accountId=user['id'], nonce=user['Nonce'])
        r = s.post('https://mobile.warframe.com/api/logout.php', params=params, json=dict())
        print('Logout response:', r.text, '(1 means success)')
        return
    
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
        creds['pwhash'] = hashlib.new('whirlpool', pw.encode('utf-8')).hexdigest()
    
    json.dump(creds, open('credentials.json', 'w'), indent=2, sort_keys=True)
    
    cookie = creds.get('cookie')
    if not cookie:
        buf = unhexlify(SALT)
        buf += '{}/{}'.format(creds['email'], creds['pwhash']).encode('utf-8')
        _hash = hashlib.new('whirlpool', buf).hexdigest()
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
        json.dump(r.json(), open('user.json', 'w'), indent=2, sort_keys=True)
        user_id = r.json()['id']
        nonce = r.json()['Nonce']
        
        print('Fetching "Inventory" data...')
        r = s.post('https://mobile.warframe.com/api/inventory.php?accountId={}&nonce={}'.format(user_id, nonce), json=dict())
        json.dump(r.json(), open('inventory.json', 'w'), indent=2, sort_keys=True)
        
        # Signed request example; getting extractor data
        print('Fetching "Drones" data...')
        ts = int(time.time())
        url_path = 'api/drones.php'
        url_params = '?accountId={}&nonce={}&GetActive=true&signed=true'.format(user_id, nonce)
        body = json.dumps({})
        # Turns out that while "signed" is in the URL parameters for this one, it's not actually signed, thanks DE!
        # signature = sign(ts, url_path, url_params, body)
        # body += '\n' + signature
        
        r = s.post('https://mobile.warframe.com/{}{}'.format(url_path, url_params), data=body)
        json.dump(r.json(), open('drones.json', 'w'), indent=2, sort_keys=True)
        
        # Log out to prevent warning that a session is still logged in
        # (note: disable this if you wish to use the nonce for IRC login)
        if do_logout:
            params = dict(accountId=user_id, nonce=nonce)
            r = s.post('https://mobile.warframe.com/api/logout.php', params=params, json=dict())
            print('Logout response:', r.text, '(1 means success)')
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
        if allow_kick:
            print('Session still active, retrying with kick...')
            return main(kick=True, do_logout=do_logout)
        else:
            print('Session still active, not kicking!')
            return
    else:
        print('Unknown Response status:', r.status_code)
        print('Response body:\n\n', r.content)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Login to WF API and do some stuff')
    parser.add_argument('-k', '--allow-kicking', action='store_true', dest='allow_kick',
                        help='Allow kicking a currently active session')
    parser.add_argument('-l', '--logout', action='store_true', dest='logout',
                        help='Load saved user data and attempt log out')
    parser.add_argument('-n', '--no-logout', action='store_true', dest='no_logout',
                        help='Do not log out after fetching data (e.g. for IRC usage)')
    args = parser.parse_args()
    main(allow_kick=args.allow_kick, do_logout=not args.no_logout, logout=args.logout)
