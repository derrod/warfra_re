from hashlib import sha256
from base64 import b64encode

psk = open('../scripts/psk.bin', 'rb').read()


def sign(ts, url, params, body):
    ts = ts & 0x7fffffff
    ts_mod = (ts + 0x1f) % 0x21d
    
    url = '/{}{}'.format(url, params).encode('ascii')
    body = '{}\n{}.'.format(body, ts).encode('ascii')
    
    hash_inps = [
        body,
        url,
        psk[ts_mod:],
        psk,
        psk,
    ]
    hash_inps_lengths = [
        len(body),
        len(url),
        0x21d - ts_mod,
        ts_mod,
        0x21d,
    ]
    
    hashes = [sha256(), sha256()]
    
    for i in range(13):
        idx = i % 5
        hash_inp_len = hash_inps_lengths[idx]
        hash_inp = hash_inps[idx][:hash_inp_len]
        hashes[i & 1].update(hash_inp)
    
    # digest and XOR
    res = [h.digest() for h in hashes]
    
    buf = b''
    # interleave the hashes... backwards
    for hash_a, hash_b in zip(reversed(res[0]), reversed(res[1])):
        buf += hash_a.to_bytes(1, 'little')
        buf += hash_b.to_bytes(1, 'little')
    
    body += b64encode(buf)
    return body.decode('ascii')


if __name__ == '__main__':
    url = 'api/startRecipe.php'
    params = '?accountId=&nonce=&signed=true'
    body = '{"RecipeName":"/Lotus/Weapons/ClanTech/Bio/ClanTeamHealBlueprint","Ids":["",""]}'
    ts = 1654644444
    
    should_be = '1654644444.SOME/BASE64/SHIT=='
    res = sign(ts, url, params, body)
    
    print('Result:', res)
    print('Success?', res.split('\n')[1] == should_be)
