import time
import hashlib
import binascii
import hexchat

__module_name__ = 'Warframe IRC Auth'

psk = b'xe\xbcm\x18\x9b\x06\x82\xf4\x91,\xb2\x89\xaeKo\xb8\x0e>b=u\x88\x90\xbc\xa8\'B\x0cJ\x86a\xc2^<\x9b\xaf\xbb\xe3W\x0b\n$f\x84\xa5\x98\xc4}\x11\x93a\xda\xca\xc2\xdf\x9a\x80\x96\x03C\xd7\xfes\x89\xc6\xf9\xa6\x9f~\xfc}\x0f\xb8n\xf4e\x16\xa6\xa8\xaf5yN\xb2\x02Ga\xa1\xcb\xed\xe5\x0b\xfb\xe0ej\x11\x9c\x1e\xb0*\xe5\x05\xee\x17\x06\xcf\xa3\xab\xbb>\x1bo-\xf3\xdf\x93S\xdb-\xdfd\x1di\t#u\xc97\x83\x00\xacl\xf4r\x0f\x94\x9d\xa6\x00\xd6\xf0\x07\x95\xc5D\xaat\x14\xf4\x80\xdc\xfe#\x7f\xf6\xdcT\xad\xa4\x08mh\xa7\xaa\x924k\xf4\x01;\x90{\x10!/G\x07\xa5\xbd\xed\xcb+\xdc! \x14\xd0QD<7v1>\x05\x7fQ\xdd*\xbeu\xec,_\xa3K\xf6\xec\xf3\xa4\x12\xa9\x8c\xcc\xd3|\x8b\xfdO\x05\xe0\x02\xc9\x05J\xd2v\x84\xc0X4\xfc#\\\x94j\x8aJG\xaf\xa9N\x077j\x02<\xa4\xe0iS\x19\xf48^_\x91\xdb\xf0\xdf\x8aH\xd9\x1e\xd8\xec\xfc=\x98G\x8d$\x17\xb4\x91\x8dY\xfd]=\x88\x94\xf3\x95=\x96\x94\xa7\xe2q\n\xef\x01\xff\xf3\xc4\x91RlV\xfd\x0eQ.\xdak\xa4\xd8\xfe\x87\xa7\x84\xa3t\xee\xa8\xdb\xb6W\xc7\xd0\x8d\xf3\xa9\x80\xce\xac\x1e\xd6\xb1\xbd\xc3\xe2\xd1N}_\xaf\xdd\x0c\xa6\x16\xaf|n\x14\xe2\t\x91\x9c\xbetX\xba@\x99 \x8ce\xa0\xe8[\xdcj\x9dJ\xc3\xe0\xbb\'\xae\x80\x16\xdb\x11K+\xfd\xb5\x88\xb7\xcb\x922\xe4\xd3\x80l`g\xb0\xae\xf0Yr\xfb\x86\xc7P\x92\xca\x08\x92\x06\xb5\x8cP\xf6c\x958\xea!\x9d\xa5.\xba\x9czE\xf6=\x847\x07{\x0e\',\x9c\xa9i\xbdMN\xbcp\x0e\x9d\x19\xe3\xef\xcbY\xeay\xacgT\xb3gu\x13\xe2\xf4;\xf1\x80\xdf\xa3\xa5\xb9\xf4"\x97x\x1b\xdevj\xd9\xd1\xfa6=\x8e\x1e\xe7\xb4\x05Ww\xd0\xfc\xbbGN\x13\xd8\xd2k\x1dO\xea{\xa6K\xf2\xb9\xff\xc0fCe\x0c=\xd6\x18ymY\x89\xae\x07u\x10\xf1\xb5\xc40}\xf0,\xda\n\xbdq]\xd5k \x9c*[LG\xe7\xcc\x8d\x1ao&5\x8c\x8d\x80\x0c\x11\xbb<f\xa1\x80\x92\x9eb\xb5VU\xe37\xc6\xab\xa1\xf5T\xd0\xde\x81\x81\xdf4\x9d\xda[b\xa6\x7f\xe0N\xe3\xf8\x8c\x9f\xe3\x06\xe2'


def de_encode(out_length, in_length, input_buf, lowercase=False):
    """
    This just encodes as hex... wow.
    """
    out_buf = bytearray(out_length)

    pref = ord('7')
    if lowercase:
        pref = ord('W')
    
    i4 = 0
    idx = 0
    while idx < in_length:
        unk5 = i4 + 2
        if out_length <= unk5:
            break
        
        tmp = input_buf[idx]
        idx += 1
        unk3 = (pref + (tmp >> 4)) & 0xff
        if tmp < 0xa0:
            unk3 = tmp >> 4 | 0x30
        tmp = tmp & 0xf
        
        out_buf[i4] = unk3
        unk3 = (pref + tmp) & 0xff
        if tmp < 10:
            unk3 = tmp | 0x30
        
        out_buf[i4 | 1] = unk3
        i4 = unk5
    
    return out_buf


def irc_password(ts, auth_code, nonce):
    ts_mod = ts % 0x21d
    ac_mod = auth_code % 0x21d
    
    md5_inps = [
        psk,
        psk[ac_mod:],
        nonce.encode('ascii'),
        psk,
        psk[ts_mod:]
    ]
    md5_inps_lengths = [
        ac_mod,
        0x21d - ac_mod,
        len(nonce),
        ts_mod,
        0x21d - ts_mod
    ]
    
    md5s = [hashlib.md5(), hashlib.md5()]
    
    for i in range(17):
        idx = i % 5
        md5_inp_len = md5_inps_lengths[idx]
        md5_inp = md5_inps[idx][:md5_inp_len]
        # print(md5_inp_len, md5_inp)
        md5s[i & 1].update(md5_inp)
    
    # digest and XOR
    res = [h.digest() for h in md5s]
    xord = bytes(a ^ b for a, b in zip(*res))
    
    # isn't this just converting endianess?
    uint_max = 2**32-1
    ts_le = (ts << 0x18) & uint_max | ((ts >> 8 & 0xff) << 0x10) & uint_max | ((ts >> 0x10 & 0xff) << 8) & uint_max | ts >> 0x18
    
    buf = ts_le.to_bytes(0x4, 'little') + xord
    res = binascii.hexlify(buf).decode('ascii')
    check = de_encode(41, 0x14, buf, True)[:-1].decode('ascii')
    
    if res != check:
        print('Encoding difference:', res, '!=', check)
        return check
    
    return res

def create_auth_message(word, word_eol, userdata):
    if word[3] != ':Auth':
        return None
    
    # todo implement app based auth
    nick = ''
    user_id = ''
    nonce = 'accountId=&nonce='
    
    auth_code = word[4].partition(':')[0]
    ts = int(time.time())
    auth_code = int(auth_code, 16)
    res_str = irc_password(ts  & 0x7fffffff, auth_code & 0x7fffffff, nonce)
    hexchat.prnt('Computed auth code: ' + res_str)
    hexchat.command('RAW NICK {}'.format(nick))
    hexchat.command('RAW USER  {} 0 * {}'.format(user_id, res_str))
    return None

def user_hook(word, word_eol, userdata):
    return hexchat.EAT_HEXCHAT

# Doesn't work, the login is hardcoded
# hexchat.hook_command('USER', user_hook, priority=hexchat.PRI_HIGHEST)
hexchat.hook_server("NOTICE", create_auth_message, priority=hexchat.PRI_HIGHEST)
print('Hooked commands.')
