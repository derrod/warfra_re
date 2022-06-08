import time
import hashlib
import binascii

psk = open('../scripts/psk.bin', 'rb').read()


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
    
    # This is what the decompiler spit out, turns out, this is just swapping endianess
    # uint_max = 2**32-1
    # ts_be = (ts << 0x18) & uint_max | ((ts >> 8 & 0xff) << 0x10) & uint_max | ((ts >> 0x10 & 0xff) << 8) & uint_max | ts >> 0x18
    
    buf = ts.to_bytes(0x4, 'big') + xord
    res = binascii.hexlify(buf).decode('ascii')
    check = de_encode(41, 0x14, buf, True)[:-1].decode('ascii')
    
    if res != check:
        print('Encoding difference:', res, '!=', check)
        return check
    
    return res


if __name__ == '__main__':
    ts = 1654444444  # unix timestamp
    nonce = 'accountId=&nonce='  # account id and nonce from login response
    auth_code = 0x0  # auth code from NOTICE on connecting to the IRC server
    should_be = ''  # known good result, for testing
    
    res_str = irc_password(ts  & 0x7fffffff, auth_code & 0x7fffffff, nonce)
    
    if res_str == should_be:
        print('Success!', res_str, '==', should_be)
    else:
        print('Fail!', res_str, '!=', should_be)
