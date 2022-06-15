# Mobile API

## Login process

Before we can begin, we need a cookie we get after completing the captcha. The way this works is *peculiar* to say the least.

To get a working captcha response cookie we need to hash our username, password, and a static salt from the app. This works as following: `whirlpool( salt + email + '/' + whirlpool(password))`.

The salt for the current app version (in hexadecimal) is `7714ae5c45fd1c5991daada98fbbe4e41d907323d7375120cb111d2b3f4a3502`.  
In python, you can do this by using the included whirpool implementation in hashlib (`hashlib.new('whirlpool')`).

Example:
```python
import hashlib
from binascii import hexlify, unhexlify

pwhash = hashlib.new('whirlpool', '<password>'.encode('utf-8')).hexdigest()
buf = unhexlify('7714ae5c45fd1c5991daada98fbbe4e41d907323d7375120cb111d2b3f4a3502')
buf += '<email>/{}'.format(pwhash).encode('utf-8')

print('Result:', hashlib.new('whirlpool', buf).hexdigest())
```

Finally, open `https://mobile.warframe.com/api/mobileCaptcha/mblCaptcha.php?input=<hash>` in a browser and verify the captcha. Afterwards, grab the `wfarggdsh` cookie, that is your `c` variable for the login.

Finall, we sent a POST request to `https://mobile.warframe.com/api/login.php` with the following body:

```json
{
  "email": "<user email>",
  "password": "<Whirlpool hash of password>",
  "date": <unique device ID>,
  "appVersion": "4.15.3.0",
  "c": "<captcha cookie>",
  "os": "android",
  "time": <current time>
}
```

Noteworthy here is that `date` is not a date at all, it's a unique ID for the device.
It is random and created weirdly (like everything else here), something like this:

```python
import math
from uuid import uuid4

uuid = str(uuid4()).replace('-', '')
date = int(uuid, 16)
shave = math.floor(math.log(date) / math.log(10)) -15
if shave > 0:
    date = math.floor(date / 10**shave)

print('date:', date)
```

Note that you may receive an error response indicating you need to 2FA or a session is still active.
- Status code 400 & `new hardware detected`: wait for the 2FA code in your email, then sent another POST with an empty JSON object body `{}` to `https://mobile.warframe.com/api/authorizeNewHwid.php?code=<2fa code>` and try again
- Status code 409 & `Login failed; nonce still set`: Resend login request, but add `"kick": 1` to the JSON body

## Logout

Decidedly simpler; the logout works by sending a POST request with an empty JSON object (`{}`) to `https://mobile.warframe.com/api/logout.php?accountId=<Nonce>&nonce=<Nonce>`

## Inventory

Slightly misnamed, but this contains pretty much every piece of information about your account you could ask for, including when it was created!

Send a post to `https://mobile.warframe.com/api/inventory.php?accountId=<account id>&nonce=<nonce>` with empty JSON object in the body (`{}`) and peruse the data to your liking.

### Request signing

Some requests, such as starting a process in the foundry, are signed. See `sign_request.py` for a python implementation of how it works.
