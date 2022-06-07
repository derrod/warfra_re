# Scripts

- `decrypt_resources.py` will decrypt encrypted assets in the app (which is most of the business logic, it's an embedded web app using TitaniumSDK)
- `frida_utilities.py` will attach to the (32 bit) app and log various pieces of information such as keys, salts, and disables SSL verficiation and redirects IRC connections to a local server
  + This was created for the 32-bit ARM variant of version 4.15.3.0 of the app. The Java hooking should also work with the 64 bit ARM version however
- `irc_password.py` is a python implementation of the algorithm to create the IRC connection password (which is passesd as the "realname" in the `USER` message)
- `psk.bin` is the pre-shared secret data that is used to create the IRC password and sign http requests