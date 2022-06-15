# HexChat stuff

- `hexchat_disablelogin.patch` is needed to disable the default IRC login, which will fail and disconnect
- `hexchat_plugin.py` can be loaded in a modified HexChat to connect to the Warframe IRC, requires manually filling in some fields

The Warframe IRC IP address can be obtained either from the Frida script's log or login response. They are using SSL on ports 6695-6699.

A pre-built version of HexChat with the patch applied can be downloaded here: https://github.com/derrod/hexchat/releases/tag/v2.16.1-custom

This will still need the following:
- Python3 in `%PATH%` (tested with 3.6 and 3.8)
- Nick, user-id, and valid nonce in `hexchat_plugin.py`
- Loading `hexchat_plugin.py` *before* connecting
- Connecting using preconfigured "Warframe IRC" server

**Note:** If you have a rooted phone the userid/nonce can be obtained from the Warframe Companion config file at `/data/data/com.digitalextremes.warframenexus/shared_prefs/titanium.xml` (see `playerInfo`).
