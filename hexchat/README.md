# HexChat stuff

- `hexchat_disablelogin.patch` is needed to disable the default IRC login, which will fail and disconnect
- `hexchat_plugin.py` can be loaded in a modified HexChat to connect to the Warframe IRC, requires manually filling in some fields

The Warframe IRC IP address can be obtained either from the Frida script's log or login response. They are using SSL on ports 6695-6699
