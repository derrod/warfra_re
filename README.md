# Warframe App Reverse Engineering

This repo contains some scripts and tool written while reverse-engineering the Warframe Mobile API.
This currently is limited to authentication and the IRC-based chat.

Most of the work was done with Ghidra for reversing the native code and jadx to look at the Java bindings. Beyond that it's mostly been Frida to hook into both native and Java code. See the `scripts/` folder for more information.

Included are the following things right now:
- `api/`
  + `login.py` - little helper to login into your account and fetch basic info
  + `whirlpool.py` - Pure-python implementaion of the whirlpool hash, but updated to work in python3
  + The `README` here contains some more info about the API
- `hexchat/`
  + `hexchat_disablelogin.patch` - Disables automatic login in HexChat (required to use plugin)
  + `hexchat_plugin.py` - HexChat script to handle Warframe server login (requires manually filling in some info)
- `scripts/`
  + `decrypt_resources.py` - decrypt JavaScript of the app's embedded web UI
  + `frida_utilities.py` - Frida script with large amount of hooks for obtaining keys, disable SSL verification, etc.
  + `irc_password.py` - Python implementaion of the IRC password derivation algorithm
