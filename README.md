# Warframe App Reverse Engineering

**Disclaimer: While these scripts mimic the behaviour of the official app(s) and only interact in with the API in a read-only manner, they may still violate the Warframe or Digital Extremes EULA/TOS and any usage of them is at your own risk.**

This repo contains some scripts and tool written while reverse-engineering the Warframe Mobile API.
This currently is limited to authentication and the IRC-based chat.

Most of the work was done with Ghidra for reversing the native code and jadx to look at the Java bindings. Beyond that it's mostly been Frida to hook into both native and Java code. See the `scripts/` folder for more information.

Included are the following things right now:
- `api/`
  + `login.py` - little helper to illustrate how to login into your account and fetch basic info
  + `sign_request.py` - Python implementation for web request signing
  + `README` contains some more information about the API
- `irc/`
  + `hexchat/`
    * `hexchat_disablelogin.patch` - Disables automatic login in HexChat (required to use plugin)
    * `hexchat_plugin.py` - HexChat script to handle Warframe server login (requires manually filling in some info)
  + `irc_password.py` - Python implementaion of the IRC password derivation algorithm`
  + `README` contains additional information about the Warframe IRC and custom authentication system
- `scripts/`
  + `decrypt_resources.py` - decrypt JavaScript of the app's embedded web UI
  + `frida_utilities.py` - Frida script with large amount of hooks for obtaining keys, disable SSL verification, etc.
  + `README` contains additional information on how the frida script works and how to intercept the app's traffic for inspection
- `twitch/`
  + `arsenal.py` - Script to fetch loadout information for users that have enabled loadout sharing for the arsenal extension
