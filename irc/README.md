# Warframe IRC

The Warframe in-game chat is based on IRC. For the most part it appears to be standard, and run a customised version of InspIRCd.

The following things are required to authenticate and chat on the Warframe IRC:

- Read `NOTICE` message sent on connect, get the auth code from it (`:Auth <code>:`)
- Compute token based on auth code, current unix timestamp, and nonce (see `irc_password.py`)
- Send `NICK` message with your in-game nick
- Send `USER` message with the following parameters: `USER <account id> 0 * <token>`

The channel list can be downloaded from the servers. Most channel names use shorthands, for example "#Q_EN_EU" or "#G_EN_EU", where the first letter is a prefix denoting the type of chat, and the latter part the region and language.

Most prefixes are relatively easy to guess, "G" for "General", "T" for "Trading", "R" for "Recruiting", and "Q" for "Q&A". There are channels for specific zones and clans as well. The latter are prefixed with "C" followed by the Clan ID.

**Note:** If you have a rooted phone the IP and userid/nonce can be obtained from the Warframe Companion config file at `/data/data/com.digitalextremes.warframenexus/shared_prefs/titanium.xml` (see `playerInfo`).

## HexChat plugin

See the `hexchat/` folder for details
