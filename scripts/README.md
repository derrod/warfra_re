# Scripts

- `decrypt_resources.py` will decrypt encrypted assets in the app (which is most of the business logic, it's an embedded web app using TitaniumSDK)
- `frida_utilities.py` will attach to the Android app and log various pieces of information such as keys, salts, and disables SSL verficiation and redirects IRC connections to a local server
  + This was created for the 32-bit ARM variant of version 4.15.3.0 of the app, but should work with newer version and on 64-bit as well
- `psk.bin` is the pre-shared secret data that is used to create the IRC password and sign http requests


## Logging HTTP(S) and IRC traffic from the app

### HTTP(S)

The basic HTTP(S) traffic of the app can be intercepted via setting a proxy in the Android system configuration, however this does not include any of the *interesting* communication (anything that goes through the native code).  
On Android <= 6.0 you can simply use [Fiddler Classic](https://www.telerik.com/fiddler/fiddler-classic) or tools such as burp after installing the root certificate.

To intercept native traffic you can use a local DNS or hosts file change to redirect `mobile.warframe.com` to your Fiddler instance, and then use `!listen 443 mobile.warframe.com` to turn your Fiddler instance into a transparent proxy.  
Note that this will require launching the app with the Frida script to disable SSL verification.

### IRC

When running the frida script IRC connections are redirected to a specified IP on port 6695, adjust the IP according to your local needs.

The simplest option for loggin is to use [stcppipe](http://aluigi.altervista.org/mytoolz.htm#stcppipe) and run it like so:
```shell
./stcppipe -D -S <IRC IP> 6695 6695
```
This will log all data to the console. For more sophisticated logging you can use `-d <path/to/directory>` which will create a `.pcap` file you can analyse.  
Generally this isn't super interesting since you can just connect to the IRC directly.
