import frida

def on_message(m, _data):
    if m['type'] == 'send':
        print(m['payload'], _data if _data else '')
    elif m['type'] == 'error':
        print(m)


jscode = """
var has_sent_key = false;

Java.perform(function () {
    // Function to hook is defined here
    
    // Redirect IRC connection and log login details
    let DeUtilModule = Java.use("com.digitalextremes.deutil.DeUtilModule");
    DeUtilModule["login"].implementation = function (str, str2, str3, str4) {
        console.log('[*] login is called' + ', user name: ' + str + ', user id: ' + str2 + ', auth code: ' + str3 + ', nonce string: ' + str4);
        let ret = this.login(str, str2, str3, str4);
        // console.log('login ret value is ' + ret);
        return ret;
    };

    DeUtilModule["openConnection"].implementation = function (strArr, krollFunction, z) {
        console.log('[*] openConnection is called, IP(s): ' + strArr + ', callback: ' + krollFunction + ', IPv6: ' + z);
        const testArr = Java.array('java.lang.String', [ '10.0.10.12' ]);
        console.log('[!] Overwrote IP with: ' + testArr);
        let ret = this.openConnection(testArr, krollFunction, z);
        // console.log('openConnection ret value is ' + ret);
        return ret;
    };
    
    // Getting the asset decryption key
    let Binding = Java.use("ti.cloak.Binding");
    Binding["getKey"].implementation = function (bArr) {
        let ret = this.getKey(bArr);
        if (!has_sent_key) {
            console.log('[*] getKey is called with IV: ' + bArr);
            console.log('[>] getKey returned AES key: ' + ret);
            has_sent_key = true;
        }
        return ret;
    };
    
    // Getting the captcha salt
    DeUtilModule["getSalt"].implementation = function () {
        console.log('[*] getSalt is called');
        let ret = this.getSalt();
        console.log('[*] getSalt ret value is ' + ret);
        return ret;
    };

    let AssetCryptImpl = Java.use("com.digitalextremes.warframenexus.AssetCryptImpl");
    AssetCryptImpl["getAssetStream"].implementation = function (str) {
        // console.log('getAssetStream is called' + ', ' + 'str: ' + str);
        let ret = this.getAssetStream(str);
        // console.log('getAssetStream ret value is ' + ret);
        return ret;
    };

    AssetCryptImpl["$init"].implementation = function () {
        // console.log('$init is called');
        let ret = this.$init();
        // console.log('$init ret value is ' + ret);
        return ret;
    };
});
"""

# NOTICE: These are the offests from the 32 bit ARM binary of app version 4.15.3.0 (The only rooted phone I had on hand was an old Nexus 5)
# Offsets were obtained by running `nm --demangle --dynamic <path/to/libdeutil.so>` and then grep'ing for the desired functions
jscode_native = """
var moduleName = "libdeutil.so";

var md5_update_addr = 0x0008f7d9;
var ircpassword_addr = 0x00057cd9;
var downloadurl_ndk_addr = 0x000570d1;
var downloadurl_addr = 0x00057651;
var signpost_addr = 0x000573b1;
var ssl_set_verify_addr = 0x00067c77;
var ssl_verify_result_addr = 0x00068a5f;
var portstr_addr = 0x13E8F0;  // Address of "6695-6699" port range
var curl_setopt_addr = 0x000be695;
var sha256_update_addr = 0x000a1331;

Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        this.lib = Memory.readUtf8String(args[0]);
        // console.log("[*] dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
        if (this.lib.endsWith(moduleName)) {
            var baseAddr = Module.findBaseAddress(moduleName);
            send('[*] Opened libdeutil, adding interceptors...');
            // Change IRC port range
            Memory.patchCode(baseAddr.add(portstr_addr), 5, _bytes => {
                // 6695 + NULL
                _bytes.writeByteArray([ 54, 54, 57, 53, 0]);
            });
            
            // Disable IRC SSL verification
            Interceptor.attach(baseAddr.add(ssl_set_verify_addr), {
                onEnter: function(args) {
                    send('[*] Modifiying SSL_CTX_set_verify: ' + args[1] + ' -> 0');
                    args[1] = ptr(0);
                }
            });
            Interceptor.attach(baseAddr.add(ssl_verify_result_addr), {
                onLeave: function(_retval) {
                    send('[*] Changing SSL_get_verify_result: ' + _retval + ' -> 0');
                    _retval.replace(0);
                }
            });
            
            // SHA256 signing debugging
            Interceptor.attach(baseAddr.add(sha256_update_addr), {
                onEnter: function(args) {
                    send('[*] SHA256_Update invoked, length: ' + parseInt(args[2], 16), args[1].readByteArray(parseInt(args[2], 16)));
                }
            });
            // MD5 signing debugging
            Interceptor.attach(baseAddr.add(md5_update_addr), {
                onEnter: function(args) {
                    send('[*] MD5_Update invoked, length: ' + parseInt(args[2], 16), args[1].readByteArray(parseInt(args[2], 16)));
                }
            });
            // IRC Password 
            Interceptor.attach(baseAddr.add(ircpassword_addr), {
                onEnter: function(args) {
                    send('[*] ircPassword invoked, time: ' + parseInt(args[1], 16) + ', auth code: ' + args[2] + ', string: ' + args[3].readCString());
                }
            });
            
            // Download stuff
            Interceptor.attach(baseAddr.add(downloadurl_addr), {
                onEnter: function(args) {
                    send('[*] downloadUrl invoked, arg0: ' + args[0].readCString() + ', arg1: ' + args[1] + ', arg2: ' + args[2].readCString() + ', arg3: ' + args[3].readCString());
                }
            });
            Interceptor.attach(baseAddr.add(downloadurl_ndk_addr), {
                onEnter: function(args) {
                    send('[*] NDK downloadUrl invoked, api code: ' + parseInt(args[2], 16) + ', url: ' + args[3].readPointer().readCString() + ', params: ' + args[4].readPointer().readCString() + ', sign: ' + parseInt(args[5], 16));
                }
            });
            // HTTP request signing
            Interceptor.attach(baseAddr.add(signpost_addr), {
                onEnter: function(args) {
                    send('[*] SignPost invoked, arg0: ' + args[0].readCString() + ', arg1: ' + args[1].readCString() + ', arg2: ' + args[2].readCString());
                }
            });
            // cURL SSL verification
            Interceptor.attach(baseAddr.add(curl_setopt_addr), {
                onEnter: function(args) {
                    var curl_opt = parseInt(args[1], 16);
                    if (curl_opt == 64 || curl_opt == 81) { // CURLOPT_SSL_VERIFYPEER & CURLOPT_SSL_VERIFYHOST
                        send('[*] Modifying curl_easy_setopt option: ' + curl_opt + ', value: ' + parseInt(args[2], 16) + ' -> 0');
                        args[2] = ptr(0);
                    }
                }
            });
        }
    }
});
"""


if __name__ == '__main__':
    app_id = 'com.digitalextremes.warframenexus'

    device = frida.get_usb_device()
    pid = device.spawn([app_id])
    session = device.attach(pid)
    print('Injecting native code script...')
    native_script = session.create_script(jscode_native)
    native_script.on('message', on_message)
    native_script.load()
    device.resume(app_id)
    
    # This script will crash if it is injected too soon
    print('Injecting Java script...')
    script = session.create_script(jscode)
    script.on('message', on_message)
    script.load()

    # keep hook alive
    from sys import stdin
    stdin.read()
