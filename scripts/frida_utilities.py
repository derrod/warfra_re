import frida

def on_message(m, _data):
    if m['type'] == 'send':
        print(m['payload'], _data if _data else '')
    elif m['type'] == 'error':
        print(m)

# Note: Adjust the IRC IP (new_irc_ip) and Warframe API reverse proxy (new_hostname) according to your Fiddler/stcpipe setup
jscode = """
var has_sent_key = false;
var new_irc_ip = '10.0.10.12';

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
        const testArr = Java.array('java.lang.String', [ new_irc_ip ]);
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

jscode_native = """
var moduleName = "libdeutil.so";

// 6695-6699
const portPattern = '36 36 39 35 2d 36 36 39 39'
// New hostname/ip to resolve "mobile.warframe.com" to (e.g. Fiddler reverse-proxy)
const new_hostname = '10.0.10.12'
var hostname_ptr = null;

Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        this.lib = Memory.readUtf8String(args[0]);
        // console.log("[*] dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
        if (this.lib.endsWith(moduleName)) {
            const module = Process.getModuleByName(moduleName);
            send('[*] Opened libdeutil, adding interceptors...');

            // Search for port range string
            const results = Memory.scanSync(module.base, module.size, portPattern);
            if (results.length > 0) {
                // Overwrite port range string
                Memory.patchCode(results[0].address, 5, _bytes => {
                    // Overwrite port range with "6695" + NULL terminator
                    _bytes.writeByteArray([ 54, 54, 57, 53, 0]);
                });
            } else {
                send('[!] Port range string was not found');
            }

            // Disable IRC SSL verification
            var ssl_set_verify_addr = module.findExportByName('SSL_CTX_set_verify');
            if (ssl_set_verify_addr != null) {
                Interceptor.attach(ssl_set_verify_addr, {
                    onEnter: function(args) {
                        send('[*] Modifiying SSL_CTX_set_verify: ' + args[1] + ' -> 0');
                        // Set SSL verification mode to SSL_VERIFY_NONE
                        args[1] = ptr(0);
                    }
                });
            } else {
                send('[!] Could not find SSL_CTX_set_verify');
            }

            // Make sure that the SSL verify result check always returns a success
            var ssl_verify_result_addr = module.findExportByName('SSL_get_verify_result');
            if (ssl_verify_result_addr != null) {
                Interceptor.attach(ssl_verify_result_addr, {
                    onLeave: function(_retval) {
                        send('[*] Changing SSL_get_verify_result: ' + _retval + ' -> 0');
                        // Change result to X509_V_OK regardless of actual result
                        _retval.replace(0);
                    }
                });
            } else {
                send('[!] Could not find SSL_get_verify_result');
            }

            // SHA256 signing debugging
            var sha256_update_addr = module.findExportByName('SHA256_Update');
            if (sha256_update_addr != null) {
                Interceptor.attach(sha256_update_addr, {
                    onEnter: function(args) {
                        // send('[*] SHA256_Update invoked, length: ' + parseInt(args[2], 16), args[1].readByteArray(parseInt(args[2], 16)));
                    }
                });
            } else {
                send('[!] Could not find SHA256_Update');
            }

            // MD5 signing debugging
            var md5_update_addr = module.findExportByName('MD5_Update');
            if (md5_update_addr != null) {
                Interceptor.attach(md5_update_addr, {
                    onEnter: function(args) {
                        send('[*] MD5_Update invoked, length: ' + parseInt(args[2], 16), args[1].readByteArray(parseInt(args[2], 16)));
                    }
                });
            } else {
                send('[!] Could not find MD5_Update');
            }

            // Java -> Native bridge has a separate entrypoint that then calls downloadUrl
            var downloadurl_ndk_addr = module.findExportByName('Java_com_digitalextremes_deutil_DeUtilModule_downloadUrl');
            if (downloadurl_ndk_addr != null) {
                Interceptor.attach(downloadurl_ndk_addr, {
                    onEnter: function(args) {
                        send('[*] NDK downloadUrl invoked, api code: ' + parseInt(args[2], 16) + ', url: ' + args[3].readPointer().readCString() + ', params: ' + args[4].readPointer().readCString() + ', sign: ' + parseInt(args[5], 16));
                    }
                });
            } else {
                send('[!] Could not find Java_com_digitalextremes_deutil_DeUtilModule_downloadUrl');
            }

            // cURL SSL verification
            var curl_setopt_addr = module.findExportByName('curl_easy_setopt');
            if (curl_setopt_addr != null) {
                Interceptor.attach(curl_setopt_addr, {
                    onEnter: function(args) {
                        var curl_opt = parseInt(args[1], 16);
                        // Modify value set for CURLOPT_SSL_VERIFYPEER (64) and CURLOPT_SSL_VERIFYHOST (81) to 0
                        if (curl_opt == 64 || curl_opt == 81) {
                            send('[*] Modifying curl_easy_setopt option: ' + curl_opt + ', value: ' + parseInt(args[2], 16) + ' -> 0');
                            args[2] = ptr(0);
                        }
                    }
                });
            } else {
                send('[!] Could not find curl_easy_setopt');
            }

            // cURL Name resolution
            var curl_resolve_addr = module.findExportByName('Curl_resolv');
            if (curl_resolve_addr != null) {
                Interceptor.attach(curl_resolve_addr, {
                    onEnter: function(args) {
                        var hostname = args[1].readCString();
                        send('[*] Curl_resolv was called with hostname: ' + hostname + ', port: ' + parseInt(args[2], 16));
                        // redirect to local proxy
                        if (hostname == "mobile.warframe.com") {
                            send('[*] Modifying Curl_resolv hostname: ' + hostname + ' -> ' + new_hostname);
                            if (!hostname_ptr) {
                                hostname_ptr = Memory.allocUtf8String(new_hostname);
                            }
                            args[1] = hostname_ptr;
                        }
                    }
                });
            } else {
                send('[!] Could not find Curl_resolv');
            }

            // These are not properly exported, so we have to use the mangled names
            // IRC Password 
            var ircpassword_addr = module.findExportByName('_Z11ircPasswordRPcjjPKc');  // ircPassword
            if (ircpassword_addr != null) {
                Interceptor.attach(ircpassword_addr, {
                    onEnter: function(args) {
                        send('[*] ircPassword invoked, time: ' + parseInt(args[1], 16) + ', auth code: ' + args[2] + ', string: ' + args[3].readCString());
                    }
                });
            } else {
                send('[!] Could not find ircPassword');
            }

            // Download stuff
            var downloadurl_addr = module.findExportByName('_Z11downloadUrlPKcP12MemoryStructPcS3_');  // downloadUrl
            if (downloadurl_addr != null) {
                Interceptor.attach(downloadurl_addr, {
                    onEnter: function(args) {
                        send('[*] downloadUrl invoked, arg0: ' + args[0].readCString() + ', arg1: ' + args[1] + ', arg2: ' + args[2].readCString() + ', arg3: ' + args[3].readCString());
                    }
                });
            } else {
                send('[!] Could not find downloadUrl');
            }

            // HTTP request signing
            var signpost_addr = module.findExportByName('_Z8SignPostPKcS0_RPc'); // SignPost
            if (signpost_addr != null) {
                Interceptor.attach(signpost_addr, {
                    onEnter: function(args) {
                        send('[*] SignPost invoked, arg0: ' + args[0].readCString() + ', arg1: ' + args[1].readCString() + ', arg2: ' + args[2].readCString());
                    }
                });
            } else {
                send('[!] Could not find SignPost');
            }
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
    print('Listening for events...')
    from sys import stdin
    stdin.read()
