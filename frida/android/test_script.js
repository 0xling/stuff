var library_name = "libnative-lib.so";
var library_loaded = 0;
var lib_base = 0;

function hook_lib_native(){
    Interceptor.attach(ptr(lib_base).add(0x13221), {
        onEnter: function (args) {
            var r0 = this.context.r0;
            var r1 = this.context.r1;
        }, onLeave: function (retval) {
        }
    });

    Interceptor.attach(lib_base.add(0x1B5A5), function (args) {
            console.log('enter fun');
        }
    );
}

function hook_native() {
    Interceptor.attach(Module.findExportByName(null, 'android_dlopen_ext'),{
        onEnter: function(args){
            // first arg is the path to the library loaded
            var library_path = Memory.readCString(args[0])
            if( library_path.includes(library_name)){
                console.log("[...] Loading library : " + library_path)
                library_loaded = 1
            }
        },
        onLeave: function(args){
            // if it's the library we want to hook, hooking it
            if(library_loaded ==  1){
                console.log("[+] Loaded")
                lib_base = Module.getBaseAddress(library_name);
                console.log('libc_base:', lib_base.toString(16));
                //hook_lib_native();
                library_loaded = 0
            }
        }
    })
}

setImmediate(hook_native)