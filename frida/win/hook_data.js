var main_base = 0;
var ida_base = 0x400000;
var mem = Memory.alloc(20);

function rebase_addr(addr){
    return ptr(main_base).sub(ida_base).add(addr);
}

function native_hook(){
    // get function addr
    //var addr = Module.findExportByName('kernel32.dll', 'LoadLibraryA');
    //console.log('address:', addr);

    // get base addr
    //var base_addr= Module.getBaseAddress("hello-32.exe");
    //console.log('base address', base_addr);

    var process_Obj_Module_Arr = Process.enumerateModules();
    for(var i = 0; i < process_Obj_Module_Arr.length; i++) {
        console.log('name:', process_Obj_Module_Arr[i].name, 'base:', process_Obj_Module_Arr[i].base, 'size:', process_Obj_Module_Arr[i].size.toString(16));
        if(process_Obj_Module_Arr[i].name.endsWith('.exe')){
            main_base = process_Obj_Module_Arr[i].base;
            break;
        }
    }

    console.log('base address', main_base);

    console.log('hook addr:', rebase_addr(0x411208));
    Interceptor.attach(rebase_addr(0x411208), {
        onEnter: function (args) {
            console.log('');
            console.log('[+] Called printf' );
            console.log('[+] Ctx: ' + args[0]);
            console.log('[+] Input: ' + args[1]); // Plaintext
            var sp = this.context.sp;
            var a1 = ptr(sp).add(8).readU32();
            console.log('a1:', a1.toString(16));
            console.log('buff:', ptr(a1).readCString());
            Memory.protect(ptr(a1), 8, 'rw-');
            ptr(a1).writeByteArray([0x31, 0x32]);
            console.log('mem:', mem);
            //mem.writeByteArray([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x0]);
            Memory.copy(mem, ptr(a1), 10);
            ptr(sp).add(8).writePointer(mem);
            //ptr(sp).add(8).writeU32(mem.toInt32());
            var a1 = ptr(sp).add(8).readU32();
            console.log('mem2:', ptr(a1));
            console.log('data:', ptr(a1).readCString());
        },

        // When function is finished
        onLeave: function (retval) {
            console.log('[+] Returned from SetAesDeCrypt0: ' + retval);
        }
    });
}

native_hook()