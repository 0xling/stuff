import winappdbg
from winappdbg import Process, HexDump


class DebugEvents(winappdbg.EventHandler):
    def load_dll(self, event):
        module = event.get_module()
        logstring = "\nLoaded DLL:\nName: %s\nFilename: %s\nBase Addr: %s" % \
                    (module.get_name(), module.get_filename(), hex(module.get_base()))
        print(logstring)
        print (module.get_handle())


def set_breakpoint(debug, address, callback_function):
    print ('bp addr=0x%x' % address)
    pid = debug.get_debugee_pids()[0]
    debug.break_at(pid, address, action=callback_function)


def handler(event):
    thread = event.get_thread()
    context = thread.get_context()
    print ('context=%s, type=%s' % (context, type(context)))
    esp = context['Esp']
    pbuff = event.get_process().read_pointer(esp + 4)
    print ('pbuff=0x%x' % pbuff)
    buff = event.get_process().read_string(pbuff, 10)
    print ('buff=%s' % buff)
    event.get_process().write(pbuff, 'ling ling')
    context['Edx'] = 0
    thread.set_context(context)


is_attach = False


def main():
    # debug = winappdbg.Debug(eventHandler=DebugEvents())
    debug = winappdbg.Debug()
    try:
        if is_attach:
            # pid = 5744
            # my_process = debug.attach(pid)
            debug.system.scan()
            for (process, name) in debug.system.find_processes_by_filename('hello32.exe'):
                print ("Found %d, %s" % (process.get_pid(), process.get_filename()))
            my_process = debug.attach(process.get_pid())
        else:
            my_process = debug.execv(['hello32.exe'], bConsole=True)  # bConsole must be true for console program.
        # my_process = debug.execv(['hello32.exe', '123'])

        print ("Attached to %d - %s" % (my_process.get_pid(), my_process.get_filename()))

        main_base = my_process.get_image_base()
        print ('main_base=%x' % (main_base))

        set_breakpoint(debug, main_base + 0x412572 - 0x400000, handler)
        # Keep debugging until the debugger stops
        debug.loop()

    finally:
        # Stop the debugger
        debug.stop()
        print ("Debugger stopped.")


if __name__ == "__main__":
    main()
