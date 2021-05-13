import frida
import sys
import os
import time

def on_message(message, data):
    print(message)

is_spawn = True
use_pipe = True
program = './hello32.exe'
device = frida.get_local_device()
if is_spawn:
    if use_pipe:
        pid = device.spawn(program, stdio="pipe")
    else:
        pid = device.spawn(program)
    session = device.attach(pid)

else:
    session = device.attach(os.path.basename(program))
    #session = frida.attach(pid)

print (session)
print (dir(session))

with open('hook_data.js') as f:
    script = session.create_script(f.read())
script.on('message', on_message)
script.load()

if is_spawn:
    device.resume(pid)
    if use_pipe:
        def schedule_on_output(pid,  fd, data):
            print ('pid=%d, fd=%d, data=%s' %(pid, fd, data))

        device.input(pid, b'\n')
        device.on('output', schedule_on_output)


print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
sys.stdin.read()
session.detach()

