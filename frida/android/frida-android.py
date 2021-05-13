import time
import frida
import sys

def on_message(message, data):
    print(message)

device = frida.get_usb_device()
appname = "com.kanxue.ollvm_ndk_9"

is_spawn = True
is_hookstart = True
if is_spawn:
    if is_hookstart:
        pid = device.spawn([appname])
        session = device.attach(pid)
    else:
        pid = device.spawn([appname])
        device.resume(pid)
        time.sleep(1)  # Without it Java.perform silently fails
        session = device.attach(pid)
else:
    session = device.attach(appname)

with open('test_script.js') as f:
    script = session.create_script(f.read())
script.on('message', on_message)

script.load()

if is_spawn & is_hookstart:
    device.resume(pid)

sys.stdin.read()