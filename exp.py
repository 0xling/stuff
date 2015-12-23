from threading import Thread

from zio import *

target = ('119.254.101.197', 10000)
target = './test'


def interact(io):
    def run_recv():
        while True:
            try:
                output = io.read_until_timeout(timeout=1)
            except:
                return

    t1 = Thread(target=run_recv)
    t1.start()
    while True:
        d = raw_input()
        if d != '':
            io.writeline(d)


def exp(target):
    io = zio(target, timeout=10000, print_read=COLORED(RAW, 'red'), print_write=COLORED(RAW, 'green'))

    io.gdb_hint()
    interact(io)


exp(target)

