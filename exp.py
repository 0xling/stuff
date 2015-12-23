from zio import *

target = ('119.254.101.197', 10000)
target = './test'


def exp(target):
    io = zio(target, timeout=10000, print_read=COLORED(RAW, 'red'), print_write=COLORED(RAW, 'green'))

    io.gdb_hint()
    io.interact()


exp(target)
