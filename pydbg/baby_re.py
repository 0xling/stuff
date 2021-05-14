from pydbg import *
from pydbg.defines import *
from zio import *

def handler2(dbg):
    ecx = dbg.context.Ecx
    eax = dbg.context.Eax
    arg3 = l32(dbg.read(0x41AAF4, 4))
    print ('arg3=%x, arg2=%x, arg1=%x' %(arg3, eax, ecx))
    return DBG_CONTINUE

def handler3(dbg):
    eax = dbg.context.Eax
    arg3 = l32(dbg.read(0x41AAF4, 4))
    print ('arg3=%x, ret=%x' %(arg3, eax))
    return DBG_CONTINUE

def anti_debug(dbg):
    dbg.set_register('eip', 0x4158EE)
    return DBG_CONTINUE

def print_eax(dbg):
    eax = dbg.context.Eax
    cl = dbg.context.Ecx & 0xff
    print ('write_byte: eax=%x, cl=%x' %(eax, cl))
    return DBG_CONTINUE

def print_xor(dbg):
    eax = dbg.context.Eax
    ecx = dbg.context.Ecx
    print ('xor: eax=%x, ecx=%x' %(eax, ecx))
    return DBG_CONTINUE

def print_byte(dbg):
    eax = dbg.context.Eax
    cl = dbg.context.Ecx & 0xff
    print ('get_byte: eax=%x, cl=%x' %(eax, cl))
    return DBG_CONTINUE

def main():

    target = './bbbbbbaby_re.exe.patched.exe'
    dbg = pydbg()

    dbg.load(target, create_new_console=True)

    dbg.bp_set(0x415787, handler=handler2)
    dbg.bp_set(0x41578C, handler=handler3)
    dbg.bp_set(0x4158DB, handler=anti_debug)
    dbg.bp_set(0x41598A, handler=print_eax)
    dbg.bp_set(0x4158A7, handler=print_xor)
    dbg.bp_set(0x415804, handler=print_byte)

    dbg.run()

main()
