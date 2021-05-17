import struct
import codecs
import os
try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    exit()

def l8(value):
    if isinstance(value, int):
        return struct.pack('<B', value)
    else:
        return struct.unpack('<B', value)[0]

def l16(value):
    if isinstance(value, int):
        return struct.pack('<H', value)
    else:
        return struct.unpack('<H', value)[0]

def l32(value):
    if isinstance(value, int):
        return struct.pack('<I', value)
    else:
        return struct.unpack('<I', value)[0]

def l64(value):
    if isinstance(value, int):
        return struct.pack('<Q', value)
    else:
        return struct.unpack('<Q', value)[0]

def REPR(s): return repr(str(s)) + '\r\n'
def EVAL(s):    # now you are not worried about pwning yourself
    st = 0      # 0 for normal, 1 for escape, 2 for \xXX
    ret = []
    i = 0
    while i < len(s):
        if st == 0:
            if s[i] == '\\':
                st = 1
            else:
                ret.append(s[i])
        elif st == 1:
            if s[i] in ('"', "'", "\\", "t", "n", "r"):
                if s[i] == 't':
                    ret.append('\t')
                elif s[i] == 'n':
                    ret.append('\n')
                elif s[i] == 'r':
                    ret.append('\r')
                else:
                    ret.append(s[i])
                st = 0
            elif s[i] == 'x':
                st = 2
            else:
                raise Exception('invalid repr of str %s' % s)
        else:
            num = int(s[i:i+2], 16)
            assert 0 <= num < 256
            ret.append(chr(num))
            st = 0
            i += 1
        i += 1
    return ''.join(ret)

def HEX(s): return codecs.encode(s, 'hex')
def UNHEX(s): s=str(s).strip(); return (len(s) % 2 and '0'+s or s).decode('hex') # hex-strings with odd length are now acceptable
def BIN(s): return ''.join([format(ord(x),'08b') for x in str(s)])
def UNBIN(s): s=str(s).strip(); return ''.join([chr(int(s[x:x+8],2)) for x in xrange(0,len(s),8)])
def RAW(s): return str(s)
def NONE(s): return ''

class OnBreakpoint(gdb.Breakpoint):
    def __init__(self, loc, callback):
        if isinstance(loc, int):
            loc = '*'+hex(loc)
        super(OnBreakpoint, self).__init__(loc, gdb.BP_BREAKPOINT, internal=False)
        self.callback = callback

    def stop(self):
        self.callback()
        return False

WP_ACCESS = 2
WP_READ = 1
WP_WRITE = 0

class OnHardBreakpoint(gdb.Breakpoint):
    def __init__(self, loc, callback, wp_class=WP_ACCESS):
        if isinstance(loc, int):
            loc = '*'+hex(loc)
        super(OnHardBreakpoint, self).__init__(loc, type=gdb.BP_WATCHPOINT, wp_class=wp_class, internal=False)
        self.callback = callback

    def stop(self):
        self.callback()
        return False


def execute_output(command):

    # create temporary file for the output
    filename = os.getenv('HOME') + os.sep + 'gdb_output_' + str(os.getpid())

    # set gdb logging
    gdb.execute("set logging file " + filename)
    gdb.execute("set logging overwrite on")
    gdb.execute("set logging redirect on")
    gdb.execute("set logging on")

    # execute command
    try:
        gdb.execute(command)
    except:
        pass

    # restore normal gdb behaviour
    gdb.execute("set logging off")
    gdb.execute("set logging redirect off")

    # read output and close temporary file
    outfile = open(filename, 'r')
    output = outfile.read()
    outfile.close()
    # delete file
    os.remove(filename)

    # split lines
    output = output.splitlines()

    return output

def get_reg(reg):
    #return execute_output('info registers '+reg)
    return int(gdb.parse_and_eval("$"+reg))

def set_reg(reg, value):
    return gdb.execute("set $"+reg+"="+str(value))

def read_mem(address, length):
    inferior = gdb.selected_inferior()
    return inferior.read_memory(address, length).tobytes()

def write_mem(address, value):
    inferior = gdb.selected_inferior()
    return inferior.write_memory(address, value)
