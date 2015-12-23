#!/bin/sh
import qiradb
from capstone import CS_MODE_32, Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import *
from pefile import *
from ELFfile import *
from zio import *
from Graph import *


class Tracer():
    def __init__(self, target, log, start_clnum=0, end_clnum=0):
        f = open(target, 'rb')
        self.data = f.read()
        f.close()
        self.target = target
        self.log = log

        self.os = self.get_os()
        if self.os is None:
            raise Exception('not supports os')

        self.arch = self.get_arch()
        if self.arch is None:
            raise Exception('not known arch')

        self.base = self.get_base()

        if self.os == 'windows':
            self.pe = PE(target)
        else:
            self.elf = Elf(target)

        if self.arch == 'i386':
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)

        if self.arch == 'i386':
            self.t = qiradb.Trace(log, 0, 4, 9, False)  # 32 bits
        else:
            self.t = qiradb.Trace(log, 0, 8, 17, False)  # 64 bits

        while not self.t.did_update():
            print "waiting..."
            time.sleep(0.1)

        self.disasms = {}
        # self.generate_trace(target, log, start_clnum, end_clnum, 4)

    def get_disasm(self, va):
        offset = self.get_offset_from_rva(va - self.base)
        #print hex(offset)
        if offset > len(self.data):
            return ''
        try:
            if self.disasms.has_key(va):
                insn = self.disasms[va]
                return insn.mnemonic + ' ' + insn.op_str
            for insn in self.md.disasm(self.data[offset:], va, count=1):
                disasm = insn.mnemonic + ' ' + insn.op_str
                self.disasms[va] = insn
                return disasm
        except:
            pass
        return ''

    def get_os(self):
        if self.data[0:4] == '\x7fELF':
            return 'linux'
        elif self.data[0:2] == 'MZ':
            return 'windows'
        return None

    def get_arch(self):
        if self.os == 'linux':
            value = l16(self.data[0x12:0x14])
            if value == 3:
                return 'i386'
            elif value == 0x3e:
                return 'x86_64'
        if self.os == 'windows':  # to modify
            return 'i386'
        return None

    def get_base(self, module_name=None):
        # default is the main module
        if module_name is None:
            f = open(log + '_base', 'rb')
            for line in f:
                line = line.strip()
                if line == '':
                    continue
                if self.os == 'linux':
                    pattern = '\.so'
                else:
                    pattern = '\.dll'
                matches = re.findall(pattern, line)
                if not matches:
                    f.close()
                    return long(line.split('-')[0], 16)
            f.close()
        else:
            f = open(log + '_base', 'rb')
            for line in f:
                if module_name in line:
                    f.close()
                    return long(line.split('-')[0], 16)
            f.close()
        return None

    def get_reg_name(self, index):
        if self.arch == 'i386':
            reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
            return reg_names[index / 4]
        else:
            reg_names = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13',
                         'r14', 'r15', 'rip']
            return reg_names[index / 8]

    def get_reg_index(self, name):
        reg_names2 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
        reg_names3 = ['ah', 'ch', 'dh', 'bh']
        reg_names4 = ['al', 'cl', 'dl', 'bl']
        for i in range(len(reg_names2)):
            if name == reg_names2[i]:
                return i | 0x400
        for i in range(len(reg_names3)):
            if name == reg_names3[i]:
                return i | 0x200
        for i in range(len(reg_names4)):
            if name == reg_names4[i]:
                return i | 0x100
        if self.arch == 'i386':
            reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip']
            for i in range(len(reg_names)):
                if name == reg_names[i]:
                    return i | 0x800
        else:
            reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d',
                         'r13d', 'r14d', 'r15d']
            for i in range(len(reg_names)):
                if name == reg_names[i]:
                    return i | 0x800
            reg_names5 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12',
                          'r13','r14', 'r15', 'rip']
            for i in range(len(reg_names5)):
                if name == reg_names5[i]:
                    return i | 0x1000

    def get_offset_from_rva(self, rva):
        if self.os == 'linux':  # to modify
            return self.elf.vma2offset(rva + self.base)
        else:
            return self.pe.get_offset_from_rva(rva)

    def is_branch(self, ins):
        if ins == '':
            return False
        opcode = ins.split(' ')[1]
        if opcode == 'ret':
            return True
        if opcode == 'call':
            return True
        if opcode.startswith('j'):
            return True
        return False

    def write_one_ins(self, out, clnum, ins, ops):
        result = str(clnum) + ': '
        result = result.ljust(8, ' ')
        result += ins.ljust(50, ' ')
        for op in ops:
            if self.arch == 'i386':
                result += op.ljust(24, ' ')
            else:
                result += op.ljust(36, ' ')
        out.write(result + '\n')

        if self.is_branch(ins):
            out.write('\n')

    def byte_to_value(self, bytes):
        result = ''
        for byte in bytes:
            result += chr(byte & 0xff)
        if len(result) == 1:
            return l8(result)
        elif len(result) == 2:
            return l16(result)
        elif len(result) == 4:
            return l32(result)
        elif len(result) == 8:
            return l64(result)
        raise Exception('not known len:%d' % len(result))

    def generate_trace(self, start_addr=None, start_clnum=0, end_clnum=0, limit=1):
        out = open(self.log + '.out', 'wb')
        if start_clnum == 0:
            start_clnum = self.t.get_minclnum()

        if end_clnum == 0:
            end_clnum = self.t.get_maxclnum()
        print 'start:', start_clnum
        print 'end:', end_clnum
        ins = ''
        ops = []

        start_record = True
        if start_addr is not None:
            start_record = False
        for i in range(start_clnum, end_clnum):
            changes = self.t.fetch_changes_by_clnum(i, limit)
            if len(changes) < 1:
                continue
            change = changes[0]
            #print change
            if change['type'] == 'I':
                if not start_record:
                    pc = change['address']
                    if pc == start_addr:
                        start_record = True
                    else:
                        continue
                self.md.detail = True
                ins = '%x %s' % (change['address'], self.get_disasm(change['address']))
                ops = []
                if not self.disasms.has_key(change['address']):
                    continue
                insn = self.disasms[change['address']]
                operands = insn.operands
                if len(operands) > 0:
                    j = -1
                    for op in operands:
                        j += 1
                        if op.type == X86_OP_IMM:
                            continue
                        elif op.type == X86_OP_FP:
                            continue
                        elif op.type == X86_OP_REG:
                            reg_name = insn.reg_name(op.reg)
                            reg_value = self.get_reg(i - j, reg_name)
                            ops.append('%s:%x' % (reg_name, reg_value))

                        elif op.type == X86_OP_MEM:
                            if op.mem.base != 0:
                                base_name = insn.reg_name(op.mem.base)  # reg
                                base = self.get_reg(i - j, base_name)
                            else:
                                base = 0

                            if op.mem.index != 0:
                                index_name = insn.reg_name(op.mem.index)  # reg
                                index = self.get_reg(i - j, index_name)
                            else:
                                index = 0
                            scale = op.mem.scale
                            disp = op.mem.disp
                            mem_addr = base + scale * index + disp
                            mem_byte = self.t.fetch_memory(i - j, mem_addr, op.size)
                            mem_value = self.byte_to_value(mem_byte)
                            ops.append('[%x]:%x' % (mem_addr, mem_value))
                '''
                elif change['type'] == 'R':
                    op = '%s => %x' % (self.get_reg_name(change['address']), change['data'])
                    ops.append(op)
                    # change['size']
                elif change['type'] == 'W':
                    op = '%s <= %x' % (self.get_reg_name(change['address']), change['data'])
                    ops.append(op)
                elif change['type'] == 'L':
                    op = '[%x] => %x' % (change['address'], change['data'])
                    ops.append(op)
                elif change['type'] == 'S':
                    op = '[%x] <= %x' % (change['address'], change['data'])
                    ops.append(op)
                elif change['type'] == 's':
                    pass
                    # if self.os == 'linux':
                    # 'sys_' + self.get_sys_call_name(change['address'])
                else:
                    print change
                '''
            self.write_one_ins(out, i, ins, ops)
        out.close()

    def get_memory(self, clnum, addr, size):
        result = ''
        for byte in self.t.fetch_memory(clnum, addr, size):
            result += chr(byte & 0xff)
        return result

    def get_reg(self, clnum, reg_name):
        index = self.get_reg_index(reg_name)
        reg_value = self.t.fetch_registers(clnum)[index & 0xff]
        if index & 0x1000:
            reg_value = reg_value
        if index & 0x800:
            reg_value = reg_value & 0xffffffff
        elif index & 0x400:
            reg_value = reg_value & 0xffff
        elif index & 0x200:
            reg_value = (reg_value & 0xff00) >> 8
        elif index & 0x100:
            reg_value &= 0xff

        if (self.arch != 'i386') & (index&0xff == 16):
            changes = self.t.fetch_changes_by_clnum(clnum, 1)
            for change in changes:
                if change['type'] == 'I':
                    reg_value = change['address'] + change['data'] #rip
        return reg_value

    def get_ret_addr(self, clnum):
        if self.arch == 'i386':
            esp = self.get_reg(clnum, 'esp')
            retval = l32(self.get_memory(clnum, esp, 4))
        else:
            rsp = self.get_reg(clnum, 'rsp')
            retval = l64(self.get_memory(clnum, rsp, 8))
        return retval

    def get_pc(self, clnum):
        changes = self.t.fetch_changes_by_clnum(clnum, 1)
        for change in changes:
            # print change
            if change['type'] == 'I':
                return change['address']
        return 0

    def generate_cfg(self, start_addr, ret_addr=None, start_clnum=0, end_clnum=0):
        if start_clnum == 0:
            start_clnum = self.t.get_minclnum() + 1

        if end_clnum == 0:
            end_clnum = self.t.get_maxclnum() - 1

        traces = []
        enter_call = 0
        enter_sub_call = 0

        for i in range(start_clnum, end_clnum + 1):
            pc = self.get_pc(i)
            asm = self.get_disasm(pc)
            if enter_call == 0:
                if pc == start_addr:
                    if ret_addr is None:
                        end_addr = self.get_ret_addr(i - 1)
                        print hex(end_addr)
                    else:
                        end_addr = ret_addr
                    enter_call = 1
                    trace = [(i, pc, asm)]
            else:
                if end_addr == pc:
                    print 'exit call'
                    enter_call = 0
                    traces.append(trace)
                    trace = []
                if enter_sub_call == 0:
                    trace.append((i, pc, asm))
                    if asm.startswith('call'):
                        enter_sub_call = 1
                        sub_call_ret = self.get_ret_addr(i)
                else:
                    if pc == sub_call_ret:
                        trace.append((i, pc, asm))
                        enter_sub_call = 0

        graph = Graph()

        pcs = []
        for trace in traces:
            print trace

        for trace in traces:
            exist_node = None
            exist_index = 1
            new_node = None
            for ins in trace:
                if ins[1] not in pcs:
                    pcs.append(ins[1])
                    if exist_node is None:
                        if new_node is None:
                            new_node = Node([Assemble(ins[1], ins[2])])
                            graph.add_node(new_node)
                        else:
                            new_node.add_asm(Assemble(ins[1], ins[2]))
                    else:
                        new_node = Node([Assemble(ins[1], ins[2])])
                        graph.add_node(new_node)
                        if len(exist_node.asm_seqs) == exist_index:
                            graph.add_edge(exist_node, new_node)
                        else:
                            node1, node2 = graph.split_node(exist_node, exist_index, count=exist_node.count - 1)
                            graph.add_edge(node1, new_node)
                        exist_node = None
                        exist_index = 0
                else:
                    if exist_node is None:
                        if new_node is None:
                            exist_node = graph.search_and_split(ins[1])
                            exist_node.add_count()
                            exist_index = 1
                        else:
                            node, index = graph.search_node(ins[1])
                            if index == 0:
                                graph.add_edge(new_node, node)
                                node2 = node
                            else:
                                node1, node2 = graph.split_node(node, index)
                                if node == new_node:
                                    graph.add_edge(node2, node2)
                                else:
                                    graph.add_edge(new_node, node2)
                            new_node = None
                            exist_node = node2
                            node2.add_count()
                            exist_index = 1
                    else:
                        if new_node is None:
                            if len(exist_node.asm_seqs) == exist_index:
                                node3 = graph.search_and_split(ins[1])
                                graph.add_edge(exist_node, node3)
                                exist_node = node3
                                node3.add_count()
                                exist_index = 1
                            else:
                                if exist_node.asm_seqs[exist_index].addr == ins[1]:
                                    exist_index += 1
                                else:
                                    node1, node2 = graph.split_node(exist_node, exist_index, count=exist_node.count-1)
                                    node3 = graph.search_and_split(ins[1])
                                    graph.add_edge(node1, node3)
                                    exist_node = node3
                                    node3.add_count()
                                    exist_index = 1
                        else:
                            print 'impossible2', ins
        graph.print_graph('tracer.png')

    def test(self):
        changes = self.t.fetch_changes_by_clnum(13, 1000)
        print self.t.fetch_registers(13)
        for change in changes:
            print change


'''
target = './test/crackme.wp.exe'
log = './test/qira_logs/232783872'
trace = Tracer(target, log)
trace.generate_cfg(0x41af70)
'''

log = '/Users/ling/share/qira_logs/406192128'
target = '/Users/ling/share/qira_logs/xor32'
log = '/Users/ling/share/test/qira_logs/499515392'
target = '/Users/ling/share/test/xor32'

log = '/Users/ling/share/test/xor64_log/610402304'
target = '/Users/ling/share/test/xor64'

log = '/Users/ling/share/r0ops/qira_logs/1242955776'
target = '/Users/ling/share/r0ops/r0ops'
trace = Tracer(target, log)
trace.generate_trace(0xdead429)
trace.generate_cfg(0xdead1f4, ret_addr=0xdead3af)
# trace.test()
# trace.generate_cfg(0x0804846d)
print 'finished'
