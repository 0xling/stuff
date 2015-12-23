import pygraphviz as pgv


class Assemble():
    def __init__(self, addr, asm, comment=''):
        self.addr = addr
        self.asm = asm
        self.comment = comment


class Node():
    def __init__(self, asm_seq, count=1):
        self.id = asm_seq[0].addr
        self.asm_seqs = asm_seq
        self.count = count

    def add_asm(self, asm):
        self.asm_seqs.append(asm)

    def add_count(self):
        self.count += 1

    def change_asm_seq(self, asm_seq):
        self.asm_seqs = asm_seq

    #@property
    def to_str(self):
        result = ''
        for asm in self.asm_seqs:
            if result != '':
                result += '\n'
            res = ('%x %s;%s' %(asm.addr, asm.asm, asm.comment))
            count = res.count(' ')
            res = res.ljust(70+count-len(res), ' ')
            #print res, len(res)
            result += res
        return result

class Edge():
    def __init__(self, src=None, dest=None, count=1):
        self.src = src
        self.dest = dest
        self.count = count

    def add_count(self):
        self.count += 1

    def modify_src(self, src):
        self.src = src

class Graph():
    def __init__(self):
        self.nodes = {}
        self.edges = {}

    def add_node(self, node):
        if not self.nodes.has_key(node.id):
            self.nodes[node.id] = node
        else:
            self.nodes[node.id].add_count()

    def add_edge(self, src_node, dest_node, count=1):
        #print 'add_edge:', hex(src_node.id), hex(dest_node.id)
        if not self.edges.has_key((src_node.id, dest_node.id)):
            self.edges[(src_node.id, dest_node.id)] = Edge(src_node.id, dest_node.id, count)
        else:
            self.edges[(src_node.id, dest_node.id)].add_count()

    '''
    def remove_node(self, addr):
        if self.nodes.has_key(addr):
            self.nodes.pop(addr)

    def remove_edge(self, src_addr, dest_addr):
        if self.edges.has_key((src_addr, dest_addr)):
            self.edges.pop((src_addr, dest_addr))
    '''''

    def print_graph(self, outfile):
        A = pgv.AGraph(directed=True, strict=True)
        A.node_attr['style'] = 'filled'
        A.node_attr['shape'] = 'box'
        A.node_attr['nojustify'] = 'false'
        A.node_attr['labeljust'] = 'l'

        for key, value in self.nodes.items():
            A.add_node(key, label=value.to_str())

        for key, value in self.edges.items():
            A.add_edge(value.src, value.dest, label=str(value.count))

        #print A.string()
        A.graph_attr['epsilon'] = '0.01'
        A.layout('dot')  # layout with dot
        A.draw(outfile)  # write to file

    def split_node(self, node, index, count=0):
        #print 'split_node:'+hex(node.id)+':'+hex(index)
        node2 = Node(node.asm_seqs[index:], count=node.count)
        node.change_asm_seq(node.asm_seqs[0:index])
        self.nodes[node2.id] = node2

        edges2 = self.edges
        for key, edge in edges2.items():
            if (edge.src == node.id) & (edge.dest == node.id):
                self.add_edge(node2, node, count=edge.count)
                self.edges.pop((edge.src, edge.dest))
            elif edge.src == node:
                self.add_edge(node2, node, count=edge.count)
                self.edges.pop((edge.src, edge.dest))
        #print node.count
        if count == 0:
            count = node.count
        self.add_edge(node, node2, count=count)

        return node, node2

    def search_node(self, ins):
        for key, node in self.nodes.items():
            for i in range(len(node.asm_seqs)):
                if ins == node.asm_seqs[i].addr:
                    return node, i
        print 'error'
        return None, 0

    def search_and_split(self, ins):
        node, index = self.search_node(ins)
        if index != 0:
            node1, node = self.split_node(node, index)
        return node

'''
if __name__ == '__main__':
    graph = Graph()

    asm = Assemble(0x08048000, 'mov eax, ebx', 'test')
    node1 = Node(asm)

    asm2 = Assemble(0x08048001, 'pop eax', 'test2')
    node2 = Node(asm2)

    asm3 = Assemble(0x08048002, 'push eax', 'test3')
    node3 = Node(asm3)

    graph.add_node(node1)
    graph.add_node(node2)
    graph.add_node(node3)

    graph.add_edge(node1, node2)
    graph.add_edge(node1, node3)
    graph.add_edge(node3, node1)

    graph.print_graph()
'''
