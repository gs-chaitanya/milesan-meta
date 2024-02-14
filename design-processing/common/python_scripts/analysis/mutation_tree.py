#%%
import pandas as pd
import numpy as np
import glob
COV_DUMPS = "/cellift-meta/design-processing/common/python_scripts/analysis/cov_dumps"
import json
from typing import List
import subprocess
MUT_GRAPHS = '/cellift-meta/design-processing/common/python_scripts/analysis/plots/mutation_graphs'
#%%
queues = pd.DataFrame()
for p in glob.glob(f'{COV_DUMPS}/*/*/*/queue/*',recursive=True):

    splits = p.split('/')
    dut = splits[7]
    inst = splits[8]
    seed = splits[9]
    io = splits[-1].split('.')[-2]

    with open(p, 'r') as f:
        d = json.load(f)
    
    if('taints' in d):
        taints = np.array(d['taints']).flatten()
        if len(taints) != 0:
            rel_taints = np.count_nonzero(taints)/len(taints)
            d['rel_taints'] = rel_taints

    if 'coverage' in d:
        d['cov_hash'] = hash("".join(str(i) for i in np.array(d['coverage']).flatten()))     

    if 'inputs' in d:
        d['inp_hash'] = hash("".join(str(i) for i in np.array(d['inputs']).flatten()))                 

    d['inst'] = inst
    d['seed'] = seed
    d['DUT'] = dut
    d['io'] = io   
    pd_dict = pd.DataFrame([d])
    queues = pd.concat([queues, pd_dict], ignore_index = True)

#%%
Sodors = [f'Sodor{i}Stage' for i in [1,3,5]]
DUTs = ['VexRiscV','PicoRV']
for dut in DUTs:
    for inst in ['drfuzz','rfuzz']:
        loc = (queues['io']=='in') & (queues['inst']==inst) & (queues['DUT']==dut)
        nodes = {}
        for d in queues[loc].sort_values('ID').iterrows():
            s = d[1]
            parent = nodes.get(s['parent'], None)
            node = TreeNode(s['ID'], parent, s['mutator'], s['rel_taints'], s['cov_hash'], s['inp_hash'])
            nodes[s['ID']] = node

        make_mutation_graph(f'{MUT_GRAPHS}/{dut}_{inst}.pdf',nodes)
# %%
class TreeNode:
    def __init__(self, id, parent, mutator, taint, cov_hash, inp_hash):
        self.id = id
        self.children = []
        self.mutator = mutator
        self.taint = taint
        self.cov_hash = cov_hash
        self.inp_hash = inp_hash
        if parent != None:
            self.parent = parent
            self.parent.children.append(self)
            self.depth = parent.depth + 1
        else:
            self.depth = 0
    @property
    def is_leaf(self): return len(self.children) == 0

    @property
    def leaf_count(self): return sum(cc.is_leaf for cc in self.children)

    @property
    def reachable_count(self):
        return sum(cc.reachable_count for cc in self.children) + 1

    def dot_node(self) -> str:
        taint = '%.2f'%self.taint
        return f'\t{self.id} [label="{self.id}:{taint}"];'

    def dot_edges(self) -> List[str]:
        return [f'\t{self.id} -> {cc.id} [label="{cc.mutator}"];' for cc in self.children]


        

# %%

def make_mutation_graph_dot(nodes):
	dot = ["digraph g {"]
	dot += [n.dot_node() for n in nodes.values()]
	for n in nodes.values():
		dot += n.dot_edges()
	dot += ["}"]
	return "\n".join(dot)
#%%
def make_mutation_graph(filename, nodes, fmt=None):
	dot = make_mutation_graph_dot(nodes)
	if fmt is None:
		fmt = os.path.splitext(filename)[1][1:]
	with open('tmp.dot', 'w') as out:
		out.write(dot)
		dotfile = out.name
	# cmd = ['dot', '-Tpdf', dotfile, '-o', filename]
	cmd = ['sfdp', '-x', '-Goverlap=scale', '-Gdpi=200', '-T' + fmt, dotfile, '-o', filename]
	subprocess.run(cmd, check=True)
#%%
loc = (queues['io']=='out') & (queues['DUT']=='Sodor1Stage')
shared_muts = pd.DataFrame()
for q in queues[loc].iterrows():
    cov_hash = q[1]['cov_hash']
    if len(queues[queues['cov_hash']==cov_hash])>1:
        shared_muts = pd.concat([shared_muts, queues[loc][queues['cov_hash']==cov_hash]],ignore_index = True)

#%%

nodes = {}
for d in shared_muts.iterrows():
    s = d[1]
    parent = nodes.get(s['parent'], None)
    node = TreeNode(s['ID'], parent, s['mutator'], s['rel_taints'], s['cov_hash'], s['inp_hash'])
    nodes[s['ID']] = node

make_mutation_graph(f'shared_muts_sodor1.pdf',nodes)