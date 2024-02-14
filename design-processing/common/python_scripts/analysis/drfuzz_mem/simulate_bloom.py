#%%
import numpy as np
import matplotlib.pyplot as plt
import random
import seaborn as sns
#%%
P_TAINT=22528/(1287*32) # (n_tainted__bits/n_total_address_bits) from some execution
N_BITS_BLOOM = 8 # b
N_BITS_MEM = 16 #k
N_ADDRS = 23
N_HASH_FUNCS = 8
#%%
P_e = (1-np.exp(-N_HASH_FUNCS*N_ADDRS/(2**N_BITS_BLOOM)))**N_HASH_FUNCS
print(f"P_e={P_e}")
#%%
addrs = [np.random.randint(0,2**N_BITS_MEM) for _ in range(N_ADDRS)] # N_BITS_MEM bits inputs for memory with 2**N_BITS_MEM addresses
addrs_t =[int(''.join([str(i) for i in np.random.choice([0,1],N_BITS_MEM,True,[1-P_TAINT,P_TAINT])]),2) for _ in range(N_ADDRS)]

#%%
bloom_table_t = [0 for i in range(2**N_BITS_BLOOM)]
bloom_table = [0 for i in range(2**N_BITS_BLOOM)]
memory_t = [0 for i in range(2**N_BITS_MEM)]
#%%
hash_funcs = [[(random.sample(range(0,N_BITS_MEM),2)) for _ in range(N_BITS_BLOOM)] for _ in range(N_HASH_FUNCS)]   
#%%
fig, ax = plt.subplots()
hash_outputs = [[] for _ in range(N_HASH_FUNCS)]
for i in range(N_HASH_FUNCS):
    for addr in addrs:
        hash_outputs[i] += [apply_h(addr,hash_funcs[i])]
    sns.histplot(hash_outputs[i],label=i, ax=ax,binwidth=1)
ax.legend()


#%%
def get_all_inputs_idx(addr,addr_t,n_bits):
    inputs = []
    for i in range(2**n_bits):
        if not (i^addr)&~addr_t:
            inputs += [i]
    return inputs
#%%
def apply_h(addr,h):
    return int(''.join([str(i) for i in [((addr&(1<<k[0]))>>k[0])^((addr&(1<<k[1]))>>k[1]) for k in h]]),2)
def apply_h_t(addr,addr_t,h):
    replica_outputs =     [[ \
                (v0 if addr_t&(1<<k[0]) else ((addr&(1<<k[0]))>>k[0])) \
                    ^ \
                (v1 if addr_t&(1<<k[1]) else ((addr&(1<<k[1]))>>k[1]))  \
                for k in h \
            ]  \
            for v0 in [0,1] for v1 in [0,1] \
        ]
    t = [0]*len(replica_outputs[0])
    for i in range(len(replica_outputs)-1):
        t = [j|k for j,k in zip(t,[l^m for l,m in zip(replica_outputs[i],replica_outputs[i+1])])]
    return int(''.join([str(i) for i in t]),2) # return taints
# %%
addr = addrs[0]
addr_t = addrs_t[0]
s0 = set([l for i in [[apply_h(a,h) for h in hash_funcs] for a in get_all_inputs_idx(addr,addr_t,N_BITS_MEM)] for l in i])
s1 = set([l for i in [get_all_inputs_idx(apply_h(addr,h),apply_h_t(addr,addr_t,h),N_BITS_BLOOM) for h in hash_funcs] for l in i])
print(s0)
print(s1)
#%%
def write_mem_t(addr,addr_t,memory_t):
    for i in get_all_inputs_idx(addr,addr_t,N_BITS_MEM):
        memory_t[i] = 1
def read_mem_t(addr,memory_t):
    return memory_t[addr]
#%%
def write_bloom_t(addr,addr_t,bloom_table_t, hash_funcs):
    for h in hash_funcs: 
        for i in get_all_inputs_idx(apply_h(addr,h),apply_h_t(addr,addr_t,h),N_BITS_BLOOM):
            bloom_table_t[i] = 1
        # bloom_table_t[apply_h(addr,h)] = 1

def read_bloom(addr,bloom_table):
    res = 1
    for h in hash_funcs:
        res &= bloom_table[apply_h(addr,h)]
    return res

def write_bloom(addr,addr_t,bloom_table,hash_funcs):
    for h in hash_funcs:
        for i in get_all_inputs_idx(addr,addr_t,N_BITS_MEM):
            bloom_table[apply_h(i,h)] = 1


#%%
for addr,addr_t in zip(addrs,addrs_t):
    write_mem_t(addr,addr_t,memory_t)
    write_bloom(addr,addr_t,bloom_table,hash_funcs)
    write_bloom_t(addr,addr_t,bloom_table_t,hash_funcs)
# %%
for addr in range(2**N_BITS_MEM):
    if read_mem_t(addr,memory_t) and not read_bloom(addr,bloom_table):
        print(addr)
for addr in range(2**N_BITS_MEM):
    if read_mem_t(addr,memory_t) and not read_bloom(addr,bloom_table_t):
        print(addr)

#%%
fig,ax = plt.subplots()
ax.scatter(x=range(2**N_BITS_BLOOM),y=bloom_table,label='Pre-Hash')
ax.scatter(x=range(2**N_BITS_BLOOM), y=bloom_table_t,label='Post-Hash',marker='x')
ax.legend()

# %%
matches = [i==j for i,j in zip(bloom_table,bloom_table_t)]
acc = len([i for i in matches if i])/len(matches)
fp = len([i for i,j in zip(bloom_table_t,bloom_table) if i and not j])/len(matches)
fn = len([i for i,j in zip(bloom_table_t,bloom_table) if j and not i])/len(matches)
print(f"Accuracy: {acc}, FP: {fp}, FN: {fn}")
# %%
matches = [read_bloom(addr,bloom_table_t)==read_mem_t(addr,memory_t) for addr in range(2**N_BITS_MEM)]
acc = len([i for i in matches if i])/len(matches)
fp = len([read_bloom(addr,bloom_table_t) for addr in range(2**N_BITS_MEM) if read_bloom(addr,bloom_table_t) and not read_mem_t(addr,memory_t)])/len(matches)
fn = len([read_bloom(addr,bloom_table_t) for addr in range(2**N_BITS_MEM) if not read_bloom(addr,bloom_table_t) and read_mem_t(addr,memory_t)])/len(matches)
print(f"Accuracy: {acc}, FP: {fp}, FN: {fn}")

# %%
matches = [read_bloom(addr,bloom_table)==read_mem_t(addr,memory_t) for addr in range(2**N_BITS_MEM)]
acc = len([i for i in matches if i])/len(matches)
fp = len([read_bloom(addr,bloom_table) for addr in range(2**N_BITS_MEM)if read_bloom(addr,bloom_table) and not read_mem_t(addr,memory_t)])/len(matches)
fn = len([read_bloom(addr,bloom_table) for addr in range(2**N_BITS_MEM) if not read_bloom(addr,bloom_table) and read_mem_t(addr,memory_t)])/len(matches)
print(f"Accuracy: {acc}, FP: {fp}, FN: {fn}")

# %%
