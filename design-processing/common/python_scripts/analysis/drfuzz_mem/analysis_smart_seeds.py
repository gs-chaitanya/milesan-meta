#%%
import matplotlib.pyplot as plt
import json
import pandas as pd
import seaborn as sns
import numpy as np
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import scipy as sp
import seaborn as sns
import glob
from multiprocessing import Pool
#%%
N_PROC = 10
RD_BIT = 7
RD_MASK = 0x1f
RS1_BIT = 15
RS1_MASK = 0x1f
RS2_BIT = 20
RS2_MASK = 0x1f
IMMI_BIT = 10
IMMI_MASK = 0xfff
OVERTAINT_TH = 0.8
# COV_DUMPS = "/mnt/cov_dump/"    
COV_DUMPS = "/cascade-data/cov_dump_mem_stdout*"
#%% reader function to parallelize reading
def read_json(p):
    with open(p, 'r') as f:
            d = json.load(f)
    d = d[0]
    d["n_cov"] = np.count_nonzero(d["cov"])
    d["n_mux"] = len(d["cov"])
    d["rel_cov"] = np.count_nonzero(d["cov"])/len(d["cov"])*100
    if "cov_t0" in d:
        d["n_cov_t0"] = np.count_nonzero(d["cov_t0"])
        d["rel_cov_t0"] = np.count_nonzero(d["cov_t0"])/len(d["cov_t0"])*100

        d["n_pot"] = np.count_nonzero([j for i,j in zip(d["cov"], d["cov_t0"]) if j and not i])
        d["rel_pot"] = d["n_pot"]/len(d["cov_t0"])*100
    
        d["cov_t0"] = [i for i,j in enumerate(d["cov_t0"]) if j]
    if len(d["instructions"]):
        d["i_str"] = d["instructions"][0]["i_str"]
        d["bytecode_t0"] = d["instructions"][0]["bytecode_t0"]
        d["i_type"] = d["instructions"][0]["type"]
    d["cov"] = [i for i,j in enumerate(d["cov"]) if j]
    d["q_path"] = p
    d["mode"] = p.split("/")[2]

    return pd.DataFrame([d])
#%%
data = pd.DataFrame()
files = glob.glob(f'{COV_DUMPS}/**/cov/*.queue.json',recursive=True)
for file in files:
    d = read_json(file)
    if d is None: continue
    data = pd.concat([data,d])

# %%
fig, ax = plt.subplots()
sns.lineplot(data,x="ticks",y="rel_cov_t0",ax=ax)
# sns.lineplot(data,x="ticks",y="pc",hue="mode",ax=ax)
# ax.axvline(min(data[data["injected_taint"] == 1]["ticks"]))
# ax.get_legend().remove()
# %%
fig, ax = plt.subplots()
sns.lineplot(data,x="ticks",y="pc",ax=ax)
# ax.axvline(max(data[data["pc_taint"] == "break"]["ticks"]))
# ax.set_xlim([15600,16000])
# ax.get_legend().remove()
#%%

def clean_reg_taint(reg, reg_t0):
    skipped_regs = [8]
    for skip in skipped_regs:
        if reg&~reg_t0 == skip&~reg_t0: # untainted bits match
            for i in range(5):
                reg_t0 = reg_t0&~(1<<i)
                if reg&~reg_t0 != skip&~reg_t0:
                    break
    return reg, reg_t0
#%%
cov_t0_jmps = set(data["rel_cov_t0"])
pcs = {}
for cov_t0 in cov_t0_jmps:
    ticks = min(data[data["rel_cov_t0"] == cov_t0]["ticks"])
    pc = data[data["ticks"] == ticks]["pc"].values[0]
    pcs[ticks] = pc
    ticks = max(data[data["rel_cov_t0"] == cov_t0]["ticks"])
    pc = data[data["ticks"] == ticks]["pc"].values[0]
    pcs[ticks] = pc

    # print(f"pc {hex(pc)}, tick: {ticks}")
#%%
fig, ax = plt.subplots()
sns.lineplot(data,x="ticks",y="rel_cov_t0",ax=ax)
for tick in sorted(pcs):
    fig, ax = plt.subplots()
    sns.lineplot(data,x="ticks",y="rel_cov_t0",ax=ax)
    ax.set_xlim([tick-10,tick+10])
    ax.set_title(hex(pcs[tick]))
    ax.axvline(tick)

#%%
acc_cov = pd.DataFrame()
missing_ids = set()
# for inst in set(data["inst"]):
for mode in set(data["mode"]):
    acc_cov_pts = set()
    for row in data[data["mode"] == mode].sort_values("ticks").iterrows():
        t = row[1]
        acc_cov_pts |= set(t["cov"])
        acc_rel_cov = len(acc_cov_pts)/t["n_mux"]
        tick = t["ticks"]
        new_cov = {
            "acc_cov_pts": acc_cov_pts,
            "acc_rel_cov" : acc_rel_cov,
            "tick": tick,
            "mode":mode,
            "id": t["id"]
        }
        acc_cov = pd.concat([acc_cov,pd.DataFrame([new_cov])])

#%%
fig,ax = plt.subplots()
sns.lineplot(acc_cov,x="tick",y="acc_rel_cov",hue="mode",marker="o",ax=ax)
# ax.set_xlim([-10**6,max(acc_cov[acc_cov["mode"] == "smart_seed+fuzz"]["tick"])])
# ax.set_ylim([0.65,0.7])
# ax.set_xlim([0,2*10**5])

ax.set_title("Multithread-cov")
ax.set_xlabel("Ticks [1]")
ax.set_ylabel("cov [%]")

# %%
