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
COV_DUMPS = "/cascade-data/cov_dump/rocket"
PLOT_PATH = "/mnt/cascade-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots"
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
    d["i_str"] = d["instructions"][0]["i_str"]
    d["bytecode_t0"] = d["instructions"][0]["bytecode_t0"]
    d["i_type"] = d["instructions"][0]["type"]
    d["cov"] = [i for i,j in enumerate(d["cov"]) if j]
    return pd.DataFrame([d])
#%%
data = pd.DataFrame()
files = glob.glob(f'{COV_DUMPS}/**/*.queue.json',recursive=True)
for file in files:
    d = read_json(file)
    if d is None: continue
    data = pd.concat([data,d])

# %%
fig, ax = plt.subplots()
sns.lineplot(data,x="ticks",y="rel_cov", hue="id",ax=ax)
ax.get_legend().remove()
#%%
acc_cov = pd.DataFrame()
missing_ids = set()
for inst in set(data["inst"]):
    acc_cov_pts = set()
    if inst=="drfuzz_mem":
        acc_cov_pts_t0 = set()
    for row in data[data["inst"] == inst].sort_values("ticks").iterrows():
        t = row[1]
        # if len(data[(data["inst"] != inst) & (data["id"] == t["id"])]) == 0:
        #     missing_ids |= {t["id"]}
        #     continue
        acc_cov_pts |= set(t["cov"])
        acc_rel_cov = len(acc_cov_pts)/t["n_mux"]
        tick = t["ticks"]
        new_cov = {
            "acc_cov_pts": acc_cov_pts,
            "acc_rel_cov" : acc_rel_cov,
            "tick": tick,
            "inst":inst,
            "id": t["id"] 
        }
        if inst == "drfuzz_mem":
            acc_cov_pts_t0 |= set(t["cov_t0"])
            acc_tainted_but_untoggled = acc_cov_pts_t0 - acc_cov_pts
            acc_rel_tainted_but_untoggled = len(acc_tainted_but_untoggled)/t["n_mux"]
            new_cov["acc_cov_pts_t0"] = acc_cov_pts_t0
            new_cov["acc_tainted_but_untoggled"] = acc_tainted_but_untoggled
            new_cov["acc_rel_tainted_but_untoggled"] = acc_rel_tainted_but_untoggled
        acc_cov = pd.concat([acc_cov,pd.DataFrame([new_cov])])

#%%
fig,ax = plt.subplots()
sns.lineplot(acc_cov,x="tick",y="acc_rel_cov",hue="i_str")
# sns.lineplot(acc_cov[acc_cov["inst"] == "drfuzz_mem"],x="tick",y="acc_rel_tainted_but_untoggled",hue="inst",label="taint",ax=ax)
# ax.set_xlim([0,10**7])
# ax.set_ylim([0.63,0.65])
ax.set_xlim([0,2*10**6])

ax.set_title("Multithread-cov Rocket: RegImm Fuzzing")
ax.set_xlabel("Ticks [1]")
ax.set_ylabel("cov [%]")

#%%
fig,ax = plt.subplots()
sns.lineplot(acc_cov[acc_cov["inst"] == "drfuzz_mem"],x="tick",y="acc_rel_tainted_but_untoggled",hue="inst")
ax.set_xlim([0,2*10**6])
# %%
gains = pd.DataFrame()
for id in set(data["id"]):
    for inst in set(data["inst"]):
        # loc = (data["id"] == id) & (data["inst"] != inst)
        # if len(data[loc]) == 0: continue

        loc = (data["id"] == id) & (data["inst"] == inst)
        if len(data[loc]) == 0: continue

        gain = max(data[loc]["n_cov"]) -  min(data[loc]["n_cov"])
        rel_gain = max(data[data["id"] == id]["rel_cov"]) -  min(data[data["id"] == id]["rel_cov"])
        gain_df = pd.DataFrame([{
            "gain" : gain,
            "rel_gain" : rel_gain,
            "id" : id,
            "inst": inst,
            "n_cov_max": max(data[data["id"] == id]["n_cov"]),
            "n_cov_min": min(data[data["id"] == id]["n_cov"]),
            "rel_cov_max": max(data[data["id"] == id]["rel_cov"]),
            "rel_cov_min": min(data[data["id"] == id]["rel_cov"]),
            "cov_max": data[(data["id"] == id) & (data["n_cov"] == max(data[data["id"] == id]["n_cov"]))]["cov"],
            "cov_min": data[(data["id"] == id) & (data["n_cov"] == min(data[data["id"] == id]["n_cov"]))]["cov"],
            "i_str": data[data["id"] == id]["i_str"].values[0],
            "i_type": data[data["id"] == id]["i_type"].values[0],
            "bytecode_t0":  data[data["id"] == id]["bytecode_t0"].values[0]
        }])
        gains = pd.concat([gains,gain_df])
#%%
sns.relplot(gains,x="rel_cov_min",y="rel_cov_max",hue="i_type")
#%%
fig, ax = plt.subplots()
sns.histplot(gains,x="rel_gain",hue="i_type",ax=ax)
#%%
fig, ax = plt.subplots()
sns.histplot(gains[gains["rel_gain"] != 0],x="n_cov_min",ax=ax, label="rel_gain>0")
sns.histplot(gains[gains["rel_gain"] == 0],x="n_cov_min",ax=ax, label="rel_gain=0")
ax.legend()
ax.set_title("Seed cov")
#%%
fig, ax = plt.subplots()
sns.histplot(gains[gains["rel_gain"] != 0],x="n_cov_max",ax=ax, label="rel_gain>0")
sns.histplot(gains[gains["rel_gain"] == 0],x="n_cov_max",ax=ax, label="rel_gain=0")
ax.legend()
ax.set_title("Final cov")
#%%
fig, ax = plt.subplots()
sns.histplot(gains[gains["rel_gain"] != 0],x="n_cov_min",ax=ax, hue="inst")
# sns.histplot(gains[gains["rel_gain"] == 0],x="n_cov_min",ax=ax, hue="inst")
# ax.legend()
ax.set_title("Seed cov")
#%%
fig, ax = plt.subplots()
sns.histplot(gains[gains["rel_gain"] != 0],x="n_cov_max",ax=ax, hue="inst")
# sns.histplot(gains[gains["rel_gain"] == 0],x="n_cov_max",ax=ax, hue="inst")
# ax.legend()
ax.set_title("Final cov")
# %%
fig, ax = plt.subplots()
loc = gains["rel_gain"] == 0
sns.histplot([i for j in [k[0] for k in gains[loc]["cov_max"].values] for i in j],ax=ax,label="rel_gain=0")
loc = gains["rel_gain"] >= 0
sns.histplot([i for j in [k[0] for k in gains[loc]["cov_max"].values] for i in j],ax=ax,label="rel_gain>0")
ax.legend()

# %%
loc = gains["rel_gain"] == 0
set_cov_points_nogain = set([i for j in [k[0] for k in gains[loc]["cov_max"].values] for i in j])
loc = gains["rel_gain"] >= 0
set_cov_points_gain = set([i for j in [k[0] for k in gains[loc]["cov_max"].values] for i in j])

# %%
n_extra_mux = len(set_cov_points_gain - set_cov_points_nogain)
# total_improvement = n_extra_mux/1517
# %%
