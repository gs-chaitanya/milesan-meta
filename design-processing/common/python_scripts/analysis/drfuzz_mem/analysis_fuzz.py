#%%
import matplotlib.pyplot as plt
import json
import pandas as pd
import seaborn as sns
import numpy as np
import numpy as np
import matplotlib.pyplot as plt
import glob
import pandas as pd
import scipy as sp
import seaborn as sns
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
    d["n_cov"] = np.count_nonzero(d["coverage"])
    d["n_mux"] = len(d["coverage"])
    d["rel_cov"] = np.count_nonzero(d["coverage"])/len(d["coverage"])*100
    if "taints" in d:
        d["n_cov_t0"] = np.count_nonzero(d["taints"])
        d["rel_cov_t0"] = np.count_nonzero(d["taints"])/len(d["taints"])*100

        d["n_pot"] = np.count_nonzero([j for i,j in zip(d["coverage"], d["taints"]) if j and not i])
        d["rel_pot"] = d["n_pot"]/len(d["taints"])*100
    
        d["coverage_t0"] = [i for i,j in enumerate(d["taints"]) if j]


    d["coverage"] = [i for i,j in enumerate(d["coverage"]) if j]

    return pd.DataFrame([d])
#%%
data = pd.DataFrame()
files = glob.glob(f'{COV_DUMPS}/**/*.cov.json',recursive=True)
for file in files:
    d = read_json(file)
    if d is None: continue
    data = pd.concat([data,d])

# %%
fig, ax = plt.subplots()
sns.lineplot(data[data["inst"] == "drfuzz_mem"],x="ticks",y="rel_cov", hue="id",ax=ax)
ax.get_legend().remove()
#%%
acc_cov = pd.DataFrame()
for inst in set(data["inst"]):
    acc_cov_pts = set()
    if inst=="drfuzz_mem":
        acc_cov_pts_t0 = set()
    for row in data[data["inst"] == inst].sort_values("ticks").iterrows():
        t = row[1]
        acc_cov_pts |= set(t["coverage"])
        acc_rel_cov = len(acc_cov_pts)/t["n_mux"]
        tick = t["ticks"]
        new_cov = {
            "acc_cov_pts": acc_cov_pts,
            "acc_rel_cov" : acc_rel_cov,
            "tick": tick,
            "inst":inst
        }
        if inst == "drfuzz_mem":
            acc_cov_pts_t0 |= set(t["coverage_t0"])
            acc_tainted_but_untoggled = acc_cov_pts_t0 - acc_cov_pts
            acc_rel_tainted_but_untoggled = len(acc_tainted_but_untoggled)/t["n_mux"]
            new_cov["acc_cov_pts_t0"] = acc_cov_pts_t0
            new_cov["acc_tainted_but_untoggled"] = acc_tainted_but_untoggled
            new_cov["acc_rel_tainted_but_untoggled"] = acc_rel_tainted_but_untoggled
        acc_cov = pd.concat([acc_cov,pd.DataFrame([new_cov])])

#%%
fig,ax = plt.subplots()
sns.lineplot(acc_cov,x="tick",y="acc_rel_cov",hue="inst")
# ax.set_xlim([0,10**7])
ax.set_ylim([0.63,0.65])

#%%
fig,ax = plt.subplots()
sns.lineplot(acc_cov[acc_cov["inst"] == "drfuzz_mem"],x="tick",y="acc_rel_tainted_but_untoggled",hue="inst")
ax.set_xlim([0,0.1*10**8])
# %%
gains = pd.DataFrame()
for id in set(data["id"]):
    for inst in set(data["inst"]):
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
            "coverage_max": data[(data["id"] == id) & (data["n_cov"] == max(data[data["id"] == id]["n_cov"]))]["coverage"],
            "coverage_min": data[(data["id"] == id) & (data["n_cov"] == min(data[data["id"] == id]["n_cov"]))]["coverage"]
        }])
        gains = pd.concat([gains,gain_df])
# %%
sns.histplot(gains,x="rel_gain",binwidth=0.1,hue="inst")
#%%
fig, ax = plt.subplots()
sns.histplot(gains[gains["rel_gain"] != 0],x="n_cov_min",ax=ax, label="rel_gain>0")
sns.histplot(gains[gains["rel_gain"] == 0],x="n_cov_min",ax=ax, label="rel_gain=0")
ax.legend()
ax.set_title("Seed Coverage")
#%%
fig, ax = plt.subplots()
sns.histplot(gains[gains["rel_gain"] != 0],x="n_cov_max",ax=ax, label="rel_gain>0")
sns.histplot(gains[gains["rel_gain"] == 0],x="n_cov_max",ax=ax, label="rel_gain=0")
ax.legend()
ax.set_title("Final Coverage")
# %%
fig, ax = plt.subplots()
loc = gains["rel_gain"] == 0
sns.histplot([i for j in [k[0] for k in gains[loc]["coverage_max"].values] for i in j],ax=ax,label="rel_gain=0")
loc = gains["rel_gain"] >= 0
sns.histplot([i for j in [k[0] for k in gains[loc]["coverage_max"].values] for i in j],ax=ax,label="rel_gain>0")
ax.legend()

# %%
loc = gains["rel_gain"] == 0
set_cov_points_nogain = set([i for j in [k[0] for k in gains[loc]["coverage_max"].values] for i in j])
loc = gains["rel_gain"] >= 0
set_cov_points_gain = set([i for j in [k[0] for k in gains[loc]["coverage_max"].values] for i in j])

# %%
n_extra_mux = len(set_cov_points_gain - set_cov_points_nogain)
# total_improvement = n_extra_mux/1517
# %%
