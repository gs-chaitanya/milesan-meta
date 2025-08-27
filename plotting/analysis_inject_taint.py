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
COV_DUMPS = "/milesan-data/cov_dump/"
PLOT_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots"
#%% reader function to parallelize reading
def read_json(p):
    with open(p, 'r') as f:
            d = json.load(f)[0]
    assert len(d["instructions"]) ==  1, "max_n_inst per bbs should be one" 

    d["coverage"] = [i for i,j in  enumerate(d["output"]["coverage"]) if j]
    d["coverage_t0"] = [i for i,j in enumerate(d["output"]["taints"]) if j]
    d["potential"] = [i for i,(j,k) in enumerate(zip(d["output"]["taints"],d["output"]["coverage"])) if j and not k]
    d["n_cov_t0"] = len(d["coverage_t0"])
    d["n_cov"] = len(d["coverage"])
    d["n_pot"] = len(d["potential"])
    d["overtaints"] = d["n_cov_t0"] >= OVERTAINT_TH * len(d["output"]["taints"])
    d["bytecode"] = [int(i["bytecode"],16) for i in d["instructions"]][0]
    d["bytecode_t0"] = [int(i["bytecode_t0"],16) for i in d["instructions"]][0]

    d["rd"] = hex((d["bytecode"] & (RD_MASK<<RD_BIT))>>RD_BIT)
    d["rd_t0"] = hex((d["bytecode_t0"] & (RD_MASK<<RD_BIT))>>RD_BIT)

    d["rs1"] = hex((d["bytecode"] & (RS1_MASK<<RS1_BIT))>>RS1_BIT)
    d["rs1_t0"] = hex((d["bytecode_t0"] & (RS1_MASK<<RS1_BIT))>>RS1_BIT)

    d["i_type"] = [i["type"] for i in d["instructions"]][0]
    if d["i_type"] == "R":
        d["rs2"] = hex((d["bytecode"] & (RS2_MASK<<RS2_BIT))>>RS2_BIT)
        d["rs2_t0"] = hex((d["bytecode_t0"] & (RS2_MASK<<RS2_BIT))>>RS2_BIT)
    elif d["i_type"] == "I":
        d["imm"]= hex((d["bytecode"] & (IMMI_MASK<<IMMI_BIT))>>IMMI_BIT)
        d["imm_t0"]= hex((d["bytecode_t0"] & (IMMI_MASK<<IMMI_BIT))>>IMMI_BIT)
    else:
        raise Exception(f"Error casting i_type: {d['i_type']}")

    d["dut"] = d["output"]["dut"]
    with open(d["mut_inst_path"], 'r') as f:
            mut_inst = json.load(f)[0]
    d["i_str"] = mut_inst["str"]
    d["addr"] = mut_inst["addr"]
    return pd.DataFrame([d])
#%%
data = pd.DataFrame()
files = glob.glob(f'{COV_DUMPS}/**/*.queue.json',recursive=True)
for file in files:
    d = read_json(file)
    if d is None: continue
    data = pd.concat([data,d])

# %%
sns.histplot([i for j in data["coverage"].values for i in j])
# %%
sns.histplot([i for j in data["coverage_t0"].values for i in j])
#%% 
sns.histplot([i for j in data["potential"].values for i in j])
#%% 
sns.histplot(data=data, x="n_pot", hue="i_type")
#%% 
sns.histplot(data=data, x="n_cov_t0", hue="i_type")
# %%
sns.histplot(data=data[data["i_type"] == "R"], x="n_cov_t0", hue="rs2_t0")
#%%
sns.histplot(data=data[data["i_type"] == "R"], x="n_cov_t0", hue="rs1_t0")
#%%
sns.histplot(data=data[data["i_type"] == "R"], x="n_cov_t0", hue="rd_t0")
# %%
sns.histplot(data=data[data["i_type"] == "I"], x="n_cov_t0", hue="rs1_t0")
#%%
sns.histplot(data=data[data["i_type"] == "I"], x="n_cov_t0", hue="imm_t0")
#%%
sns.histplot(data=data[data["i_type"] == "I"], x="n_cov_t0", hue="rd_t0")
# %%
sns.scatterplot(data=data, x='bytecode_t0', y='n_cov_t0')
#%%
loc = (data["n_cov_t0"] == max(data["n_cov_t0"])) & (data['i_type'] == 'R')
sns.histplot(data=data[loc], x = 'bytecode_t0')
# %%
sns.catplot(data=data,y="rs1",x="n_cov_t0",kind='swarm',hue="rs1_t0",s=4)
#%%
sns.catplot(data=data[data['i_type'] == 'R'],y="rs2",x="n_cov_t0",kind='swarm')
#%%
sns.catplot(data=data,y="rd",x="n_cov_t0",kind='swarm',hue="rs1_t0",s=10,order=[hex(i) for i in range(32)])

# %%
sns.catplot(data=data[data["overtaints"] == True],y="rd",x="rd_t0",kind='swarm',hue="rs1_t0",s=10,order=[hex(i) for i in range(32)])
#%%
sns.scatterplot(data=data[data["overtaints"] == False],y="rs1",x="rs1_t0")
#%%
sns.histplot(data=data,x="bytecode_t0",y='overtaints')

# %%
d_good = data[data["overtaints"] == False]
d_bad = data[data["overtaints"] == True]
#%%
d_good_potential = d_good[d_good["n_pot"] > 0]
#%%
DUT="Kronos"
fig, ax = plt.subplots(figsize=(20,20))
sns.histplot([i for j in d_good_potential[d_good_potential["dut"] == DUT]["potential"].values for i in j],binwidth=1,ax=ax,label="pot")
sns.histplot([i for j in d_good_potential[d_good_potential["dut"] == DUT]["coverage"].values for i in j],binwidth=1,ax=ax,label="cov")
ax.legend()
# sns.histplot([i for j in d_good_potential[d_good_potential["dut"] == "Rocket"]["coverage_t0"].values for i in j],binwidth=5,ax=ax)

# %%
fig, ax = plt.subplots(figsize=(20,20))
sns.histplot([i for j in data[data["dut"] == DUT]["potential"].values for i in j],binwidth=1,ax=ax,label="pot")
sns.histplot([i for j in data[data["dut"] == DUT]["coverage"].values for i in j],binwidth=1,ax=ax,label="cov")
ax.legend()
#%%
set(d_bad[d_bad["dut"] == DUT]["i_str"])
#%%
set(d_good[d_good["dut"] == DUT]["i_str"])
