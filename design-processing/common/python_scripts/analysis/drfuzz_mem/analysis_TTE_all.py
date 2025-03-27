#%%
import numpy
import pandas as pd
import glob
import matplotlib.pyplot as plt
import seaborn as sns
import json
import subprocess
import numpy as np
#%%
FIGSIZE_FLAT = (8,2)
LABELSIZE = 15
TICKSIZE = 12
LEGENDSIZE = 12
CCS_PATH = "/mnt/milesan-data-ccs"
TTE_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/tte"
class Colorcodes(object):
    """
        Provides ANSI terminal color codes which are gathered via the ``tput``
        utility. That way, they are portable. If there occurs any error with
        ``tput``, all codes are initialized as an empty string.
        The provides fields are listed below.
        Control:
        - bold
        - reset
        Colors:
        - blue
        - green
        - orange
        - red
        :license: MIT
        """
    def __init__(self):
        try:
            self.bold = subprocess.check_output("tput bold".split(),text=True)
            self.reset = subprocess.check_output("tput sgr0".split(),text=True)
            self.blue = subprocess.check_output("tput setaf 4".split(),text=True)
            self.green = subprocess.check_output("tput setaf 2".split(),text=True)
            self.orange = subprocess.check_output("tput setaf 3".split(),text=True)
            self.red = subprocess.check_output("tput setaf 1".split(),text=True)
        except subprocess.CalledProcessError as e:
            
            self.bold = ""
            self.reset = ""
            self.blue = ""
            self.green = ""
            self.orange = ""
            self.red = ""

_c = Colorcodes()

CRED = _c.red
CEND = _c.reset

#%%
seed_to_time = pd.DataFrame()
for i,file in enumerate(glob.glob(CCS_PATH+ "/S_to_U/boom/**/perfstats.json", recursive=True)):
    try:
        with open(file, "r") as f:
            p = json.load(f)
        seed_to_time = pd.concat([seed_to_time, pd.DataFrame([p])])
    except:
        pass
#%%
seed_to_time["run"] = seed_to_time["seed"]%10
#%%
seed_to_time = seed_to_time.sort_values(by='seed')  # Sort by 'seed' for proper calculation

#%%
seed_to_time["t_acc"] = seed_to_time.apply(
        lambda row: seed_to_time[(seed_to_time['seed'] <= row['seed']) & (seed_to_time["run"] == row["run"])]['t_total'].sum(), axis=1
    )
# %%
seed_to_time['t_acc_h'] = seed_to_time['t_acc'] / 3600

#%%
seed_to_leaker = pd.DataFrame()
with open(CCS_PATH + "/S_to_U/logs/boom.reduce.log") as f:
    for line in f.read().split("\n"):
        if "seed" in line:
            seed = int(line.split(":")[0].split(" ")[1])
        if "Failing instr:" in line:
            leaker = line.split(":")[-1].replace(CRED,"").replace(CEND,"").strip(" ")
            seed_to_leaker = pd.concat([seed_to_leaker, pd.DataFrame([{"seed": seed, "leaker": leaker}])])
            

#%%
seed_to_reduce = pd.DataFrame()
for i,file in enumerate(glob.glob(CCS_PATH+ "/S_to_U/boom/**/reduce.log", recursive=True)):
    with open(file, "r") as f:
        p = json.load(f)
    p["seed"] = int(file.split("/")[-2].split("_")[-2])
    seed_to_reduce = pd.concat([seed_to_reduce, pd.DataFrame([p])])
#%%
seed_data = seed_to_reduce.merge(seed_to_leaker, "left").merge(seed_to_time,"left")
#%%
def leaker_identifier_f(row):
    if row["cross-priv"]:
        if "Exception" in row["leaker"]:
            return "MD"
        elif row["leaker"].startswith("b"):
            return "Trans. MD"
        elif row["leaker"].startswith("jalr"):
            return "cp-Spec-V2"
    else:
        if row["leaker"].startswith("b"):
            return "Spec-V1"
        elif row["leaker"].startswith("jalr"):
            return "Spec-RSB" if "ra" in row["leaker"].split(",")[-2] else "Spec-V2"
        elif row["leaker"].startswith("l"):
            return "Spec-V4"
#%%
seed_data["vuln"] = seed_data.apply(leaker_identifier_f, axis=1)
#%%
seed_data["domain-boundary"] = seed_data.apply(lambda x: "cross-domain" if x["cross-priv"] else "intra-domain",axis=1)
# %%
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
sns.violinplot(seed_data, y="t_acc_h",x="vuln",ax=ax,palette=["r","b"],hue="domain-boundary",order=["Spec-V1","Spec-V2","Spec-V4","MD","Trans. MD","cp-Spec-V2"])
ax.set_xlabel("") 
yticks = [0,20,40,60,80,100,120]
yticklabels = yticks
ax.set_yticks(yticks,labels=yticklabels,fontsize=TICKSIZE)
ax.set_ylim([0,120])
ax.grid()
ax.set_ylabel("TTE [CPUh]",fontsize=LABELSIZE)
ax.legend(title="",fontsize=LEGENDSIZE)
plt.savefig(TTE_PATH+"/tte.transient.svg")

#%%
def s_to_cpuh(s):
    return f"{int(s//3600)}h{int((s%3600)//60)}min{int(s%60)}s"
#%%
def compute_min_t_acc(x):
    min_t_acc = min(x["t_acc"])
    return s_to_cpuh(min_t_acc)

#%%
def compute_median_t_acc(x):
    median_t_acc = np.mean(x["t_acc"])
    return s_to_cpuh(median_t_acc)
# %%

seed_data.groupby("vuln").apply(compute_min_t_acc)
# %%
seed_data.groupby("vuln").apply(compute_median_t_acc)
# %%
