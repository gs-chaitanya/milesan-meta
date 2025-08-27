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
TABLE_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/tables"
PRETTY_NAMES_DUT = {
    "openc910":"OpenC910",
    "cva6":"CVA6",
    "boom":"BOOM"
}
TTE_SPECDOC = {
    "Spectre-V1": 26.9,
    "Spectre-V2": 30.6,
    "MD":34.7,
    "Trans. MD": 26.9 
}
VULNS = ["MD","Trans. MD","cp-Spec-V2","Spec-V1","Spec-RSB","Spec-V2","MDS"]

#%%

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
        p["pretty_name_dut"] = PRETTY_NAMES_DUT[p["dut"]]

        seed_to_time = pd.concat([seed_to_time, pd.DataFrame([p])])
    except:
        pass
#%%
mds_ids = set()
for i,file in enumerate(glob.glob(CCS_PATH+ "/MDS/S_to_U/pt-boom/**/perfstats.json", recursive=True)):

    with open(file, "r") as f:
        p = json.load(f)
    if p["id"] in seed_to_time["id"]:
        continue
    mds_ids |= {p["id"]}
    seed_to_time = pd.concat([seed_to_time, pd.DataFrame([p])])

#%%
N_RUNS = 50
#%%
seed_to_time["run"] = seed_to_time["seed"]%N_RUNS
#%%
seed_to_time = seed_to_time.sort_values("dut").sort_values(by='seed')  # Sort by 'seed' for proper calculation

#%%
seed_to_time["t_acc"] = seed_to_time.apply(
        lambda row: seed_to_time[(seed_to_time['seed'] <= row['seed']) & (seed_to_time["run"] == row["run"])  & (seed_to_time["dut"] == row["dut"])]['t_total'].sum(), axis=1
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

with open(CCS_PATH + "/MDS/S_to_U/logs/pt-boom.reduce.log") as f:
    for line in f.read().split("\n"):
        if "seed" in line:
            seed = int(line.split(":")[0].split(" ")[1])
        if "Failing instr:" in line:
            leaker = line.split(":")[-1].replace(CRED,"").replace(CEND,"").strip(" ")
            if seed in seed_to_leaker["seed"]:
                continue

            seed_to_leaker = pd.concat([seed_to_leaker, pd.DataFrame([{"seed": seed, "leaker": leaker}])])
            

#%%
seed_to_reduce = pd.DataFrame()
for i,file in enumerate(glob.glob(CCS_PATH+ "/S_to_U/boom/**/reduce.log", recursive=True)):
    with open(file, "r") as f:
        p = json.load(f)
    p["seed"] = int(file.split("/")[-2].split("_")[-2])
    seed_to_reduce = pd.concat([seed_to_reduce, pd.DataFrame([p])])

for i,file in enumerate(glob.glob(CCS_PATH+ "/MDS/S_to_U/boom/**/reduce.log", recursive=True)):
    with open(file, "r") as f:
        p = json.load(f)
    p["seed"] = int(file.split("/")[-2].split("_")[-2])
    if p["seed"] in seed_to_reduce:
        continue
    seed_to_reduce = pd.concat([seed_to_reduce, pd.DataFrame([p])])
#%%
seed_data = seed_to_reduce.merge(seed_to_leaker, "left").merge(seed_to_time,"left")
#%%
def leaker_identifier_f(row):
    if row["id"] in mds_ids:
        return "cp-MDS" if row["cross-priv"] else "M"
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
    
        # else:
        #     return "div[u][w]/rem[u][w]"
        # # elif row["leaker"].startswith("l"):
        # #     return "Spec-V4"
#%%
seed_data["vuln"] = seed_data.apply(leaker_identifier_f, axis=1)
#%%
seed_data["domain-boundary"] = seed_data.apply(lambda x: "S->U" if x["cross-priv"] else "S->S",axis=1)
#%%
def get_tte(x):
    t_accs = seed_data[(seed_data["vuln"] == x["vuln"]) & (seed_data["run"] == x["run"])]["t_acc"]
    return None if not len(t_accs) else min(t_accs)

#%%
ttes = pd.DataFrame()
for vuln in VULNS:
    for run in range(0,N_RUNS):
        t =  seed_data[(seed_data["vuln"] == vuln) & (seed_data["run"] == run)]
        if not len(t):
            continue
        tte = min(t["t_acc"])
        ttes = pd.concat([
            ttes,
            pd.DataFrame(
                [ {
                    "tte" : tte,
                    "run" : run,
                    "vuln" :vuln,
                    "domain-boundary":t["domain-boundary"].values[0]
                }
                ]
            )
        ])
# %%
ttes['tte_h'] = ttes['tte'] / 3600
ttes['tte_m'] = ttes['tte'] / 60

# %%
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
sns.violinplot(ttes, y="tte_h",x="vuln",ax=ax,palette=["r","b"],hue="domain-boundary",order=["Spec-V1","Spec-V2","MD","cp-MDS","Trans. MD","cp-Spec-V2","MDS"])
ax.set_xlabel("") 
yticks = [0,5,10,15,20,25]
yticklabels = yticks
ax.set_yticks(yticks,labels=yticklabels,fontsize=TICKSIZE)
ax.set_ylim([0,25])
ax.grid()
ax.set_ylabel("TTE [CPUh]",fontsize=LABELSIZE)
ax.legend(title="",fontsize=LEGENDSIZE)
# plt.savefig(TTE_PATH+"/tte_transient.svg")

#%%
def s_to_cpuh(s):
    return f"{int(s//3600)}h{int((s%3600)//60)}m"
#%%
def compute_min_tte(x):
    min_tte = min(x["tte"])
    return s_to_cpuh(min_tte)

#%%
def compute_median_tte(x):
    median_tte = np.median(x["tte"])
    return s_to_cpuh(median_tte)

#%%
def compute_mean_tte(x):
    mean_tte = np.mean(x["tte"])
    return s_to_cpuh(mean_tte)

#%%
def compute_stddev_tte(x):
    stddev = np.std(x["tte"])
    return s_to_cpuh(stddev)

#%%
def compute_min_seed(x):
    return np.min(x["seed"])
#%%
def compute_median_seed(x):
    return np.median(ttes[ttes["run"] == x["run"]]["seed"])

#%%
def compute_mean_seed(x):
    return np.mean(ttes[ttes["run"] == x["run"]]["seed"])

#%%
def compute_stddv_seed(x):
    return np.std(ttes[ttes["run"] == x["run"]]["seed"])
# %%

mins = ttes.groupby("vuln").apply(compute_min_tte)
# %%
means = ttes.groupby("vuln").apply(compute_mean_tte)
# %%
medians = ttes.groupby("vuln").apply(compute_median_tte)
# %%
stds= ttes.groupby("vuln").apply(compute_stddev_tte)
#%%
table_data = pd.DataFrame()
table_data["mean"] = means
table_data["median"] = medians
table_data["stddev"] = stds
table_data = table_data.reindex(["Spec-V1","Spec-V2","MD","Trans. MD","cp-Spec-V2"])
table_data.to_csv(TABLE_PATH + "/tte_transient.csv")
print(table_data)
#%%

ttes.groupby("vuln").apply(compute_median_seed)
# %%
ttes.groupby("vuln").apply(compute_mean_seed)
# %%
ttes.groupby("vuln").apply(compute_stddv_seed)
# %%
vulns = ["MD","Trans. MD","cp-Spec-V2","Spec-V1","Spec-RSB","Spec-V2"]
for vuln in vulns:
    median = np.median(ttes[ttes["vuln"] == vuln]["seed"])//N_RUNS
    mean = np.mean(ttes[ttes["vuln"] == vuln]["seed"])//N_RUNS
    std = np.std(ttes[ttes["vuln"] == vuln]["seed"])//N_RUNS
    print(f'Vuln: {vuln}: {median}, {mean}, {std}')
# %%
