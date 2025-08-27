#%%
import numpy
import pandas as pd
import glob
import matplotlib.pyplot as plt
import seaborn as sns
import json
import subprocess
import numpy as np
import re
import pickle
#%%
FIGSIZE_FLAT = (8,2)
FIGSIZE_RECT = (16,6)
TTES_PICKLE_PATH = "/mnt/milesan-data-ccs/ttes.pickle"
LABELSIZE = 15
TICKSIZE = 12
LEGENDSIZE = 12
CCS_PATH = "/mnt/milesan-data-ccs"
PLOT_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/tte"
TABLE_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/tables"
PRETTY_NAMES_DUT = {
    "openc910":"OpenC910",
    "cva6":"CVA6",
    "boom":"BOOM",
    "pt-boom":"BOOM"
}
TTE_SPECDOC = {
    "Spectre-V1": 26.9*3600,
    "Spectre-V2": 30.6*3600,
    "Meltdown":34.7*3600,
    "Trans. Meltdown": 26.9*3600 
}
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
perfstats = pd.DataFrame()
for i,file in enumerate(glob.glob(CCS_PATH+ "/**/perfstats.json", recursive=True)):
    if "to" not in file:
        continue
    with open(file, "r") as f:
        p = json.load(f)
    context = re.findall("[SUM]_to_[SUM]",file)[0]
    p["taint_source_priv"] = context[0]
    p["taint_sink_priv"] = context[-1]
    p["context"] = context
    perfstats = pd.concat([perfstats, pd.DataFrame([p])])

#%%
reduce_log = pd.DataFrame()
for i,file in enumerate(glob.glob(CCS_PATH+ "/**/reduce.log.json", recursive=True)):
    if "to" not in file:
        continue
    with open(file, "r") as f:
        p = json.load(f)
    context = re.findall("[SUM]_to_[SUM]",file)[0]
    p["taint_source_priv"] = context[0]
    p["taint_sink_priv"] = context[-1]
    p["context"] = context
    reduce_log = pd.concat([reduce_log, pd.DataFrame([p])])

# %%
#%%
for dut in ["pt-boom"]:
    for source in ["S","U"]:
        for sink in ["S","U"]:
            if source == sink:
                continue
            if f"{source}_to_{sink}" == "M_to_S":
                continue
            print(f"{dut}->{source}_to_{sink}")

            id_to_succ = {}
            id_to_leaker = {}
            try:
                with open(CCS_PATH + f"/MDS/{source}_to_{sink}/logs/{dut}.reduce.log.bk") as f:
                    for line in f.read().split("\n"):
                        if "seed" in line:
                            seed = int(line.split(":")[0].split(" ")[1])
                            id = line.split(" ")[-1].strip(":")
                        if "Failing instr" in line:
                            leaker = line.strip("\t Failing instr: ")
                            id_to_leaker[id] = leaker.replace(CRED,"").replace(CEND,"")
                        if "Dead code reduction success:" in line:
                            id_to_succ[id] = "True" in line
            except Exception as e:
                print(e)
            
            with open(CCS_PATH + f"/MDS/{source}_to_{sink}/logs/{dut}.reduce.log") as f:
                for line in f.read().split("\n"):
                    if "seed" in line:
                        seed = int(line.split(":")[0].split(" ")[1])
                        id = line.split(" ")[-1].strip(":")
                    if "Failing instr" in line:
                        leaker = line.strip("\t Failing instr: ")
                        id_to_leaker[id] = leaker.replace(CRED,"").replace(CEND,"")
                    if "Dead code reduction success:" in line:
                        id_to_succ[id] = "True" in line

                for i,file in enumerate(glob.glob(CCS_PATH+ f"/MDS/{source}_to_{sink}/{dut}/**/reduce.log", recursive=True)):
                    if "to" not in file:
                        continue
                    with open(file, "r") as f:
                        p = json.load(f)
                    # with open(file + ".bk", "w") as f:
                    #     json.dump(p,f)
                    p["id"] = file.split("/")[-2]
                    p["dut"] = dut
                    assert p["id"] != "pt-boom"
                    p["success_reduce_dead_code"] = id_to_succ[p["id"]] if p["id"] in id_to_succ else False
                    p["leaker"] = id_to_leaker[p["id"]] 
                    p["leaker_priv"] =  p["leaker"][1] 
                    print(file)
                    with open(file+ ".json", "w") as f:
                        json.dump(p,f)
            # except Exception as e:
            #     print(e)
#%%
N_RUNS = 50
#%%
perfstats["run"] = perfstats["seed"]%N_RUNS
#%%
# perfstats = perfstats.sort_values("dut").sort_values(by='seed')  # Sort by 'seed' for proper calculation

#%%
perfstats["t_acc"] = perfstats.apply( \
        lambda row: \
            perfstats[ \
                (perfstats['seed'] <= row['seed']) & \
               (perfstats["run"] == row["run"])  & \
                (perfstats["dut"] == row["dut"])  & \
                (perfstats["context"] == row["context"])  \
                ] \
                ['t_total'].sum(), axis=1)
# %%
perfstats['t_acc_h'] = perfstats['t_acc'] / 3600
#%%
# %%
merged = pd.merge(reduce_log, perfstats,on = ["id","context"],how="left")
#%%
for col in merged.columns:
    if col.endswith("_x"):
        if set(merged[col] == merged[col[:-2]+"_y"]) == {True}:
            merged[col[:-2]] = merged[col]
#%%

# %%
def is_branch(instr):
    return "beq" in instr or "bne" in instr or "bge" in instr or "blt" in instr

def is_jalr(instr):
    return "jalr" in instr

def is_ret(instr):
    return is_jalr(instr) and "ra" in instr.split(",")[-2]

def is_except(instr):
    return "Exception" in instr

def is_load(instr): 
    return "lh" in instr or "lb" in instr or "lw" in instr or "ld" in instr 

def leaker_identifier_f(row):
    cross_priv = row["taint_source_priv"] != row["leaker_priv"]
    leaker = row["leaker"]
    if is_ret(leaker):
        if cross_priv:
            return "cp-Spectre-RSB"
        else:
            return "Spectre-RSB"
    elif is_branch(leaker):
        if cross_priv:
            return "Trans. Meltdown"
        else:
            return "Spectre-V1"
    elif is_jalr(leaker):
        if cross_priv:
            return "cp-Spectre-V2"
        else:
            return "Spectre-V2"
    elif is_except(leaker) and is_load(leaker):
        if row["dut"] == "pt-boom" and row["id"] not in reduce_log[reduce_log["dut"] == "boom"]["id"]:
            return "MDS*"
        return "Meltdown"
    elif is_load(leaker):
        if cross_priv:
            return "cp-Spectre-V4"
        else:
            return "Spectre-V4"
#%%
merged["vuln"] = merged.apply(leaker_identifier_f, axis=1)

#%%
with open(TTES_PICKLE_PATH,"rb") as f:
    ttes = pickle.load(f)
#%%
ttes = pd.DataFrame()
for vuln in set(merged["vuln"]):
    for run in range(0,N_RUNS):
        for dut in set(merged["dut"]):
                for taint_source_priv in set(merged["taint_source_priv"]):
                    for leaker_priv in set(merged["leaker_priv"]):
                        t = merged[
                            (merged["vuln"] == vuln) &  \
                            (merged["run"] == run) & \
                            (merged["dut"] == dut) & \
                            (merged["taint_source_priv"] == taint_source_priv) & \
                            (merged["leaker_priv"] == leaker_priv) \
                            ]
                        if not len(t):
                            continue
                        tte = min(t["t_acc"])
                        id = t[t["t_acc"] == tte]["id"]
                        ttes = pd.concat([
                            ttes,
                            pd.DataFrame(
                                [ {
                                    "tte" : tte,
                                    "run" : run,
                                    "vuln" :vuln,
                                    "dut":dut,
                                    "pretty_name_dut" : PRETTY_NAMES_DUT[dut],
                                    "taint_source_priv": taint_source_priv,
                                    "leaker_priv": leaker_priv,
                                    "id" : id.values[0],
                                    "cross-priv": taint_source_priv != leaker_priv
                                }
                                ]
                            )
                        ])
# %%
ttes['tte_h'] = ttes['tte'] / 3600
ttes['tte_m'] = ttes['tte'] / 60
# %%
TAINT_SOURCE_PRIVS = ["S","U","M"]
TAINT_SINK_PRIVS = ["S","U"]
hue_order = ["BOOM","CVA6","OpenC910"]
fig, ax = plt.subplots(nrows = len(TAINT_SOURCE_PRIVS), ncols = len(TAINT_SINK_PRIVS), figsize=FIGSIZE_RECT)
for i,taint_source_priv in enumerate(TAINT_SOURCE_PRIVS):
    for j,leaker_priv in enumerate(TAINT_SINK_PRIVS):
        filtered_ttes = ttes[(ttes["taint_source_priv"] == taint_source_priv) & \
                            (ttes["leaker_priv"] == leaker_priv)]
        if not len(filtered_ttes):
            continue
        sns.violinplot(filtered_ttes, y="tte_h",x="vuln",ax=ax[i,j],hue="pretty_name_dut",hue_order=hue_order)
        # ax[i,j].set_title(f"{taint_source_priv} -> {leaker_priv}")
        if i != 0 or j!= 0:
            ax[i,j].legend("")
plt.tight_layout()    
# ax.legend(title="",fontsize=LEGENDSIZE)

# %%

hueorder = ["Spectre-V1","Spectre-V2","Spectre-RSB","Meltdown","Trans. Meltdown","cp-Spectre-V2","MDS*"]
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
filtered_ttes = ttes[(ttes["pretty_name_dut"] == "BOOM") & (ttes["vuln"] != "Spectre-V4") & (ttes["vuln"] != "cp-Spectre-RSB")].sort_values('leakage-type',ascending=False)

sns.violinplot(filtered_ttes, y="tte_h",x="vuln",ax=ax,scale="width",order=hueorder,hue="leakage-type",palette=["b","r"])
ax.set_ylim([0,25])
yticks = [0,5,10,15,20,25]
yticklabels = yticks
ax.set_yticks(yticks,labels=yticklabels,fontsize=TICKSIZE)
x_tick_labels = ["Spec-V1","Spec-V2","Spec-RSB","MD","Trans-MD","Spec-V2","MDS*"]
ax.set_xticks(hueorder,labels=x_tick_labels,fontsize=TICKSIZE)
ax.grid()
ax.set_ylabel("TTE [CPUh]",fontsize=LABELSIZE)
ax.set_xlabel("")
ax.legend(title="",fontsize=LEGENDSIZE,title_fontsize=LEGENDSIZE)
# plt.tight_layout() 

plt.savefig(PLOT_PATH+"/tte_transient.svg")
#%%

fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
filtered_ttes = ttes[(ttes["pretty_name_dut"] == "OpenC910") & (ttes["vuln"] != "cp-Spectre-V4")] 
sns.violinplot(filtered_ttes, y="tte_h",x="vuln",ax=ax,scale="width",hue="cross-priv",palette=["b","r"])
# ax.set_ylim([0,25])
# yticks = [0,5,10,15,20,25]
# yticklabels = yticks
# ax.set_yticks(yticks,labels=yticklabels,fontsize=TICKSIZE)
# x_tick_labels = ["Spec-V1","Spec-V2","Spec-RSB","MD","Trans-MD","cp-SpecV2","MDS*"]
# ax.set_xticks(hueorder,labels=x_tick_labels,fontsize=TICKSIZE)
ax.grid()
ax.set_ylabel("TTE [CPUh]",fontsize=LABELSIZE)
ax.set_xlabel("")
ax.legend(title="Cross-Privilege",fontsize=LEGENDSIZE,title_fontsize=LEGENDSIZE)
#%%
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
filtered_ttes = ttes[(ttes["pretty_name_dut"] == "CVA6")] 
sns.violinplot(filtered_ttes, y="tte_h",x="vuln",ax=ax,scale="width",hue="cross-priv",palette=["b","r"])
# ax.set_ylim([0,25])
# yticks = [0,5,10,15,20,25]
# yticklabels = yticks
# ax.set_yticks(yticks,labels=yticklabels,fontsize=TICKSIZE)
# x_tick_labels = ["Spec-V1","Spec-V2","Spec-RSB","MD","Trans-MD","cp-SpecV2","MDS*"]
# ax.set_xticks(hueorder,labels=x_tick_labels,fontsize=TICKSIZE)
ax.grid()
ax.set_ylabel("TTE [CPUh]",fontsize=LABELSIZE)
ax.set_xlabel("")
ax.legend(title="Cross-Privilege",fontsize=LEGENDSIZE,title_fontsize=LEGENDSIZE)

#%%

def s_to_cpuh(s):
    return f"{int(s//3600)}h{int((s%3600)//60)}m"
#%%
def compute_min_tte(x):
    return  min(x["tte"])

#%%
def compute_median_tte(x):
    return np.median(x["tte"])

#%%
def compute_mean_tte(x):
    return np.mean(x["tte"])
#%%
def compute_stddev_tte(x):
    return np.std(x["tte"])

#%%
def compute_min_tte(x):
    return np.std(x["tte"])
#%%
medians = ttes.groupby(["dut", "vuln"]).apply(compute_median_tte)
#%%
means = ttes.groupby(["dut", "vuln"]).apply(compute_mean_tte)
#%%
stds = ttes.groupby(["dut", "vuln"]).apply(compute_stddev_tte)
#%%
mins = ttes.groupby(["dut", "vuln"]).apply(compute_min_tte)
#%%
medians_df = pd.DataFrame(medians.reset_index())
medians_df = medians_df.rename({0:"median"},axis=1)
means_df = pd.DataFrame(means.reset_index())
means_df = means_df.rename({0:"mean"},axis=1)
stds_df = pd.DataFrame(stds.reset_index())
stds_df = stds_df.rename({0:"stddev"},axis=1)
mins_df = pd.DataFrame(mins.reset_index())
mins_df = mins_df.rename({0:"min"},axis=1)
#%%
table_data = pd.merge(medians_df,means_df,on=["vuln","dut"])
table_data = pd.merge(table_data, stds_df, on = ["vuln","dut"])
table_data = pd.merge(table_data, mins_df, on = ["vuln","dut"])
table_data["mean_cpuh"] = table_data["mean"].apply(s_to_cpuh)
table_data["median_cpuh"] = table_data["median"].apply(s_to_cpuh)
table_data["stddev_cpuh"] = table_data["stddev"].apply(s_to_cpuh)
table_data["min_cpuh"] = table_data["min"].apply(s_to_cpuh)
#%%
def compute_specdoc_mean_speedup(x):
    if x["vuln"] in TTE_SPECDOC.keys():
        return TTE_SPECDOC[x["vuln"]]/x["mean"]
def compute_specdoc_max_speedup(x):
    if x["vuln"] in TTE_SPECDOC.keys():
        return TTE_SPECDOC[x["vuln"]]/x["min"]

#%%
table_data_boom = table_data[(table_data["dut"] == "boom") | (table_data["dut"] == "pt-boom") & (table_data["vuln"] == "MDS*")]
table_data_boom = table_data_boom[table_data_boom["vuln"] != "Spectre-V4"]
table_data_boom["pretty_name_dut"] = "BOOM"

# Define the custom order for the "vuln" column
vuln_order = [
    "Spectre-V1", 
    "Spectre-V2", 
    "Spectre-RSB", 
    # "Spectre-V4", 
    "Meltdown", 
    "Trans. Meltdown", 
    "cp-Spectre-V2", 
    "MDS*"
]

# Convert "vuln" column to a categorical type with the specified order
table_data_boom["vuln"] = pd.Categorical(table_data_boom["vuln"], categories=vuln_order, ordered=True)
table_data_boom["specdoc-mean-speedup"] = table_data_boom.apply(compute_specdoc_mean_speedup,axis=1)
table_data_boom["specdoc-max-speedup"] = table_data_boom.apply(compute_specdoc_max_speedup,axis=1)

# Sort the rows by the custom order of "vuln"
table_data_boom = table_data_boom.sort_values(by="vuln")
# table_data_boom.to_csv(TABLE_PATH + "/tte_transient.csv")
# table_data.to_csv(TABLE_PATH + "/tte_transient.csv")

#%%
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
sns.violinplot(ttes[ttes["pretty_name_dut"] == "OpenC910"], y="tte_h",x="vuln",ax=ax,hue="cross-priv")
# ax.set_ylim([0,25])
# yticks = [0,5,10,15,20,25]
# yticklabels = yticks
# ax.set_yticks(yticks,labels=yticklabels,fontsize=TICKSIZE)
ax.grid()
ax.set_ylabel("TTE [CPUh]",fontsize=LABELSIZE)
plt.tight_layout() 
# %%
#%%
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
sns.violinplot(ttes[ttes["pretty_name_dut"] == "CVA6"], y="tte_h",x="vuln",ax=ax,hue="cross-priv")
# ax.set_ylim([0,25])
# yticks = [0,5,10,15,20,25]
# yticklabels = yticks
# ax.set_yticks(yticks,labels=yticklabels,fontsize=TICKSIZE)
ax.grid()
ax.set_ylabel("TTE [CPUh]",fontsize=LABELSIZE)
plt.tight_layout() 
# %%
