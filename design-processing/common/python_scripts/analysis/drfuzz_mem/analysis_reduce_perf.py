#%%
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from seaborn.objects import Stack
import json
import glob
import pandas as pd
import os
import sys
FIGSIZE_FLAT = (8,2)
LABELSIZE = 15
TICKSIZE = 12
LEGENDSIZE = 12
PRETTY_NAMES = {
    "rocket":"Rocket",
    "cva6":"CVA6",
    "boom":"BOOM",
    "openc910":"OpenC910"
}
TAINT_MISMATCH_PATH = "/mnt/milesan-data/REDUCTION_PERF_NO_MMU/"
PERFORMANCE_PLOTS_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/performance"
#%%
perf_df = pd.DataFrame()
new_entry = {}
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/*.reduce.log", recursive=True):
    dut = file.split("/")[-1].split(".")[0]
    with open(file, "r") as f:
        for line in f.read().split("\n"):
            if "seed" in line:
                if len(new_entry):
                    new_entry["success_find_pillar_instr"] = new_entry["pillar_instr"] > 0
                    perf_df = pd.concat([perf_df, pd.DataFrame([new_entry])])
                new_entry = {}
                new_entry["seed"] = int(line.split(":")[0].split(" ")[-1])
                new_entry["id"] = line.split(":")[1].strip(" ")
                new_entry["dut"] = dut
                new_entry["n_bbs"] = int(new_entry["id"].split("_")[-1])
            if "Time to find failing BB" in line:
                new_entry["failing_bb"]=float(line.split(":")[-1].strip()[:-1])
            elif "Time to find failing instr" in line:
                new_entry["failing_instr"]=float(line.split(":")[-1].strip()[:-1])
            elif "Time to find pillar BB" in line:
                new_entry["pillar_bb"]=float(line.split(":")[-1].strip()[:-1])
            elif "Time to find pillar instr" in line:
                new_entry["pillar_instr"]=float(line.split(":")[-1].strip()[:-1])
            elif "Time to nopize instr" in line:
                new_entry["nopize"]=float(line.split(":")[-1].strip()[:-1])   
            elif "Success nopize instr" in line:
                new_entry["success_nopize"]= line.split(":")[-1].strip() == "True"
            elif "Time to reduce taint" in line:
                new_entry["taint"]=float(line.split(":")[-1].strip()[:-1])
            elif "Time to reduce dead code" in line:
                new_entry["dead_code"]=float(line.split(":")[-1].strip()[:-1])
            elif "Success find pillar BB" in line:
                new_entry["success_find_pillar_bb"]= line.split(":")[-1].strip() == "True"
            elif "Success find pillar instr" in line:
                new_entry["success_find_pillar_instr"]= line.split(":")[-1].strip() == "True"
            elif "Taint reduction success" in line:
                new_entry["success_reduce_taint"]= line.split(":")[-1].strip() == "True"
            elif "Dead code reduction success" in line:
                new_entry["success_reduce_dead_code"]= line.split(":")[-1].strip() == "True"
            elif "Total number of non-nop instructions" in line:
                new_entry["n_instrs_before_leaker"] = int(line.split(":")[-1].split("(")[0].strip())
            elif "Failing bb id" in line:
                new_entry["failing_bb_id"] = int(line.split(":")[-1].split("/")[0])
            elif "Failing instr" in line:
                new_entry["leaker"] = line.split(":")[-1].strip().split(" ")[0]
            elif "Total time" in line:
                new_entry["total_time"] = float(line.split(":")[-1][:-1])

#%%

perf_means = pd.DataFrame()
for dut in set(perf_df["dut"]):
    for n_bbs in set(perf_df[perf_df["dut"] == dut]["n_bbs"]):
        where = (perf_df["dut"] == dut) & (perf_df["n_bbs"] == n_bbs)
        failing_bb = np.mean(perf_df[where]["failing_bb"])
        failing_instr = np.mean(perf_df[where]["failing_instr"])
        pillar_bb = np.mean(perf_df[(where) & (perf_df["success_find_pillar_bb"])]["pillar_bb"])
        pillar_instr_vals = perf_df[(where) & (perf_df["success_find_pillar_instr"])]["pillar_instr"]
        pillar_instr = np.mean(pillar_instr_vals) if len(pillar_instr_vals) else 0
        nopize_vals = perf_df[(where) & (perf_df["success_nopize"])]["nopize"]
        nopize = np.mean(nopize_vals) if len(nopize_vals) else 0
        taint = np.mean(perf_df[(where) & (perf_df["success_reduce_taint"])]["taint"])
        dead_code = np.mean(perf_df[(where)]["dead_code"])
        t_sum = failing_bb + failing_instr + pillar_bb + pillar_instr + taint + dead_code
        perf_means = pd.concat([
            perf_means,
            pd.DataFrame([
                {
                "dut": dut,
                "failing_bb": failing_bb,
                "failing_instr":failing_instr,
                "pillar_bb":pillar_bb,
                "pillar_instr":pillar_instr,
                "nopize": nopize,
                "taint":taint,
                "dead_code":dead_code,
                "primer":(pillar_bb+pillar_instr),
                "leaker":(failing_bb+failing_instr),
                "t_sum": t_sum,
                "control-flow": (failing_bb+failing_instr+pillar_bb),
                "program": (failing_bb+failing_instr+pillar_bb+pillar_instr),
                "n_bbs":n_bbs
                }
            ])
        ])

perf_means = perf_means.dropna()
# %%
palette = ['r', 'g', 'b', 'c', 'y', 'm', 'k']
patterns = [ "" ,"////", "*", "o", ".", "+","0"]
duts = [i for i,j in PRETTY_NAMES.items() if i in set(perf_df["dut"])]
#%%
PERF_T =  ["leaker","primer"]
PRETTY_NAMES_T = ["Leaker","Primer"]
w = 0.6
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    bottom = 0
    t_sum = perf_means[perf_means["dut"] == dut]["t_sum"][0]
    for j,t in enumerate(PERF_T):
        ax.bar(i, perf_means[perf_means["dut"] == dut][t]/t_sum*100,color=palette[j], hatch=patterns[j], width=w, bottom=bottom, label= None if i != 0 else PRETTY_NAMES_T[j])
        split = perf_means[perf_means["dut"] == dut][t].values[0]/t_sum*100
        bottom += split
        # if t != PERF_T[-1]:
        #     ax.text(i-w/4, bottom+0.5, '{0:.1f}%'.format(split),size=LEGENDSIZE)


# ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Time per step [%]", fontsize=LABELSIZE)

ax.grid(axis="y")
ax.legend(fontsize=LEGENDSIZE)
# plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"timesplot_relative.svg"))
#%%
PERF_T =  ["failing_bb","failing_instr","pillar_bb","pillar_instr"]
PRETTY_NAMES_T = ["Leaking BB","Leaking Instruction","Primer BB","Primer Instruction"]
# PERF_T =  ["leaker","primer"]
# PRETTY_NAMES_T = ["Leaker","Primer"]
n_bbs_list = list(set(perf_means["n_bbs"]))
n_bbs_list.sort()
w = 0.5
duts = ["rocket","cva6","boom","openc910"]
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    for j,n_bbs in enumerate(n_bbs_list):
        bottom = 0
        where = (perf_means["dut"] == dut) & (perf_means["n_bbs"] == n_bbs)
        if not any(where):
            continue
        t_sum = perf_means[perf_means["dut"] == dut]["t_sum"][0]
        for k,t in enumerate(PERF_T):
            ax.bar(i*w+j*len(duts)*len(n_bbs_list), perf_means[where][t],color=palette[i], hatch=patterns[k], width=w, bottom=bottom, label= None if i+j != 0 else PRETTY_NAMES_T[k])
            bottom += perf_means[where][t].values[0]
            # time_str = f"{bottom//60:.0f}m{bottom%60:.0f}s"
            # ax.text(i-w/4, bottom+0.5, time_str,size=LEGENDSIZE)

# ax.set_yscale("log")
# ax.set_xticks(np.arange(len(duts)),labels=[PRETTY_NAMES[i] for i in duts],fontsize=TICKSIZE)
# ax.set_yticks([0,60*15,60*30,60*45],labels=[0,15,30,45],fontsize=TICKSIZE)
# ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Total runtime [min]", fontsize=LABELSIZE)

ax.grid(axis="y")
ax.legend(fontsize=LEGENDSIZE)
# plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"timesplot_total.svg"))
# %%

duts = ["rocket","cva6","boom","openc910"]
pretty_names = ["Rocket","CVA6","Boom","OpenC910"]
colors = ["red","peru","greenyellow","forestgreen","black"]
w = 1
x_ticks = []
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    where = (perf_means["dut"] == dut)
    total_time = perf_means[where]["t_sum"].values[0]
    ax.bar(i*w+j*len(duts), total_time,color=colors[i], width=w, label=pretty_names[i] if j == 0 else None)

# ax.set_yticks([60,60*5,60*10,60*15],[1,5,10,15])
# ax.set_yscale("log")
# ax.set_ylim([1,10**3])
# ax.set_xticks(x_ticks,labels=n_instrs_list,fontsize=TICKSIZE)

# ax.set_xlabel("Program size [#instructions]", fontsize=LABELSIZE)
# ax.set_ylabel("Total runtime [s]", fontsize=LABELSIZE)

ax.grid(axis="y")
ax.legend()
#%%
for i,dut in enumerate(duts):
    fig, ax = plt.subplots()
    sns.displot(perf_df[perf_df["dut"] == dut],x="n_instrs_before_leaker",kind="kde",hue="leaker_t",ax=ax)
    ax.set_title(dut)
    plt.show()
#%%
for i,dut in enumerate(duts):
    fig, ax = plt.subplots()
    sns.histplot(perf_df[perf_df["dut"] == dut],x="n_instrs_before_leaker",hue="leaker_t",ax=ax,kde=True,stat="density")
    ax.set_title(dut)
    plt.show()

#%%
for i,dut in enumerate(duts):
    fig, ax = plt.subplots()
    sns.histplot(perf_df[perf_df["dut"] == dut],x="n_instrs_before_leaker",hue="leaker_t",kde=True,stat="density",ax=ax)
#%%
sns.histplot(perf_df,x="n_instrs_before_leaker",hue="leaker_t",kde=True,stat="density")

#%%
palette = ['r', 'g', 'b', 'c', 'y', 'm', 'k']
patterns = [ "/" , "*", "o", ".", "+","0"]
duts = ["rocket","cva6","boom","openc910"]
pretty_names = ["Rocket","CVA6","Boom","OpenC910"]
pretty_names_t = ["Program", "Taint","Dead Code"]
perf_t = ["program","taint","dead_code"]
w = 0.6
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    bottom = 0
    t_sum =  perf_means[perf_means["dut"] == dut]["t_sum"].values[0]
    print(f"{dut}: {t_sum}")
    for j,t in enumerate(perf_t):
        r =  perf_means[perf_means["dut"] == dut][t].values[0]/t_sum*100
        ax.bar(i,r,color=palette[j], hatch=patterns[j], width=w, bottom=bottom, label= None if i != 0 else pretty_names_t[j])
        bottom += r
        # if t == perf_t[-2]:
        #     ax.text(i-w/4, bottom+0.5, '{0:.1f}%'.format(bottom),size=LEGENDSIZE)

ax.set_xticks(np.arange(4),labels=pretty_names,fontsize=TICKSIZE)
ax.set_yticks([0,25,50,75,100],labels=[0,25,50,75,100],fontsize=TICKSIZE)
ax.set_ylim([0,100])
ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Time per step [%]", fontsize=LABELSIZE)

ax.grid(axis="y")
ax.legend(fontsize=LEGENDSIZE)
plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"timesplot_relative.svg"))
# %%
