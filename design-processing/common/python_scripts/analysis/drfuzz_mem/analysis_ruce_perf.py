#%%
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from seaborn.objects import Stack
import json
import glob
import pandas as pd
import os
FIGSIZE_FLAT = (8,2)
LABELSIZE = 15
TICKSIZE = 12
LEGENDSIZE = 12

TAINT_MISMATCH_PATH = "/mnt/cascade-data/"
PERFORMANCE_PLOTS_PATH = "/mnt/cascade-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/performance"
#%%
perf_df = pd.DataFrame()
new_entry = {}
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/*.reduce.log", recursive=True):
    dut = file.split("/")[-1].split(".")[0]
    with open(file, "r") as f:
        for line in f.read().split("\n"):
            if "seed" in line:
                if len(new_entry):
                    perf_df = pd.concat([perf_df, pd.DataFrame([new_entry])])
                new_entry = {}
                new_entry["seed"] = int(line.split(":")[0].split(" ")[-1])
                new_entry["id"] = line.split(":")[-1].strip(" ")[:-1]
                new_entry["dut"] = dut
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
            
#%%
PERF_T =  ["failing_bb", "failing_instr","pillar_bb","nopize"]
perf_means = pd.DataFrame()
for dut in set(perf_df["dut"]):
    t_gen_bbs = np.mean(perf_df[perf_df["dut"] == dut]["t_gen_bbs"])
    t_spike_resol = np.mean(perf_df[perf_df["dut"] == dut]["t_spike_resol"])
    t_gen_elf = np.mean(perf_df[perf_df["dut"] == dut]["t_gen_elf"])
    t_rtl = np.mean(perf_df[perf_df["dut"] == dut]["t_rtl"])
    t_sum = t_gen_bbs + t_spike_resol + t_gen_elf + t_rtl
    perf_means = pd.concat([
        perf_means,
        pd.DataFrame([
            {
            "dut": dut,
            "t_gen_bbs": t_gen_bbs /t_sum,
            "t_spike_resol":t_spike_resol/t_sum,
            "t_gen_elf":t_gen_elf/t_sum,
            "t_rtl": t_rtl/t_sum,
            "t_sum": t_sum
            }
        ])
    ])

# %%
palette = ['r', 'g', 'b', 'c', 'y', 'm', 'k']
patterns = [ "/" , "*", "o", ".", "+","0"]
duts = ["kronos","rocket","cva6","boom","openc910"]
pretty_names = ["Kronos","Rocket","CVA6","Boom","OpenC910"]
pretty_names_t = ["Program Generation","ELF Compilation", "Spike"]
w = 0.6
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    bottom = 0
    for j,t in enumerate(["t_gen_bbs","t_gen_elf","t_spike_resol"]):
        ax.bar(i, perf_means[perf_means["dut"] == dut][t]*100,color=palette[j], hatch=patterns[j], width=w, bottom=bottom, label= None if i != 0 else pretty_names_t[j])
        bottom += perf_means[perf_means["dut"] == dut][t].values[0]*100
    ax.text(i-w/4, bottom+0.5, '{0:.1f}%'.format(bottom),size=LEGENDSIZE)

ax.set_xticks(np.arange(5),labels=pretty_names,fontsize=TICKSIZE)
ax.set_yticks([0,25,50,75,100],labels=[0,25,50,75,100],fontsize=TICKSIZE)

ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Time per step [%]", fontsize=LABELSIZE)

ax.grid(axis="y")
ax.legend(fontsize=LEGENDSIZE)
# plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"timesplot.svg"))
# %%
# fig, axs = plt.subplots(2,2,figsize=(10,5))
# for i,(ax,t) in enumerate(zip(axs.flatten(), PERF_T)):
#     sns.histplot(perf_df, x=t, hue='dut' if t=="t_rtl" else None,ax=ax)

# plt.tight_layout()    
# # %%
# fig, axs = plt.subplots(2)
# for i,(ax,t) in enumerate(zip(axs.flatten(), ["n_instrs","n_bbs"])):
#     sns.histplot(perf_df, x=t, ax=ax)

# axs[0].set_xlabel("#instructions")
# axs[1].set_xlabel("#BBs")
# plt.tight_layout()    


#%%
duts = ["kronos","rocket","cva6","boom","openc910"]
pretty_names = ["Kronos","Rocket","CVA6","Boom","OpenC910"]
pretty_names_t = ["Program Generation","ELF Compilation", "Spike Validation"]
w = 0.6
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    total_time = perf_means[perf_means["dut"] == dut]["t_sum"].values[0]
    ax.bar(i, total_time,color="black", width=w)
    t = f"{total_time//60:.0f}m{total_time%60:.0f}s"
    ax.text(i-w/2+0.08, total_time+0.5, t ,size=LEGENDSIZE)

ax.set_xticks(np.arange(5),labels=pretty_names,fontsize=TICKSIZE)
ax.set_yticks([0,60,120,180,240],labels=[0,1,2,3,4],fontsize=TICKSIZE)

ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Total runtime per program [min]", fontsize=LABELSIZE)

ax.grid(axis="y")
plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"total_time.svg"))
# ax.legend()
# %%
