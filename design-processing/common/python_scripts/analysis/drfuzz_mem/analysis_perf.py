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
LABELSIZE = 10
TICKSIZE = 10
LEGENDSIZE = 10

TAINT_MISMATCH_PATH = "/cascade-data/"
PERFORMANCE_PLOTS_PATH = "/mnt/cascade-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/performance"
#%%
perf_df = pd.DataFrame()
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/perfstats.json", recursive=True):
    with open(file, "r") as f:
        perf_df = pd.concat([perf_df,
            pd.DataFrame([
                json.load(f)
            ])
        ])

#%%
PERF_T =  ["t_gen_bbs", "t_spike_resol","t_gen_elf","t_rtl"]
perf_means = pd.DataFrame()
for dut in set(perf_df["dut"]):
    perf_means = pd.concat([
        perf_means,
        pd.DataFrame([
            {
            "dut": dut,
            "t_gen_bbs":np.mean(perf_df[perf_df["dut"] == dut]["t_gen_bbs"]),
            "t_spike_resol":np.mean(perf_df[perf_df["dut"] == dut]["t_spike_resol"]),
            "t_gen_elf":np.mean(perf_df[perf_df["dut"] == dut]["t_gen_elf"]),
            "t_rtl": np.mean(perf_df[perf_df["dut"] == dut]["t_rtl"]),
            }
        ])
    ])
#%%
PERF_T =  ["t_gen_bbs", "t_spike_resol","t_gen_elf","t_rtl"]
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
            "t_gen_bbs":t_gen_bbs /t_sum,
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
duts = ["kronos","rocket","boom","cva6"]
pretty_names = ["Kronos","Rocket","Boom","CVA6"]
pretty_names_t = ["Program Generation","ELF Compilation", "Spike"]
w = 0.6
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    bottom = 0
    for j,t in enumerate(["t_gen_bbs","t_gen_elf","t_spike_resol"]):
        ax.bar(i, perf_means[perf_means["dut"] == dut][t]*100,color=palette[j], hatch=patterns[j], width=w, bottom=bottom, label= None if i != 0 else pretty_names_t[j])
        bottom += perf_means[perf_means["dut"] == dut][t].values[0]*100
    ax.text(i-w/4, bottom+0.5, '{0:.1f}%'.format(bottom))

ax.set_xticks(np.arange(4),labels=pretty_names,fontsize=TICKSIZE)
ax.set_yticks([0,25,50,75,100],labels=[0,25,50,75,100],fontsize=TICKSIZE)

ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Time per step [%]", fontsize=LABELSIZE)

ax.grid(axis="y")
ax.legend()
plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"timesplot.svg"))
# %%
fig, axs = plt.subplots(2,2,figsize=(10,5))
for i,(ax,t) in enumerate(zip(axs.flatten(), PERF_T)):
    sns.histplot(perf_df, x=t, hue='dut' if t=="t_rtl" else None,ax=ax)

plt.tight_layout()    
# %%
fig, axs = plt.subplots(2)
for i,(ax,t) in enumerate(zip(axs.flatten(), ["n_instrs","n_bbs"])):
    sns.histplot(perf_df, x=t, ax=ax)

axs[0].set_xlabel("#instructions")
axs[1].set_xlabel("#BBs")
plt.tight_layout()    


#%%
duts = ["kronos","rocket","boom","cva6"]
pretty_names = ["Kronos","Rocket","Boom","CVA6"]
pretty_names_t = ["Program Generation","ELF Compilation", "Spike Validation"]
w = 0.6
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    total_time = perf_means[perf_means["dut"] == dut]["t_sum"].values[0]
    ax.bar(i, total_time,color="black", width=w)
    ax.text(i-w/4, total_time+0.5, '{0:.1f}s'.format(total_time))

ax.set_xticks(np.arange(4),labels=pretty_names,fontsize=TICKSIZE)
ax.set_yticks([0,50,100,150],labels=[0,50,100,150],fontsize=TICKSIZE)

ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Total runtime per program [s]", fontsize=LABELSIZE)

ax.grid(axis="y")
plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"total_time.svg"))
# ax.legend()

# %%
