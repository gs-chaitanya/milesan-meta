#%%
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import json
import glob
import pandas as pd
TAINT_MISMATCH_PATH = "/mnt/milesan-data/MAX_N_INSTRS/"
FIGSIZE_FLAT = (8,2)
LABELSIZE = 15
TICKSIZE = 12
LEGENDSIZE = 12
TTE_PLOTS_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/tte/"
PRETTY_NAMES_DUT = {
    "openc910":"OpenC910",
    "cva6":"CVA6",
    "boom":"BOOM",
    "rocket":"Rocket"
}
#%% Load all perf stats
perf_df = pd.DataFrame()
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/perfstats.json", recursive=True):
    with open(file, "r") as f:
        d = json.load(f)
    d["pretty_name_dut"] = PRETTY_NAMES_DUT[d["dut"]]
    d["n_instrs_upperbound"] = int(file.split("/")[4].split("_")[1])
    perf_df = pd.concat([perf_df,
        pd.DataFrame([
            d
        ])
    ])
#%% Filter out the ones that do not cause leakage (e.g. value mismatch)
taint_mismatch_perf_df = pd.DataFrame()
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/*.taint_mismatch.log", recursive=True):
    with open(file, "r") as f:
        for line in f.read().split("\n"):
            if "seed" in line:
                seed = int(line.split(":")[0].split(" ")[-1])
                taint_mismatch_perf_df = pd.concat([
                    taint_mismatch_perf_df,
                    perf_df[perf_df["seed"] == seed]
                ])

# %%
p_trigger_leakage_df = pd.DataFrame()
for n_instrs_upperbound in set(perf_df["n_instrs_upperbound"]):
    for dut in set(taint_mismatch_perf_df[taint_mismatch_perf_df["n_instrs_upperbound"] == n_instrs_upperbound]["dut"]):
        d = {}
        where = (taint_mismatch_perf_df["n_instrs_upperbound"] == n_instrs_upperbound) & (taint_mismatch_perf_df["dut"] == dut)
        p_trigger_leakage = len(taint_mismatch_perf_df[where])/(10**6/n_instrs_upperbound)*100
        d["p"] = p_trigger_leakage
        d["dut"] = dut
        d["pretty_name_dut"] = taint_mismatch_perf_df[where]["pretty_name_dut"].values[0]
        d["n_instrs"] = n_instrs_upperbound
        p_trigger_leakage_df = pd.concat(
            [p_trigger_leakage_df, pd.DataFrame([d])]
        )

# %%
palette = ["peru","greenyellow","forestgreen","black"]
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
sns.barplot(p_trigger_leakage_df, x="n_instrs",y="p",hue="pretty_name_dut",hue_order=["Rocket","CVA6","BOOM","OpenC910"],ax=ax,palette=palette)
ax.set_ylim([0,100])
ax.set_yticks([0,25,50,75,100])
ax.set_yticklabels([0,25,50,75,100],fontsize=TICKSIZE)
ax.set_ylabel("Percentage [%]",fontsize=LABELSIZE)
ax.set_xticklabels(["100","1k","10k"],fontsize=TICKSIZE)
ax.set_xlabel("Max #instr per program",fontsize=LABELSIZE)
ax.legend(fontsize=LEGENDSIZE)
plt.savefig(TTE_PLOTS_PATH+"/program_length_leakage.svg")

# %%
