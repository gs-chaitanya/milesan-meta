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
TAINT_MISMATCH_PATH = "/mnt/milesan-data/"
PERFORMANCE_PLOTS_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/performance"
#%%
perf_df = pd.DataFrame()
new_entry = {}
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/*.reduce.log", recursive=True):
    print(file)
    dut = file.split("/")[-1].split(".")[0]
    with open(file, "r") as f:
        for line in f.read().split("\n"):
            if "seed" in line:
                if "n_instrs_before_leaker" in new_entry:
                    perf_df = pd.concat([perf_df, pd.DataFrame([new_entry])])
                new_entry = {}
                new_entry["seed"] = int(line.split(":")[0].split(" ")[-1])
                new_entry["id"] = line.split(":")[1].strip(" ")
                new_entry["dut"] = dut
                new_entry["n_bbs"] = int(new_entry["id"].split("_")[-1])
                cross_privilege = False
            elif "Total number of non-nop instructions" in line:
                new_entry["n_instrs_before_leaker"] = int(line.split(":")[-1].split("(")[0].strip())
            elif "Failing instr" in line:
                new_entry["leaker"] = line.split(":")[-1].strip().split(" ")[0]

#%%
fig, ax = plt.subplots(figsize=(20,2))
sns.boxplot(perf_df,x="leaker",y="n_instrs_before_leaker",hue="dut",showfliers=False)
# ax.set_yticks([10**4,2*10**4,3*10**4])
# ax.set_yticklabels(["10k","20k","30k"])
ax.set_ylabel("#instr")
# %%
