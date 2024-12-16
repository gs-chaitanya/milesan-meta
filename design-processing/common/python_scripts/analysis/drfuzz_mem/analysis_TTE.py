#%%
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import json
import glob
import pandas as pd
TAINT_MISMATCH_PATH = "/mnt/milesan-data/CT-VIOLATIONS-TTE/"
FIGSIZE_FLAT = (8,2)
LABELSIZE = 15
TICKSIZE = 12
LEGENDSIZE = 12
TTE_PLOTS_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/tte"
PRETTY_NAMES_DUT = {
    "openc910":"OpenC910",
    "cva6":"CVA6"
}
#%%
perf_df = pd.DataFrame()
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/perfstats.json", recursive=True):
    with open(file, "r") as f:
        d = json.load(f)
    d["leaker"] = file.split("/")[4].split("_")[2]
    d["pretty_name_dut"] = PRETTY_NAMES_DUT[d["dut"]]
    perf_df = pd.concat([perf_df,
        pd.DataFrame([
            d
        ])
    ])
    

# %%
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
sns.violinplot(perf_df, y="t_total",x="leaker",hue="pretty_name_dut",saturation=1,showfliers=0,order=["DIV","DIVU","DIVW","DIVUW","REM","REMU","REMW","REMUW"],palette=["r","b"])
ax.set_ylim([0,600])
ax.set_yticks([i*60 for i in range(0,11,2)])
ax.set_yticklabels([i for i in range(0,11,2)],fontsize=TICKSIZE)
ax.set_ylabel("Time to discovery [min]",fontsize=LABELSIZE)
ax.set_xlabel("")
ax.set_xticklabels(ax.get_xticklabels(), size=TICKSIZE)
ax.legend(title="")
plt.savefig(TTE_PLOTS_PATH + "/tte_ct_violations.svg")
# %%
