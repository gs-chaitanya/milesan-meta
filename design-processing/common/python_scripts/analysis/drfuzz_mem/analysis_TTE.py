#%%
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import re
import glob
import os
import pandas as pd
TAINT_MISMATCH_PATH = "/cascade-data/"
FIGSIZE_FLAT = (8,2)
LABELSIZE = 10
TICKSIZE = 10
LEGENDSIZE = 10
TTE_PLOTS_PATH = "/mnt/cascade-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/tte"
#%%
log_df = pd.DataFrame()
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/*.log", recursive=True):
    if "rtl_timeout" in file:
        category = "rtl_timeout"
    elif "taint_mismatch" in file:
        category = "taint_mismatch"
    elif "value_mistmatch" in file:
        category = "value_mismatch"
    # elif "failed" in file:
    #     category = "failed"
    else:
        continue
    setting = file.split("/")[-3]
    with open(file, "r") as f:
        logfile = f.read()
    design_name = file.split("/")[-1].split(".")[0]
    lines = logfile.split("\n")
    for i,line in enumerate(lines):
        id = re.findall(f"[0-9]+_{design_name}_[0-9]+_[0-9]+", line)
        if len(id) == 0:
            continue
        assert len(id) == 1, line
        id = id[0]
        for line_ in lines[i:]:
            if "timestamp" in line_:
                timestamp = re.findall("timestamp:.*[0-9]+.[0-9]+", line_)
                assert len(timestamp) == 1
                timestamp = float(timestamp[0].split(":")[-1].strip())
                d = {
                    "dut" : design_name,
                    "category" : category,
                    "id" : id,
                    "timestamp": timestamp,
                    "setting": setting,
                }
                log_df = pd.concat([log_df, pd.DataFrame([d])])


# %%
reduce_df = pd.DataFrame()
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/*.reduce.log", recursive=True):
    setting = file.split("/")[-3]
    with open(file, "r") as f:
        logfile = f.read()
    design_name = file.split("/")[-1].split(".")[0]
    lines = logfile.split("\n")
    for i,line in enumerate(lines):
        id = re.findall(f"[0-9]+_{design_name}_[0-9]+_[0-9]+", line)
        if len(id) == 0:
            continue
        assert len(id) == 1, line
        id = id[0]
        seed = int(id.split("_")[-2])
        timestamp = None
        instr = None
        for line_ in lines[i:]:
            if "Total time for reduction" in line_:
                assert timestamp is None
                timestamp = float(line_.split(":")[-1].strip())
                d = {
                    "dut" : design_name,
                    "category" : category,
                    "id" : id,
                    "timestamp": timestamp,
                    "setting": setting,
                    "instr":instr,
                    "operands":operands,
                    "rd": rd,
                    "seed": id
                }
                break
            if "Failing instr                    :" in line_:
                instr = line_.split(":")[-1].split(" ")[1].strip()
                operands = line_.split(":")[-1].split(",")[1:]
                rd = line_.split(":")[-1].split(",")[0].split(" ")[-1].strip()
                reduce_df = pd.concat([reduce_df, pd.DataFrame([d])])


# %%
w = 0.5
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
duts = ["rocket","boom","cva6"]
for i, dut in enumerate(duts):
    dut_df = reduce_df[reduce_df["dut"] == dut]
    mean = np.mean(dut_df["timestamp"])
    ax.bar(i, mean,color="black")
    ax.text(i-w/4, mean+0.5, '{0:.1f}s'.format(mean))

ax.set_xticks([0,1,2],labels=["Rocket","Boom","CVA6"],fontsize=TICKSIZE)
ax.set_yticks([0,250,500,750,1000],labels=[0,250,500,750,1000],fontsize=TICKSIZE)
# ax.set_ylim(0,50)
ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Reduction Performance (s)", fontsize=LABELSIZE)
ax.grid(axis="y")
# ax.legend(fontsize=LEGENDSIZE)
plt.savefig(os.path.join(TTE_PLOTS_PATH,"reduction.svg"))

# %%
w = 0.5
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
duts = ["cva6", "boom","rocket","kronos"]
for i, dut in enumerate(duts):
    dut_df = log_df[log_df["dut"] == dut]
    mean = np.mean(dut_df["timestamp"])
    ax.bar(i, mean,color="black")
    ax.text(i-w/4, mean+0.5, '{0:.1f}s'.format(mean))

ax.set_xticks([0,1,2],labels=["CVA6","Boom","Rocket","Kronos"],fontsize=TICKSIZE)
ax.set_yticks([0,50,100,150,200],labels=[0,50,100,250,200],fontsize=TICKSIZE)
# ax.set_ylim(0,50)
ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Runtime (s)", fontsize=LABELSIZE)
ax.grid(axis="y")
# ax.legend(fontsize=LEGENDSIZE)
# plt.savefig(os.path.join(TTE_PLOTS_PATH,"runtime_total.svg"))