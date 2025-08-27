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
MILESAN_DATADIR = "/mnt/milesan-data/TAINT_STATS/"
EXEC_PLOTS_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/exec"
#%%
exec_traces = []
for i,file in enumerate(glob.glob(MILESAN_DATADIR+ "**/taint_stats.json", recursive=True)):
    with open(file, "r") as f:
        try:
            exec_traces += [json.load(f)]
        except Exception as e:
            print(e)


# %%


idx = 3
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
priv = [i["priv"] for i in exec_traces[idx]]
taint_source_privs = [i["taint_source_privs"] for i in exec_traces[idx]]
taint_sink_privs = [i["taint_sink_privs"] for i in exec_traces[idx]]
taint = [i["n_tainted_regs_ratio"]*100 for i in exec_traces[idx]]
sns.lineplot(taint,ax=ax,color="black")
ax.fill_between(range(0,len(priv)), 0, 1,  where=[i in j for i,j in zip(priv, taint_source_privs)],
                color='red', alpha=0.5, transform=ax.get_xaxis_transform(), label="$D_+$")

ax.fill_between(range(0,len(priv)), 0, 1, where=[i not in j for i,j in zip(priv, taint_source_privs)],
            color='blue', alpha=0.5, transform=ax.get_xaxis_transform(), label="$D_-$")


# ax.fill_between(range(0,len(priv)), 0, 1, where=[i not in j+k for i,j,k in zip(priv, taint_sink_privs,taint_source_privs)],
#             color='grey', alpha=0.1, transform=ax.get_xaxis_transform(), label="$C_{\bot}$")

ax.grid(axis="y")
ax.set_ylim(0,100)
ax.set_yticks([0,25,50,75,100])
ax.set_yticklabels([0,25,50,75,100],fontsize=TICKSIZE)
ax.set_xlim(0,4000)
ax.set_xticks([0,1000,2000,3000,4000])
ax.set_xticklabels(["0","1k","2k","3k","4k"],fontsize=TICKSIZE)
ax.set_ylabel("Tainted registers [%]",fontsize=LABELSIZE)
ax.set_xlabel("Simulation cycle",fontsize=LABELSIZE)
ax.legend(fontsize=LEGENDSIZE,loc="best")
plt.savefig(os.path.join(EXEC_PLOTS_PATH, "taint_in_regs.svg"))

# %%
ratios = []
for exec_trace in exec_traces:
    average_in_trace = 0
    n_instrs = 0
    for instr in exec_trace:
        if instr["priv"] in instr["taint_source_privs"]:
            average_in_trace += instr["n_tainted_regs_ratio"]*100
            n_instrs += 1

    if n_instrs == 0:
        continue
    ratios += [average_in_trace/n_instrs]
mean = np.mean(ratios)
median = np.median(ratios)

fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
sns.histplot(ratios,ax=ax,stat="probability",binwidth=3,color="black")
ax.axvline(x=mean, label="Mean ({0:.1f}%)".format(mean),color="r")
ax.axvline(x=median, label="Median ({0:.1f}%)".format(median))
ax.set_ylabel("Test cases [%]", fontsize=LABELSIZE)
ax.grid(axis="y")
ax.set_yticks([0.05,0.1,0.15])
ax.set_xticks([0,20,40,60,80,100])
ax.set_yticklabels([5,10,15], fontsize=TICKSIZE)
ax.set_xticklabels([0,20,40,60,80,100],fontsize=TICKSIZE)
ax.set_xlabel("Ratio of tainted registers [%]", fontsize=LABELSIZE)
ax.legend(fontsize=LEGENDSIZE,loc="upper left")
plt.savefig(os.path.join(EXEC_PLOTS_PATH, "taint_in_regs_stat.svg"))
# %%
ratios = []
for exec_trace in exec_traces:
    average_in_trace = 0
    n_instrs = 0
    for instr in exec_trace:
        if instr["priv"] == 1:
            if instr["rd_value_t0_after_exec"] is not None:
                average_in_trace += 1
            n_instrs += 1

    if n_instrs == 0:
        continue
    ratios += [average_in_trace/n_instrs*100]
mean = np.mean(ratios)
median = np.median(ratios)
# %%
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
sns.histplot(ratios,ax=ax,stat="probability",color="black")
ax.axvline(x=mean, label="Mean ({0:.1f}%)".format(mean),color="r")
ax.axvline(x=median, label="Median ({0:.1f}%)".format(median))
ax.set_xlim(0,100)
ax.set_ylabel("Test cases [%]",fontsize=LABELSIZE)
ax.grid(axis="y")
ax.set_yticks([0.1,0.2])
ax.set_yticklabels([10,20], fontsize=TICKSIZE)
ax.set_xticklabels([0,20,40,60,80,100],fontsize=TICKSIZE)
ax.set_xlabel("Ratio of tainting instructions [%]", fontsize=LABELSIZE)
ax.legend(fontsize=LEGENDSIZE)
plt.savefig(os.path.join(EXEC_PLOTS_PATH, "taint_in_comps_stat.svg"))
# %%
ratios_all_privs = pd.DataFrame()
for exec_trace in exec_traces:
    average_in_trace = 0
    n_instrs = 0
    for instr in exec_trace:
        if instr["priv"] in instr["taint_source_privs"]:
            average_in_trace += 1
        n_instrs += 1

    if n_instrs == 0:
        continue
    ratio = average_in_trace/n_instrs*100
    if ratio == 0:
        continue
    ratios_all_privs = pd.concat([ratios_all_privs, pd.DataFrame([
        {
        "ratio": ratio,
        "taint_source_privs":instr["taint_source_privs"]
        }
    ])])

priv_names = ["U","S"]
for priv in set([0,1]):
    ratios = ratios_all_privs[[priv in r for r in ratios_all_privs["taint_source_privs"]]]
    mean = np.mean(ratios["ratio"])
    median = np.median(ratios["ratio"])
    fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
    sns.histplot(ratios,x="ratio", ax=ax,stat="probability",color="black",binwidth=5)
    ax.axvline(x=mean, label=f"Mean {priv_names[priv]}-mode " + "({0:.1f}%)".format(mean),color="r")
    ax.axvline(x=median, label=f"Median {priv_names[priv]}-mode " + "({0:.1f}%)".format(median))
    ax.set_xlim(0,100)
    ax.set_ylabel("Test cases [%]", fontsize=LABELSIZE)
    ax.grid(axis="y")
    ax.set_yticks([0,0.1,0.2,0.3])
    ax.set_yticklabels([0,10,20,30],fontsize=TICKSIZE)
    ax.set_xticklabels([0,20,40,60,80,100],fontsize=TICKSIZE)
    ax.set_xlabel(f"Ratio of taint-source instructions {priv_names[priv]}-mode [%]",fontsize=LABELSIZE)
    ax.legend(fontsize=LEGENDSIZE)
    # plt.savefig(os.path.join(EXEC_PLOTS_PATH, f"comp_in_taint_source_priv_{[priv_names[priv]]}.svg"))

# %%
ratios_all_privs = pd.DataFrame()
for exec_trace in exec_traces:
    average_in_trace = 0
    n_instrs = 0
    for instr in exec_trace:
        if instr["priv"] != 3 and instr["priv"] not in instr["taint_source_privs"]:
            average_in_trace += 1
        n_instrs += 1

    if n_instrs == 0:
        continue
    ratio = average_in_trace/n_instrs*100
    ratios_all_privs = pd.concat([ratios_all_privs, pd.DataFrame([
        {
        "ratio": ratio,
        "taint_source_privs":instr["priv"]
        }
    ])])

priv_names = ["U","S"]
for priv in set([0,1]):
    ratios = ratios_all_privs[ratios_all_privs["taint_source_privs"] == priv]
    mean = np.mean(ratios["ratio"])
    median = np.median(ratios["ratio"])
    fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
    sns.histplot(ratios,x="ratio", ax=ax,stat="probability",color="black",binwidth=5)
    ax.axvline(x=mean, label=f"Mean of instructions executed in taint-sink {priv_names[priv]}-mode " + "({0:.1f}%)".format(mean),color="r")
    ax.axvline(x=median, label=f"Median of instructions executed in taint-sink {priv_names[priv]}-mode " + "({0:.1f}%)".format(median))
    ax.set_xlim(0,100)
    ax.set_ylabel("Test cases [%]", fontsize=LABELSIZE)
    ax.grid(axis="y")
    ax.set_yticks([0,0.2,0.4])
    ax.set_yticklabels([0,20,40],fontsize=TICKSIZE)
    ax.set_xticklabels([0,20,40,60,80,100],fontsize=TICKSIZE)
    ax.set_xlabel(f"Ratio of instructions executed in taint-sink {priv_names[priv]}-mode [%]",fontsize=LABELSIZE)
    ax.legend()
    # plt.savefig(os.path.join(EXEC_PLOTS_PATH, f"comp_in_taint_sink_priv_{[priv_names[priv]]}.svg"))

# %%
ratios_all_privs = pd.DataFrame()
for exec_trace in exec_traces:
    average_in_trace = 0
    n_instrs = 0
    for instr in exec_trace:
        if instr["priv"] == 3:
            average_in_trace += 1
        n_instrs += 1

    if n_instrs == 0:
        continue
    ratio = average_in_trace/n_instrs*100
    ratios_all_privs = pd.concat([ratios_all_privs, pd.DataFrame([
        {
        "ratio": ratio,
        "taint_source_privs":instr["priv"]
        }
    ])])

priv_names = ["U","S","H","M"]
for priv in set([1]):
    ratios = ratios_all_privs[ratios_all_privs["taint_source_privs"] == priv]
    mean = np.mean(ratios["ratio"])
    median = np.median(ratios["ratio"])
    fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
    sns.histplot(ratios,x="ratio", ax=ax,stat="probability",color="black",binwidth=5)
    ax.axvline(x=mean, label=f"Mean of instructions executed in taint-sink {priv_names[priv]}-mode " + "({0:.1f}%)".format(mean),color="r")
    ax.axvline(x=median, label=f"Median of instructions executed in taint-sink {priv_names[priv]}-mode " + "({0:.1f}%)".format(median))
    ax.set_xlim(0,100)
    ax.set_ylabel("Test cases [%]", fontsize=LABELSIZE)
    ax.grid(axis="y")
    ax.set_yticks([0,0.2,0.4])
    ax.set_yticklabels([0,20,40],fontsize=TICKSIZE)
    ax.set_xticklabels([0,20,40,60,80,100],fontsize=TICKSIZE)
    ax.set_xlabel(f"Ratio of instructions executed in taint-sink {priv_names[priv]}-mode [%]",fontsize=LABELSIZE)
    ax.legend()
    # plt.savefig(os.path.join(EXEC_PLOTS_PATH, f"comp_in_taint_sink_priv_{[priv_names[priv]]}.svg"))
# %%
priv_stats = pd.DataFrame()
for exec_trace in exec_traces:

    average_u_in_trace = 0
    average_s_in_trace = 0
    average_m_in_trace = 0
    n_instrs = 0
    for instr in exec_trace:
        if instr["priv"] == 0:
            average_u_in_trace += 1
        elif instr["priv"] == 1:
            average_s_in_trace += 1
        elif instr["priv"] == 3:
            average_m_in_trace += 1
        n_instrs += 1

    average_u = average_u_in_trace/n_instrs*100
    average_s = average_s_in_trace/n_instrs*100
    average_m = average_m_in_trace/n_instrs*100
    d = {
        "average_u": average_u,
        "average_s": average_s,
        "average_m":average_m,
        "taint_source_privs":exec_trace[0]["taint_source_privs"][0]
    }
    priv_stats = pd.concat([priv_stats,pd.DataFrame([d])])

# %%
palette = ['r', 'g', 'b', 'c', 'y', 'm', 'k']
patterns = [ "/" , "*", "o", ".", "+","0"]
w = 0.5
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)


for i,priv in enumerate(set(priv_stats["taint_source_privs"])):
    average_u = np.mean(priv_stats[priv_stats["taint_source_privs"] == priv]["average_u"])
    average_s = np.mean(priv_stats[priv_stats["taint_source_privs"]  == priv]["average_s"])
    average_m = np.mean(priv_stats[priv_stats["taint_source_privs"]  == priv]["average_m"])
    ax.bar(i, average_u,color="b", hatch=patterns[0], width=w, bottom=0, label="U-mode" if i == 0 else None)
    ax.bar(i, average_s,color="r", bottom=average_u,hatch=patterns[1], width=w, label = "S-mode" if i == 0 else None)
    ax.bar(i, average_m,color="white", bottom=average_u+average_s, width=w, label="M-mode" if i == 0 else None)
    ax.text(i-w/4, average_u+average_s+0.5, '{0:.1f}%'.format(average_u+average_s),fontsize=LEGENDSIZE)

ax.set_xticks([0,1,2],labels=["U-Mode","S-Mode","M-Mode"],fontsize=TICKSIZE)
ax.set_yticks([0,15,30,45],labels=[0,15,30,45],fontsize=TICKSIZE)
ax.set_ylim(0,45)
ax.set_xlabel("Taint-source privilege", fontsize=LABELSIZE)
ax.set_ylabel("Execution in privilege [%]", fontsize=LABELSIZE)
ax.grid(axis="y")
ax.legend(fontsize=LEGENDSIZE)
# plt.savefig(os.path.join(EXEC_PLOTS_PATH, "priv_stat.svg"))
#%%
###
## TAINT OVERAPPROX STATS
###
MILESAN_DATADIR = "/mnt/milesan-data/kronos/"
traces = pd.DataFrame()
for i,file in enumerate(glob.glob(MILESAN_DATADIR+ "**/*writeback.txt", recursive=True)):
    with open(file, "r") as f:
        writeback = f.read()
    id = file.split("/")[-2]
    acc = 0
    for idx, line in enumerate(writeback.split("\n")):
        if len(line) == 0:
            continue
        rtl = int(line.split(",")[-1].strip(),16)
        insitu = int(line.split(",")[-2].strip(),16)
        mismatch = ((rtl^insitu)&0xFFFFFFFF).bit_count()/(32 if "kronos" in file else 64)*100
        acc += mismatch
        assert insitu>=rtl
        d = {
            "id":id,
            "rtl": rtl,
            "insitu": insitu,
            "mismatch": mismatch,
            "acc": acc,
            "idx": idx
        }
        traces = pd.concat([traces,pd.DataFrame([d])])

#%%
fig, (ax_t,ax_b) = plt.subplots(figsize=FIGSIZE_FLAT, nrows=2, ncols=1)
mean = np.mean(traces["mismatch"])
median = np.median(traces["mismatch"])
for ax in [ax_b, ax_t]:
    sns.histplot(traces,x='mismatch', ax=ax,stat="percent",color="black",binwidth=5)
    ax.axvline(x=mean, label="Mean ({0:.1f}%)".format(mean),color="r")
    ax.axvline(x=median, label="Median ({0:.1f}%)".format(median))
ax_b.set_ylim(0,5)
ax_b.set_yticks([0,2.5,5])
ax_b.set_yticklabels([0,2.5,5], fontsize=TICKSIZE)
ax_b.set_xlim(0,100)
ax_b.grid(axis="y")

ax_t.set_ylim(50,100)
# ax_t.set_yticklabel
ax_t.set_xticks([])
ax_t.set_xlim(0,100)
ax_t.set_xlabel("")
ax_t.set_yticks([50,75,100])
ax_t.set_yticklabels([50,75,100], fontsize=TICKSIZE)
ax_t.grid(axis="y")
ax_t.set_ylabel("Test cases [%]", fontsize=LABELSIZE)
ax_b.set_ylabel("")
# ax.grid(axis="y")
# ax.set_yticks([0.5,1])
ax_b.set_xticks([0,20,40,60,80,100],labels=[0,20,40,60,80,100],fontsize=TICKSIZE)
ax_t.spines["bottom"].set_visible(False)
ax_b.spines["top"].set_visible(False)
ax_b.set_xlabel("In-situ taint over-approximation [%]", fontsize=LABELSIZE)
ax_t.legend(fontsize=LEGENDSIZE)
# plt.savefig(os.path.join(EXEC_PLOTS_PATH, "taint_overapprox.svg"))

# %%
