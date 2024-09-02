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
CASCADE_DATADIR = "/cascade-data/"
EXEC_PLOTS_PATH = "/mnt/cascade-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/exec"
#%%
exec_traces = []
for i,file in enumerate(glob.glob(CASCADE_DATADIR+ "**/taint_stats.json", recursive=True)):
    with open(file, "r") as f:
        try:
            exec_traces += [json.load(f)]
        except Exception as e:
            print(e)


# %%
idx = 1
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
priv = [i["priv"] for i in exec_traces[idx]]
taint = [i["n_tainted_regs_ratio"]*100 for i in exec_traces[idx]]
sns.lineplot(taint,ax=ax,color="black")
ax.fill_between(range(0,len(priv)), 0, 1, where=np.asarray(priv) == 0,
            color='blue', alpha=0.5, transform=ax.get_xaxis_transform(), label="User")

ax.fill_between(range(0,len(priv)), 0, 1, where=np.asarray(priv) == 1,
                color='red', alpha=0.5, transform=ax.get_xaxis_transform(), label="Supervisor")

ax.fill_between(range(0,len(priv)), 0, 1, where=np.asarray(priv) == 3,
            color='grey', alpha=0.1, transform=ax.get_xaxis_transform(), label="Machine")

ax.grid(axis="y")
ax.set_ylim(0,100)
ax.set_yticks([0,25,50,75,100])
ax.set_yticklabels([0,25,50,75,100],fontsize=TICKSIZE)
ax.set_xlim(4000,6000)
ax.set_xticks([4000,4500,5000,5500,6000])
ax.set_xticklabels(["4k","4.5k","5k","5.5k","6k"], fontsize=TICKSIZE)
ax.set_ylabel("Tainted registers [%]",fontsize=LABELSIZE)
ax.set_xlabel("Simulation cycle [1]",fontsize=LABELSIZE)
ax.legend(fontsize=LEGENDSIZE,loc="upper left")
# plt.savefig(os.path.join(EXEC_PLOTS_PATH, "taint_in_regs.svg"))

# %%
ratios = []
for exec_trace in exec_traces:
    average_in_trace = 0
    n_instrs = 0
    for instr in exec_trace:
        if instr["priv"] in instr["taint_in_privs"]:
            average_in_trace += instr["n_tainted_regs_ratio"]*100
            n_instrs += 1

    if n_instrs == 0:
        continue
    ratios += [average_in_trace/n_instrs]
mean = np.mean(ratios)
median = np.median(ratios)

fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
sns.histplot(ratios,ax=ax,stat="probability",binwidth=3,color="black")
ax.axvline(x=mean, label="Mean ratio of tainted registers ({0:.1f}%)".format(mean),color="r")
ax.axvline(x=median, label="Median ratio of tainted registers ({0:.1f}%)".format(median))
ax.set_ylabel("Test cases [%]", fontsize=LABELSIZE)
ax.grid(axis="y")
ax.set_yticks([0.1,0.2])
ax.set_xticks([0,20,40,60,80,100])
ax.set_yticklabels([10,20], fontsize=TICKSIZE)
ax.set_xticklabels([0,20,40,60,80,100],fontsize=TICKSIZE)
ax.set_xlabel("Ratio of tainted registers when executing in a taint-privilege [%]", fontsize=LABELSIZE)
ax.legend(fontsize=LEGENDSIZE,loc="upper left")
# plt.savefig(os.path.join(EXEC_PLOTS_PATH, "taint_in_regs_stat.svg"))
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
ax.axvline(x=mean, label="Mean ratio of instructions with tainted result ({0:.1f}%)".format(mean),color="r")
ax.axvline(x=median, label="Median ratio of instructions with tainted result ({0:.1f}%)".format(median))
ax.set_xlim(0,100)
ax.set_ylabel("Test cases [%]",fontsize=LABELSIZE)
ax.grid(axis="y")
ax.set_yticks([0.1,0.2])
ax.set_yticklabels([10,20], fontsize=TICKSIZE)
ax.set_xticklabels([0,20,40,60,80,100],fontsize=TICKSIZE)
ax.set_xlabel("Ratio of instructions returning tainted results when executing in a taint-privilege [%]", fontsize=LABELSIZE)
ax.legend(fontsize=LEGENDSIZE)
# plt.savefig(os.path.join(EXEC_PLOTS_PATH, "taint_in_comps_stat.svg"))
# %%
# %%
ratios_all_privs = pd.DataFrame()
for exec_trace in exec_traces:
    average_in_trace = 0
    n_instrs = 0
    for instr in exec_trace:
        if instr["priv"] in instr["taint_in_privs"]:
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
        "taint_priv":instr["priv"]
        }
    ])])

priv_names = ["U","S"]
for priv in set([0,1]):
    ratios = ratios_all_privs[ratios_all_privs["taint_priv"] == priv]
    mean = np.mean(ratios["ratio"])
    median = np.median(ratios["ratio"])
    fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
    sns.histplot(ratios,x="ratio", ax=ax,stat="probability",color="black",binwidth=5)
    ax.axvline(x=mean, label=f"Mean of instructions executed in taint-source {priv_names[priv]}-mode " + "({0:.1f}%)".format(mean),color="r")
    ax.axvline(x=median, label=f"Median of instructions executed in taint-source {priv_names[priv]}-mode " + "({0:.1f}%)".format(median))
    ax.set_xlim(0,100)
    ax.set_ylabel("Test cases [%]", fontsize=LABELSIZE)
    ax.grid(axis="y")
    ax.set_yticks([0,0.2,0.4])
    ax.set_yticklabels([0,20,40],fontsize=TICKSIZE)
    ax.set_xticklabels([0,20,40,60,80,100],fontsize=TICKSIZE)
    ax.set_xlabel(f"Ratio of instructions executed in taint-source {priv_names[priv]}-mode [%]",fontsize=LABELSIZE)
    ax.legend()
    plt.savefig(os.path.join(EXEC_PLOTS_PATH, f"comp_in_taint_source_priv_{[priv_names[priv]]}.svg"))

#%%

# %%
ratios_all_privs = pd.DataFrame()
for exec_trace in exec_traces:
    average_in_trace = 0
    n_instrs = 0
    for instr in exec_trace:
        if instr["priv"] != 3 and instr["priv"] not in instr["taint_in_privs"]:
            average_in_trace += 1
        n_instrs += 1

    if n_instrs == 0:
        continue
    ratio = average_in_trace/n_instrs*100
    ratios_all_privs = pd.concat([ratios_all_privs, pd.DataFrame([
        {
        "ratio": ratio,
        "taint_priv":instr["priv"]
        }
    ])])

priv_names = ["U","S"]
for priv in set([0,1]):
    ratios = ratios_all_privs[ratios_all_privs["taint_priv"] == priv]
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
    plt.savefig(os.path.join(EXEC_PLOTS_PATH, f"comp_in_taint_sink_priv_{[priv_names[priv]]}.svg"))

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
        "taint_priv":instr["priv"]
        }
    ])])

priv_names = ["U","S","H","M"]
for priv in set([3]):
    ratios = ratios_all_privs[ratios_all_privs["taint_priv"] == priv]
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
#%%
traces = pd.DataFrame()
for i,file in enumerate(glob.glob(CASCADE_DATADIR+ "**/writeback.txt", recursive=True)):
    with open(file, "r") as f:
        writeback = f.read()
    id = file.split("/")[-2]
    acc = 0
    for idx, line in enumerate(writeback.split("\n")):
        if len(line) == 0:
            continue
        rtl = int(line.split(",")[-1].strip(),16)
        insitu = int(line.split(",")[-2].strip(),16)
        mismatch = ((rtl^insitu)&0xFFFFFFFF).bit_count()/64*100
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
    if i == 20:
        break

#%%
fig, (ax_t,ax_b) = plt.subplots(figsize=FIGSIZE_FLAT, nrows=2, ncols=1)
mean = np.mean(traces["mismatch"])
median = np.median(traces["mismatch"])
for ax in [ax_b, ax_t]:
    sns.histplot(traces,x='mismatch', ax=ax,stat="percent",color="black",binwidth=5)
    ax.axvline(x=mean, label="Mean percentage of over-approximated bits ({0:.1f}%)".format(mean),color="r")
    ax.axvline(x=median, label="Median percentage of over-approximated bits ({0:.1f}%)".format(median))
ax_b.set_ylim(0,1)
ax_b.set_yticks([0,0.5,1])
ax_b.set_yticklabels([0,0.5,1], fontsize=TICKSIZE)
ax_b.grid(axis="y")

ax_t.set_ylim(95,100)
# ax_t.set_yticklabel
ax_t.set_xticks([])
ax_t.set_xlabel("")
ax_t.set_yticks([95,97.5,100])
ax_t.set_yticklabels([95,97.5,100], fontsize=TICKSIZE)
ax_t.grid(axis="y")
ax_t.set_ylabel("Test cases [%]", fontsize=LABELSIZE)
ax_b.set_ylabel("")
# ax.grid(axis="y")
# ax.set_yticks([0.5,1])
ax_t.spines["bottom"].set_visible(False)
ax_b.spines["top"].set_visible(False)
ax_b.set_xlabel("Percentage of over-approximated bits during in-situ simulation [%]", fontsize=LABELSIZE)
ax_t.legend(fontsize=LEGENDSIZE)
plt.savefig(os.path.join(EXEC_PLOTS_PATH, "taint_overapprox.svg"))

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
        "taint_in_priv":exec_trace[0]["taint_in_privs"][0]
    }
    priv_stats = pd.concat([priv_stats,pd.DataFrame([d])])

# %%
palette = ['r', 'g', 'b', 'c', 'y', 'm', 'k']
patterns = [ "/" , "*", "o", ".", "+","0"]
w = 0.5
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)


for i,priv in enumerate(set(priv_stats["taint_in_priv"])):
    average_u = np.mean(priv_stats[priv_stats["taint_in_priv"] == priv]["average_u"])
    average_s = np.mean(priv_stats[priv_stats["taint_in_priv"]  == priv]["average_s"])
    average_m = np.mean(priv_stats[priv_stats["taint_in_priv"]  == priv]["average_m"])
    ax.bar(i, average_u,color="b", hatch=patterns[0], width=w, bottom=0, label="U-mode" if i == 0 else None)
    ax.bar(i, average_s,color="r", bottom=average_u,hatch=patterns[1], width=w, label = "S-mode" if i == 0 else None)
    ax.bar(i, average_m,color="white", bottom=average_u+average_s, width=w, label="M-mode" if i == 0 else None)
    ax.text(i-w/4, average_u+average_s+0.5, '{0:.1f}%'.format(average_u+average_s))

ax.set_xticks([0,1,2],labels=["U-mode","S-mode","M-mode"],fontsize=TICKSIZE)
ax.set_yticks([0,15,30],labels=[0,15,30],fontsize=TICKSIZE)
ax.set_ylim(0,50)
ax.set_xlabel("Taint-source privilege", fontsize=LABELSIZE)
ax.set_ylabel("Execution in privilege [%]", fontsize=LABELSIZE)
ax.grid(axis="y")
ax.legend(fontsize=LEGENDSIZE)
plt.savefig(os.path.join(EXEC_PLOTS_PATH, "priv_stat.svg"))

# %%
