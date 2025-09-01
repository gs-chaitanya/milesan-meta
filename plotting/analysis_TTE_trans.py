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
import sys
sys.path.append("/mnt/milesan-meta/plotting")
from cfg import *
# %% leakage identification
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

def leakage_type(x):
    return "cross-privilege" if x["cross-priv"] else "intra-privilege"

def get_perfstats(basedir = BASEDIR, n_runs = 50):
    perfstats = pd.DataFrame()
    for i,file in enumerate(glob.glob(basedir+ "/**/perfstats.json", recursive=True)):
        if "to" not in file:
            continue
        with open(file, "r") as f:
            p = json.load(f)
        context = re.findall("[SUM]_to_[SUM]",file)[0]
        p["taint_source_priv"] = context[0]
        p["taint_sink_priv"] = context[-1]
        p["context"] = context
        perfstats = pd.concat([perfstats, pd.DataFrame([p])])

    # bin the collected seeds into random sets.
    perfstats["run"] = perfstats["seed"]%n_runs
    # compute the accumulated core hours within the respective sets.
    perfstats["t_acc"] = perfstats.apply( \
            lambda row: \
                perfstats[ \
                    (perfstats['seed'] <= row['seed']) & \
                (perfstats["run"] == row["run"])  & \
                    (perfstats["dut"] == row["dut"])  & \
                    (perfstats["context"] == row["context"])  \
                    ] \
                    ['t_total'].sum(), axis=1)
    # compute the core hours from the core seconds.
    perfstats['t_acc_h'] = perfstats['t_acc'] / 3600
    return perfstats

def get_reducelogs(basedir = BASEDIR):
    reduce_log = pd.DataFrame()
    for i,file in enumerate(glob.glob(basedir+ "/**/reducelog.json", recursive=True)):
        if "to" not in file: # only checking the [SUM]_to_[SUM]
            # print(f"Skipping {file}")
            continue
        with open(file, "r") as f:
            p = json.load(f)
        context = re.findall("[SUM]_to_[SUM]",file)[0]
        p["taint_source_priv"] = context[0]
        p["taint_sink_priv"] = context[-1]
        p["context"] = context
        reduce_log = pd.concat([reduce_log, pd.DataFrame([p])])
    return reduce_log

def merge_perf_and_reduce(perfstats, reduce_log):
    def leaker_identifier_f(row):
        cross_priv = row["cross-priv"]
        leaker = row["failing_instr"]
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
            if row["dut"] == "pt-boom" and row["id"] not in merged[merged["dut"] == "boom"]["id"]:
                return "MDS*"
            return "Meltdown"
        elif is_load(leaker):
            if cross_priv:
                return "cp-Spectre-V4"
            else:
                return "Spectre-V4"
    merged = pd.merge(reduce_log, perfstats,on = ["id","context"],how="left")
    for col in merged.columns:
        if col.endswith("_x"):
            if set(merged[col] == merged[col[:-2]+"_y"]) == {True}:
                merged[col[:-2]] = merged[col]
    
    merged["vuln"] = merged.apply(leaker_identifier_f, axis=1)
    return merged

def get_ttes(basedir = BASEDIR, use_cached: bool = False, n_runs = N_RUNS):
    if use_cached:
        with open(basedir+TRANS_TTES_PICKLE_PATH,"rb") as f:
            return pickle.load(f)

    perfstats = get_perfstats(basedir,n_runs)
    reduce_log = get_reducelogs(basedir)
    merged = merge_perf_and_reduce(perfstats, reduce_log)

    # merge meta info from reduction log into performance stats.
    ttes = pd.DataFrame()
    for vuln in set(merged["vuln"]):
        for run in range(0,n_runs):
            for dut in set(merged["dut"]):
                    for taint_source_priv in set(merged["taint_source_priv"]):
                        for leaker_priv in set(merged["leaker-priv"]):
                            for cross_priv in [True,False]:
                                t = merged[
                                    (merged["vuln"] == vuln) &  \
                                    (merged["run"] == run) & \
                                    (merged["dut"] == dut) & \
                                    (merged["taint_source_priv"] == taint_source_priv) & \
                                    (merged["leaker-priv"] == leaker_priv) & \
                                    (merged["cross-priv"] == cross_priv) \
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
                                            "leaker-priv": leaker_priv,
                                            "id" : id.values[0],
                                            "cross-priv": cross_priv
                                        }
                                        ]
                                    )
                                ])
    ttes['tte_h'] = ttes['tte'] / 3600
    ttes['tte_m'] = ttes['tte'] / 60
    return ttes


def s_to_cpuh(s):
    return f"{int(s//3600)}h{int((s%3600)//60)}m"
def compute_min_tte(x):
    return  min(x["tte"])

def compute_median_tte(x):
    return np.median(x["tte"])

def compute_mean_tte(x):
    return np.mean(x["tte"])

def compute_stddev_tte(x):
    return np.std(x["tte"])

def compute_min_tte(x):
    return np.std(x["tte"])

def compute_specdoc_mean_speedup(x):
    if x["vuln"] in TTE_SPECDOC.keys():
        return TTE_SPECDOC[x["vuln"]]/x["mean"]
def compute_specdoc_max_speedup(x):
    if x["vuln"] in TTE_SPECDOC.keys():
        return TTE_SPECDOC[x["vuln"]]/x["min"]
    
def get_tables(ttes):
    medians = ttes.groupby(["dut", "vuln"]).apply(compute_median_tte)
    means = ttes.groupby(["dut", "vuln"]).apply(compute_mean_tte)
    stds = ttes.groupby(["dut", "vuln"]).apply(compute_stddev_tte)
    mins = ttes.groupby(["dut", "vuln"]).apply(compute_min_tte)

    medians_df = pd.DataFrame(medians.reset_index())
    medians_df = medians_df.rename({0:"median"},axis=1)
    means_df = pd.DataFrame(means.reset_index())
    means_df = means_df.rename({0:"mean"},axis=1)
    stds_df = pd.DataFrame(stds.reset_index())
    stds_df = stds_df.rename({0:"stddev"},axis=1)
    mins_df = pd.DataFrame(mins.reset_index())
    mins_df = mins_df.rename({0:"min"},axis=1)
    table_data = pd.merge(medians_df,means_df,on=["vuln","dut"])
    table_data = pd.merge(table_data, stds_df, on = ["vuln","dut"])
    table_data = pd.merge(table_data, mins_df, on = ["vuln","dut"])
    table_data["mean_cpuh"] = table_data["mean"].apply(s_to_cpuh)
    table_data["median_cpuh"] = table_data["median"].apply(s_to_cpuh)
    table_data["stddev_cpuh"] = table_data["stddev"].apply(s_to_cpuh)
    table_data["min_cpuh"] = table_data["min"].apply(s_to_cpuh)

    table_data_boom = table_data[(table_data["dut"] == "boom") | (table_data["dut"] == "pt-boom") & (table_data["vuln"] == "MDS*")]
    table_data_boom = table_data_boom[table_data_boom["vuln"] != "Spectre-V4"]
    table_data_boom["pretty_name_dut"] = "BOOM"

    # Define the custom order for the "vuln" column
    vuln_order = [
        "Spectre-V1", 
        "Spectre-V2", 
        "Spectre-RSB", 
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
    return table_data_boom

def plot_ttes(ttes):
    ttes["leakage-type"] = ttes.apply(leakage_type,axis=1)
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
    plt.savefig(PLOT_PATH+"/tte_transient.png")

#%%
if __name__ == "__main__":
    ttes = get_ttes(basedir = BASEDIR, use_cached="--cached" in sys.argv)
    plot_ttes(ttes)
    table_data_boom = get_tables(ttes)
    table_data_boom.to_csv(TABLE_PATH + "/tte_transient.csv")


# %%
