#%%
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import json
import glob
import pandas as pd
import pickle
import sys
sys.path.append("/mnt/milesan-meta/plotting")
from cfg import *

def get_ttes(basedir= BASEDIR, use_cached: bool = False):
    if(use_cached):
        with open(basedir+CT_TTES_PICKLE_PATH,"rb") as f:
            return pickle.load(f)
    seed_to_time = pd.DataFrame()
    for file in glob.glob(basedir + CT_VIOLATIONS_PATH+ "**/perfstats.json", recursive=True):
        with open(file, "r") as f:
            d = json.load(f)
        d["pretty_name_dut"] = PRETTY_NAMES_DUT[d["dut"]]
        d["leaker"] = file.split("/")[4].split("_")[2].lower()
        seed_to_time = pd.concat([seed_to_time,
            pd.DataFrame([
                d
            ])
        ])

    seed_to_reduce = pd.DataFrame()
    for i,file in enumerate(glob.glob(basedir + CT_VIOLATIONS_PATH + "**/reducelog.json", recursive=True)):
        with open(file, "r") as f:
            p = json.load(f)
            p["leaker"] = p["failing_instr"].split(":")[2].strip(" ").split(" ")[0]
        seed_to_reduce = pd.concat([seed_to_reduce, pd.DataFrame([p])])


    seed_data = seed_to_time.merge(seed_to_reduce,on=["id","leaker","seed"])

    N_RUNS = 50

    seed_data["run"] = seed_data["seed"]%N_RUNS

    seed_data = seed_data.sort_values("dut").sort_values(by='seed')  # Sort by 'seed' for proper calculation


    seed_data["t_acc"] = seed_data.apply(
            lambda row: seed_data[(seed_data['seed'] <= row['seed']) & (seed_data["run"] == row["run"])  & (seed_data["dut"] == row["dut"])]['t_total'].sum(), axis=1
        )

    def get_tte(x):
        return min(seed_data[(seed_data["dut"] == x["dut"]) & (seed_data["leaker"] == x["leaker"]) & (seed_data["run"] == x["run"])]["t_acc"])

    seed_data["tte"] = seed_data.apply(get_tte,axis=1)
    seed_data['tte_h'] = seed_data['tte'] / 3600
    seed_data['tte_m'] = seed_data['tte'] / 60
    return seed_data

def plot_cva6(seed_data):
    fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
    sns.violinplot(seed_data[seed_data["dut"] == "cva6"], y="tte_m",x="leaker",saturation=1,order=["div","divu","divw","divuw","rem","remu","remw","remuw"],palette=["b"])
    # ax.set_ylim([0,30])
    # ax.set_yticks([i*5 for i in range(0,7,1)])
    # ax.set_yticklabels([i*5 for i in range(0,7,1)],fontsize=TICKSIZE)
    ax.set_ylabel("TTE [core-m]",fontsize=LABELSIZE)
    ax.set_xlabel("")
    ax.grid()
    ax.set_xticklabels(["div","divu","divw","divuw","rem","remu","remw","remuw"], size=TICKSIZE)
    print(f"Storing tte for cva6 to " + PLOT_PATH + "/tte_ct_violations_cva6.png")
    plt.savefig(PLOT_PATH + "/tte_ct_violations_cva6.png")

def plot_openc910(seed_data):
    fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
    sns.violinplot(seed_data[seed_data["dut"] == "openc910"], y="tte_m",x="leaker",saturation=1,order=["div","divu","divw","divuw","rem","remu","remw","remuw"],palette=["b"])
    # ax.set_ylim([0,60])
    # ax.set_yticks([i*10 for i in range(0,7,1)])
    # ax.set_yticklabels([i*10 for i in range(0,7,1)],fontsize=TICKSIZE)
    ax.set_ylabel("TTE [core-m]",fontsize=LABELSIZE)
    ax.set_xlabel("")
    ax.grid()
    ax.set_xticklabels(["div","divu","divw","divuw","rem","remu","remw","remuw"], size=TICKSIZE)
    print(f"Storing tte for openc910 to " + PLOT_PATH + "/tte_ct_violations_openc910.png")
    plt.savefig(PLOT_PATH + "/tte_ct_violations_openc910.png")

def s_to_cpuh(s):
    return f"{int(s//3600)}h{int((s%3600)//60)}m{int(s%60)}s"


def compute_min_tte(x):
    min_tte = min(x["tte"])
    return s_to_cpuh(min_tte)


def compute_median_tte(x):
    median_tte = np.median(x["tte"])
    return s_to_cpuh(median_tte)


def compute_mean_tte(x):
    mean_tte = np.mean(x["tte"])
    return s_to_cpuh(mean_tte)


def compute_stddev_acc(x):
    stddev = np.std(x["tte"])
    return s_to_cpuh(stddev)

def get_tables(seed_data, basedir = BASEDIR):
    for dut in ["cva6","openc910"]:
        mins = seed_data[seed_data["dut"] == dut].groupby("leaker").apply(compute_min_tte)
        means =  seed_data[seed_data["dut"] == dut].groupby("leaker").apply(compute_mean_tte)
        medians =  seed_data[seed_data["dut"] == dut].groupby("leaker").apply(compute_median_tte)
        stds=  seed_data[seed_data["dut"] == dut].groupby("leaker").apply(compute_stddev_acc)
        table_data = pd.DataFrame()
        table_data["mean"] = means
        table_data["median"] = medians
        table_data["stddev"] = stds
        table_data.reindex(["div","divu","divw","divuw","rem","remu","remw","remuw"])
        table_data.to_csv(TABLE_PATH + f"/tte_ct_{dut}.csv")
        print(f"Storing table for {dut} to " + TABLE_PATH + f"/tte_ct_{dut}.csv")
        print(table_data)


#%%
if __name__ == "__main__":
    ttes = get_ttes(use_cached="--cached" in sys.argv)
    plot_cva6(ttes)
    plot_openc910(ttes)
    get_tables(ttes)

# %%
