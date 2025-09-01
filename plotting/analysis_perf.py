#%%
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from seaborn.objects import Stack
import json
import glob
import pandas as pd
import pickle
import os
import sys
sys.path.append("/mnt/milesan-meta/plotting")
from cfg import *
#%%
def get_perf_df(basedir = BASEDIR, use_cached: bool = False):
    if(use_cached):
        with open(basedir + PERF_PICKLE_PATH,"rb") as f:
            return pickle.load(f)

    perf_df = pd.DataFrame()
    for file in glob.glob(basedir + PERF_PATH+ "**/perfstats.json", recursive=True):
        with open(file, "r") as f:
            perf_df = pd.concat([perf_df,
                pd.DataFrame([
                    json.load(f)
                ])
            ])
        

    perf_df["throughput"] = perf_df["n_instrs"]/perf_df["t_total"]
    return perf_df

#%%
def compute_perf_means(perf_df):
    PERF_T =  ["t_gen_bbs", "t_spike_resol","t_gen_elf","t_rtl"]
    perf_means = pd.DataFrame()
    for dut in set(perf_df["dut"]):
            where = (perf_df["dut"] == dut)
            t_gen_bbs = np.mean(perf_df[where]["t_gen_bbs"])
            # t_spike_resol = np.mean(perf_df[where]["t_spike_resol"])
            t_gen_elf = np.mean(perf_df[where]["t_gen_elf"])
            t_rtl = np.mean(perf_df[where]["t_rtl"])
            t_sum = t_gen_bbs + t_gen_elf + t_rtl
            perf_means = pd.concat([
                perf_means,
                pd.DataFrame([
                    {
                    "dut": dut,
                    "t_gen_bbs": t_gen_bbs,
                    # "t_spike_resol":t_spike_resol,
                    "t_gen_elf":t_gen_elf,
                    "t_rtl": t_rtl,
                    "t_sum": t_sum,
                    }
                ])
            ])
    return perf_means
# %%
def plot_proggen(perf_means):
    palette = ['royalblue', 'mediumorchid', 'lightcoral', 'm', 'k']
    patterns = [ "//" , "--", "", ".", "+","0"]
    duts = ["kronos","rocket","cva6","boom","openc910"]
    pretty_names = ["Kronos","Rocket","CVA6","BOOM","OpenC910"]
    pretty_names_t = ["Program Generation","ELF Compilation","RTL Simulation"]
    perf_t = ["t_gen_bbs","t_gen_elf","t_rtl"]
    w = 0.6
    fig, ax = plt.subplots(figsize=(6,2))
    for i,dut in enumerate(duts):
        bottom = 0
        t_sum =  perf_means[perf_means["dut"] == dut]["t_sum"].values[0]
        for j,t in enumerate(perf_t):
            r =  perf_means[perf_means["dut"] == dut][t].values[0]/t_sum*100
            ax.bar(i,r,color=palette[j], hatch=patterns[j], width=w, bottom=bottom, label= None if i != 0 else pretty_names_t[j])
            bottom += r
            # if t == perf_t[-2]:
            #     ax.text(i-w/4, bottom+0.5, '{0:.1f}%'.format(bottom),size=LEGENDSIZE)

    ax.set_xticks(np.arange(5),labels=pretty_names,fontsize=TICKSIZE)
    ax.set_yticks([0,25,50,75,100],labels=[0,25,50,75,100],fontsize=TICKSIZE)
    ax.set_ylim([0,100])
    ax.set_ylabel("Time per step [%]", fontsize=LABELSIZE)

    ax.grid(axis="y")
    ax.legend(fontsize=LEGENDSIZE)
    print(f"Saving plot to {PLOT_PATH}/proggen.png")
    plt.savefig(f"{PLOT_PATH}/proggen.png")


#%%
def plot_throughput(perf_df):
    duts = ["kronos","rocket","cva6","boom","openc910"]
    pretty_names = ["Kronos","Rocket","CVA6","Boom","OpenC910"]
    colors = ["red","peru","greenyellow","forestgreen","black"]
    fig, ax = plt.subplots(figsize=(6,2))
    for i,dut in enumerate(duts):
        sns.scatterplot(perf_df[perf_df["dut"] == dut],x='n_instrs',y='throughput', ax=ax,label=PRETTY_NAMES_DUT[dut],color=colors[i])
    # ax.legend(pretty_names)
    ax.set_yscale("log")
    ax.set_xlim([0,16000])
    ax.set_ylim([0,10**3])
    ax.set_xticklabels([f"{i//1000}k" for i in range(0,16000,1000)],fontsize=TICKSIZE)
    ax.set_ylabel("Throughput [#instr/s]",fontsize=LABELSIZE)
    ax.set_xlabel("#instr",fontsize=LABELSIZE)
    ax.legend(fontsize=LEGENDSIZE)
    ax.yaxis.set_tick_params(labelsize=TICKSIZE)
    print(f"Saving plot to {PLOT_PATH}/throughput.png")
    plt.savefig(f"{PLOT_PATH}/throughput.png")

#%%
if __name__ == "__main__":
    perf_df = get_perf_df(use_cached = "--cached" in sys.argv)
    perf_means = compute_perf_means(perf_df)
    plot_proggen(perf_means)
    plot_throughput(perf_df)


# %%
