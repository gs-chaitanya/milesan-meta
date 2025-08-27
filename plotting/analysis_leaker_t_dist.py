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
FIGSIZE_RECTANGLE = (8,4)
FIGSIZE_QUADRATIC = (8,8)
LABELSIZE = 15
TICKSIZE = 12
LEGENDSIZE = 12
PRETTY_DUT_NAMES_DICT = {
    "openc910":"OpenC910",
    "boom":"BOOM",
    "rocket":"Rocket",
    "cva6":"CVA6",
    "kronos":"Kronos"
}
TAINT_MISMATCH_PATH = "/mnt/milesan-data/PERF/"
PERFORMANCE_PLOTS_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/performance"
#%%
perf_df = pd.DataFrame()
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/perfstats.json", recursive=True):
    with open(file, "r") as f:
        perf_df = pd.concat([perf_df,
            pd.DataFrame([
                json.load(f)
            ])
        ])
    

perf_df["throughput"] = perf_df["n_instrs"]/perf_df["t_total"]
#%%
PERF_T =  ["t_gen_bbs", "t_spike_resol","t_gen_elf","t_rtl"]
perf_means = pd.DataFrame()
for dut in set(perf_df["dut"]):
    for i in range(3):
        where = (perf_df["dut"] == dut) & (perf_df["n_instrs"] < 10**(i+1))  & (perf_df["n_instrs"] > 10**i)
        t_gen_bbs = np.mean(perf_df[where]["t_gen_bbs"])
        t_spike_resol = np.mean(perf_df[where]["t_spike_resol"])
        t_gen_elf = np.mean(perf_df[where]["t_gen_elf"])
        t_rtl = np.mean(perf_df[where]["t_rtl"])
        t_sum = t_gen_bbs + t_spike_resol + t_gen_elf + t_rtl
        perf_means = pd.concat([
            perf_means,
            pd.DataFrame([
                {
                "dut": dut,
                "t_gen_bbs": t_gen_bbs,
                "t_spike_resol":t_spike_resol,
                "t_gen_elf":t_gen_elf,
                "t_rtl": t_rtl,
                "t_sum": t_sum,
                }
            ])
        ])

# %%
palette = ['r', 'g', 'b', 'c', 'y', 'm', 'k']
patterns = [ "/" , "*", "o", ".", "+","0"]
duts = ["kronos","rocket","cva6","boom","openc910"]
pretty_names = ["Kronos","Rocket","CVA6","Boom","OpenC910"]
pretty_names_t = ["Program Generation","ELF Compilation", "Spike","RTL Simulation"]
perf_t = ["t_gen_bbs","t_gen_elf","t_spike_resol","t_rtl"]
w = 0.6
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    bottom = 0
    t_sum =  perf_means[perf_means["dut"] == dut]["t_sum"].values[0]
    for j,t in enumerate(perf_t):
        r =  perf_means[perf_means["dut"] == dut][t].values[0]/t_sum*100
        ax.bar(i,r,color=palette[j], hatch=patterns[j], width=w, bottom=bottom, label= None if i != 0 else pretty_names_t[j])
        bottom += r
        if t == perf_t[-2]:
            ax.text(i-w/4, bottom+0.5, '{0:.1f}%'.format(bottom),size=LEGENDSIZE)

ax.set_xticks(np.arange(5),labels=pretty_names,fontsize=TICKSIZE)
ax.set_yticks([0,25,50,75,100],labels=[0,25,50,75,100],fontsize=TICKSIZE)
ax.set_ylim([0,100])
ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Time per step [%]", fontsize=LABELSIZE)

ax.grid(axis="y")
ax.legend(fontsize=LEGENDSIZE)
# plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"timesplot.svg"))
# %%
# fig, axs = plt.subplots(2,2,figsize=(10,5))
# for i,(ax,t) in enumerate(zip(axs.flatten(), PERF_T)):
#     sns.histplot(perf_df, x=t, hue='dut' if t=="t_rtl" else None,ax=ax)

# plt.tight_layout()    
# # %%
# fig, axs = plt.subplots(2)
# for i,(ax,t) in enumerate(zip(axs.flatten(), ["n_instrs","n_bbs"])):
#     sns.histplot(perf_df, x=t, ax=ax)

# axs[0].set_xlabel("#instructions")
# axs[1].set_xlabel("#BBs")
# plt.tight_layout()    


#%%
duts = ["kronos","rocket","cva6","boom","openc910"]
pretty_names = ["Kronos","Rocket","CVA6","Boom","OpenC910"]
pretty_names_t = ["Program Generation","ELF Compilation", "Spike Validation"]
w = 0.6
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    total_time = perf_means[perf_means["dut"] == dut]["t_sum"].values[0]
    ax.bar(i, total_time,color="black", width=w)
    t = f"{total_time//60:.0f}m{total_time%60:.0f}s"
    ax.text(i-w/2+0.08, total_time+0.5, t ,size=LEGENDSIZE)

ax.set_xticks(np.arange(5),labels=pretty_names,fontsize=TICKSIZE)
ax.set_yticks([0,60,120,180,240],labels=[0,1,2,3,4],fontsize=TICKSIZE)

ax.set_xlabel("DUT", fontsize=LABELSIZE)
ax.set_ylabel("Total runtime [min]", fontsize=LABELSIZE)

ax.grid(axis="y")
# plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"total_time.svg"))
# ax.legend()
# %%
#%%
#%%
PERF_T =  ["t_gen_bbs", "t_spike_resol","t_gen_elf","t_rtl"]
perf_means = pd.DataFrame()
for dut in set(perf_df["dut"]):
    for i in range(2,5):
        where = (perf_df["dut"] == dut) & (perf_df["n_instrs"] < 10**(i+1))  & (perf_df["n_instrs"] > 10**i)
        t_gen_bbs = np.mean(perf_df[where]["t_gen_bbs"])
        throughput = np.mean(perf_df[where]["throughput"])
        t_spike_resol = np.mean(perf_df[where]["t_spike_resol"])
        t_gen_elf = np.mean(perf_df[where]["t_gen_elf"])
        t_rtl = np.mean(perf_df[where]["t_rtl"])
        t_sum = t_gen_bbs + t_spike_resol + t_gen_elf + t_rtl
        perf_means = pd.concat([
            perf_means,
            pd.DataFrame([
                {
                "dut": dut,
                "t_gen_bbs": t_gen_bbs,
                "t_spike_resol":t_spike_resol,
                "t_gen_elf":t_gen_elf,
                "t_rtl": t_rtl,
                "t_sum": t_sum,
                "min_n_instr": 10**i,
                "throughput": throughput
                }
            ])
        ])

#%%
duts = ["kronos","rocket","cva6","boom","openc910"]
pretty_names = ["Kronos","Rocket","CVA6","Boom","OpenC910"]
colors = ["red","peru","greenyellow","forestgreen","black"]
n_instrs_list = list(set(perf_means["min_n_instr"]))
n_instrs_list.sort()
w = 1
x_ticks = []
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    for j,n_instrs in enumerate(n_instrs_list):
        where = (perf_means["dut"] == dut) & (perf_means["min_n_instr"] == n_instrs)
        total_time = perf_means[where]["t_sum"].values[0]
        ax.bar(i*w+j*len(duts)*4, total_time,color=colors[i], width=w, label=pretty_names[i] if j == 0 else None)
        if i == len(duts)//2:
            x_ticks += [i+j*len(duts)*4]
        # t = f"{total_time//60:.0f}m{total_time%60:.0f}s"
        # ax.text(i-w/2+0.08, total_time+0.5, t ,size=LEGENDSIZE)

# ax.set_yticks([60,60*5,60*10,60*15],[1,5,10,15])
ax.set_yscale("log")
ax.set_ylim([1,10**3])
ax.set_xticks(x_ticks,labels=n_instrs_list,fontsize=TICKSIZE)

ax.set_xlabel("Program size [#instructions]", fontsize=LABELSIZE)
ax.set_ylabel("Total runtime [s]", fontsize=LABELSIZE)

ax.grid(axis="y")
ax.legend()
# plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"total_time_ninstrs.svg"))
#%%
#%%
duts = ["kronos","rocket","cva6","boom","openc910"]
pretty_names = ["Kronos","Rocket","CVA6","Boom","OpenC910"]
colors = ["red","peru","greenyellow","forestgreen","black"]
n_instrs_list = list(set(perf_means["min_n_instr"]))
n_instrs_list.sort()
w = 1
x_ticks = []
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    for j,n_instrs in enumerate(n_instrs_list):
        where = (perf_means["dut"] == dut) & (perf_means["min_n_instr"] == n_instrs)
        # total_time = perf_means[where]["t_sum"].values[0]
        throughput =  perf_means[where]["throughput"].values[0]
        ax.bar(i*w+j*len(duts)*4, throughput,color=colors[i], width=w, label=pretty_names[i] if j == 0 else None)
        if i == len(duts)//2:
            x_ticks += [i+j*len(duts)*4]
        # t = f"{total_time//60:.0f}m{total_time%60:.0f}s"
        # ax.text(i-w/2+0.08, total_time+0.5, t ,size=LEGENDSIZE)

# ax.set_yticks([60,60*5,60*10,60*15],[1,5,10,15])
ax.set_yscale("log")
ax.set_ylim([1,10**3])
ax.set_xticks(x_ticks,labels=n_instrs_list,fontsize=TICKSIZE)

ax.set_xlabel("Program size [#instructions]", fontsize=LABELSIZE)
ax.set_ylabel("Throughput [#instructions/s]", fontsize=LABELSIZE)

ax.grid(axis="y")
ax.legend()
# plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"total_time_ninstrs.svg"))
# %%
#%%
## NOT USED ## 
duts = ["kronos","rocket","cva6","boom","openc910"]
pretty_names = ["Kronos","Rocket","CVA6","Boom","OpenC910"]
perf_t = ["t_gen_bbs","t_gen_elf","t_spike_resol","t_rtl"]
pretty_names_t = ["Program Generation","ELF Compilation", "Spike","RTL Simulation"]
palette = ["red","peru","greenyellow","forestgreen","black"]
patterns = [ "/" , "*", "o", ".", "+","0"]
n_instrs_list = list(set(perf_means["min_n_instr"]))
n_instrs_list.sort()
w = 2
x_ticks = []
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    for j,n_instrs in enumerate(n_instrs_list):
        where = (perf_means["dut"] == dut) & (perf_means["min_n_instr"] == n_instrs)
        total_time = perf_means[where]["t_sum"].values[0]
        non_rtl = total_time -  perf_means[where]["t_rtl"].values[0]
        bottom = 0
        ax.bar(i+j*len(duts)*4, non_rtl/total_time,color=palette[i], width=w, bottom=bottom, label=pretty_names_t[j])

            # if t == perf_t[-2]:
            #     ax.text(i-w/4, bottom+0.5, '{0:.1f}%'.format(bottom),size=LEGENDSIZE)

        if i == len(duts)//2:
            x_ticks += [i+j*len(duts)*4]
        # t = f"{total_time//60:.0f}m{total_time%60:.0f}s"
        # ax.text(i-w/2+0.08, total_time+0.5, t ,size=LEGENDSIZE)

# ax.set_yticks([60,60*5,60*10,60*15],[1,5,10,15])
# ax.set_yscale("log")
# ax.set_ylim([0,100])
ax.set_xticks(x_ticks,labels=n_instrs_list,fontsize=TICKSIZE)

ax.set_xlabel("Program size [#instructions]", fontsize=LABELSIZE)
# ax.set_ylabel("Total runtime [s]", fontsize=LABELSIZE)

ax.grid(axis="y")
# plt.savefig(os.path.join(PERFORMANCE_PLOTS_PATH,"total_time_ninstrs.svg"))
ax.legend()
#%%
def load_reduce_perf():
    PERFORMANCE_PLOTS_PATH = "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots/performance"
    sys.path.append("/mnt/milesan-meta/fuzzer")
    from milesan.util import INSTRUCTIONS_BY_ISA_CLASS
    from milesan.util import ISAInstrClass
    perf_df = pd.DataFrame()
    new_entry = {}
    paths = glob.glob( "/mnt/milesan-data/REDUCE_PERF*/" + "**/*.reduce.log", recursive=True)
    paths += glob.glob( "/mnt/milesan-data/CT-VIOLATIONS/"+ "**/*.reduce.log", recursive=True)
    for file in paths:
        dut = file.split("/")[-1].split(".")[0]
        with open(file, "r") as f:
            for line in f.read().split("\n"):
                if "seed" in line:
                    if len(new_entry):

                        new_entry["success_find_pillar_instr"] = new_entry["pillar_instr"] > 0
                        if "leaker_t" in new_entry and new_entry["n_instrs_before_leaker"] > 0 and new_entry["success_find_pillar_bb"] and new_entry["success_find_pillar_instr"]:
                            perf_df = pd.concat([perf_df, pd.DataFrame([new_entry])])
                    new_entry = {}
                    new_entry["seed"] = int(line.split(":")[0].split(" ")[-1])
                    new_entry["id"] = line.split(":")[1].strip(" ")
                    new_entry["dut"] = dut
                    new_entry["n_bbs"] = int(new_entry["id"].split("_")[-1])
                if "Time to find failing BB" in line:
                    new_entry["failing_bb"]=float(line.split(":")[-1].strip()[:-1])
                elif "Time to find failing instr" in line:
                    new_entry["failing_instr"]=float(line.split(":")[-1].strip()[:-1])
                elif "Time to find pillar BB" in line:
                    new_entry["pillar_bb"]=float(line.split(":")[-1].strip()[:-1])
                elif "Time to find pillar instr" in line:
                    new_entry["pillar_instr"]=float(line.split(":")[-1].strip()[:-1])
                elif "Time to nopize instr" in line:
                    new_entry["nopize"]=float(line.split(":")[-1].strip()[:-1])   
                elif "Success nopize instr" in line:
                    new_entry["success_nopize"]= line.split(":")[-1].strip() == "True"
                elif "Time to reduce taint" in line:
                    new_entry["taint"]=float(line.split(":")[-1].strip()[:-1])
                elif "Time to reduce dead code" in line:
                    new_entry["dead_code"]=float(line.split(":")[-1].strip()[:-1])
                elif "Success find pillar BB" in line:
                    new_entry["success_find_pillar_bb"]= line.split(":")[-1].strip() == "True"
                elif "Success find pillar instr" in line:
                    new_entry["success_find_pillar_instr"]= line.split(":")[-1].strip() == "True"
                elif "Taint reduction success" in line:
                    new_entry["success_reduce_taint"]= line.split(":")[-1].strip() == "True"
                elif "Dead code reduction success" in line:
                    new_entry["success_reduce_dead_code"]= line.split(":")[-1].strip() == "True"
                elif "Total number of non-nop instructions" in line:
                    new_entry["n_instrs_before_leaker"] = int(line.split(":")[-1].split("(")[0].strip())
                elif "Failing bb id" in line:
                    new_entry["failing_bb_id"] = int(line.split(":")[-1].split("/")[0])
                elif "Failing instr" in line:
                    new_entry["leaker"] = line.split(":")[-1].strip().split(" ")[0]
                    for isa_class, instrs in INSTRUCTIONS_BY_ISA_CLASS.items():
                        if  new_entry["leaker"] in instrs:
                            new_entry["leaker_t"] = "cf" if isa_class.name in ["JAL","BRANCH","JALR","SPECIAL"] or "Exception" in line else "memop" if isa_class.name in ["MEM","MEM64"] else "ct-violation"

    return perf_df
#%%
BINWIDTH = 1000
duts = ["kronos","rocket","cva6","boom","openc910"]
pretty_names = ["Kronos","Rocket","CVA6","Boom","OpenC910"]
colors = ["red","peru","greenyellow","forestgreen","black"]
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
for i,dut in enumerate(duts):
    sns.scatterplot(perf_df[perf_df["dut"] == dut],x='n_instrs',y='throughput', ax=ax,label=PRETTY_DUT_NAMES_DICT[dut],color=colors[i])
# ax.legend(pretty_names)
ax.set_yscale("log")
ax.set_xlim([0,16000])
ax.set_ylim([0,10**3])
ax.set_xticklabels([f"{i//1000}k" for i in range(0,16000,1000)],fontsize=TICKSIZE)
ax.set_ylabel("throughput [#instr/s]",fontsize=LABELSIZE)
ax.set_xlabel("#instr",fontsize=LABELSIZE)
ax.legend(fontsize=LEGENDSIZE)
ax.yaxis.set_tick_params(labelsize=TICKSIZE)
# ax2 = ax.twinx()
# ax2.set_ylim([0,0.00015])
# ax2.set_yticks([0,0.00005,0.0001,0.00015])
# ax2.set_yticklabels(["0","5e-3","1e-2","1.5e-2"])
# ax2.set_ylabel("Kernel Density [%]",fontsize=LABELSIZE)
# ax2.set_yticklabels([i*10 for i in range(6)],fontsize=TICKSIZE)
# reduce_perf_df = load_reduce_perf()
# sns.histplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "cf"],x="n_instrs_before_leaker",ax=ax2,kde=True,stat="percent",label = "Control-Flow",binwidth=BINWIDTH)
# sns.histplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "memop"],x="n_instrs_before_leaker",ax=ax2,kde=True,stat="percent",label = "Memory",binwidth=BINWIDTH)
# sns.histplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "ct-violation"],x="n_instrs_before_leaker",ax=ax2,kde=True,stat="percent",label = "Arithmetic",binwidth=BINWIDTH)
# sns.kdeplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "cf"],x="n_instrs_before_leaker",ax=ax2,label = "Control-Flow")
# sns.kdeplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "memop"],x="n_instrs_before_leaker",ax=ax2,label = "Memory")
# sns.kdeplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "ct-violation"],x="n_instrs_before_leaker",ax=ax2,label = "Arithmetic")
# ax2.legend(fontsize=LEGENDSIZE)
plt.savefig(f"{PERFORMANCE_PLOTS_PATH}/throughput.svg")
# %%
BINWIDTH = 1000
fig, ax = plt.subplots(figsize=FIGSIZE_RECTANGLE)
sns.kdeplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "cf"],x="n_instrs_before_leaker",ax=ax,label = "Control-Flow")
sns.kdeplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "memop"],x="n_instrs_before_leaker",ax=ax,label = "Memop")
sns.kdeplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "ct-violation"],x="n_instrs_before_leaker",ax=ax,label = "ct-violation")
ax.set_xlim([0,16000])
ax.legend()
#%%
BINWIDTH = 100
fig, ax = plt.subplots(figsize=FIGSIZE_RECTANGLE)
sns.histplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "cf"],x="failing_bb_id",ax=ax,kde=True,stat="percent",label = "Control-Flow",binwidth=BINWIDTH)
sns.histplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "memop"],x="failing_bb_id",ax=ax,kde=True,stat="percent",label = "Memop",binwidth=BINWIDTH)
sns.histplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "ct-violation"],x="failing_bb_id",ax=ax,kde=True,stat="percent",label = "ct-violation",binwidth=BINWIDTH)
# ax.set_xlim([0,10000])
ax.legend()
#%%
#%%
BINWIDTH = 1000
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT)
ax.set_ylim([0,0.00015])
ax.set_yticks([0,0.00005,0.0001,0.00015])
ax.set_yticklabels(["0","5e-3","1e-2","1.5e-2"])
ax.set_ylabel("Kernel Density [%]",fontsize=LABELSIZE)
# ax2.set_yticklabels([i*10 for i in range(6)],fontsize=TICKSIZE)
reduce_perf_df = load_reduce_perf()
# sns.histplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "cf"],x="n_instrs_before_leaker",ax=ax2,kde=True,stat="percent",label = "Control-Flow",binwidth=BINWIDTH)
# sns.histplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "memop"],x="n_instrs_before_leaker",ax=ax2,kde=True,stat="percent",label = "Memory",binwidth=BINWIDTH)
# sns.histplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "ct-violation"],x="n_instrs_before_leaker",ax=ax2,kde=True,stat="percent",label = "Arithmetic",binwidth=BINWIDTH)
sns.kdeplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "cf"],x="n_instrs_before_leaker",ax=ax,label = "Control-Flow",color="red")
sns.kdeplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "memop"],x="n_instrs_before_leaker",ax=ax,label = "Memory",color="peru")
sns.kdeplot(reduce_perf_df[reduce_perf_df["leaker_t"] == "ct-violation"],x="n_instrs_before_leaker",ax=ax,label = "Arithmetic",color="blue")
ax.legend(fontsize=LEGENDSIZE)
ax.set_xlabel("#instr",fontsize=LABELSIZE)
ax.set_xticklabels([f"{i//1000}k" for i in range(0,16000,1000)],fontsize=TICKSIZE)
ax2 = ax.twinx()

sns.regplot(perf_df,x='n_instrs',y='throughput', ax=ax2,color="grey")
# ax.legend(pretty_names)
ax2.set_yscale("log")
ax2.set_xlim([0,16000])
ax2.set_ylim([0,10**3])
ax2.set_ylabel("throughput [#instr/s]",fontsize=LABELSIZE)
ax2.legend(fontsize=LEGENDSIZE)
ax2.yaxis.set_tick_params(labelsize=TICKSIZE)
# plt.savefig(f"{PERFORMANCE_PLOTS_PATH}/dist_over_program_length.svg")
# %%
sns.boxplot(reduce_perf_df,y="leaker_t",x="n_instrs_before_leaker",hue="dut",saturation=1,showfliers=0)