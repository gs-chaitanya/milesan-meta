#%%
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import json
import glob
import pandas as pd
TAINT_MISMATCH_PATH = "/mnt/milesan-data/MAX_N_INSTRS-PROG-STATS.bk/"
FIGSIZE_FLAT = (8,2)
FIGSIZE_FLAT_WIDE = (24,2)
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
SPECIAL_INSTR = {
    "and (PlaceholderPreConsumerInstr)":"and",
    'addi (PlaceholderProducerInstr1)':"addi",
    'xor (PlaceholderConsumerInstr)':"xor",
    'lui (PlaceholderProducerInstr0)':"lui",
    "EPCWriterInstruction":"csrrw",
    "GenericCSRWriterInstruction":"csrrw",
    "TvecWriterInstruction":"csrrw",
    "ExceptionInstruction":"unimp",
}

INSTRUCTIONS = [
        "lui",
        "auipc",
        "addi",
        "slti",
        "sltiu",
        "xori",
        "ori",
        "andi",
        "slli",
        "srli",
        "srai",
        "add",
        "sub",
        "sll",
        "slt",
        "sltu",
        "xor",
        "srl",
        "sra",
        "or",
        "and",

        "addiw",
        "slliw",
        "srliw",
        "sraiw",
        "addw",
        "subw",
        "sllw",
        "srlw",
        "sraw"

        "mul",
        "mulh",
        "mulhsu",
        "mulhu",
        "div",
        "divu",
        "rem",
        "remu"

        "mulw",
        "divw",
        "divuw",
        "remw",
        "remuw"

        "lr.w",
        "sc.w",
        "amoswap.w",
        "amoadd.w",
        "amoxor.w",
        "amoand.w",
        "amoor.w",
        "amomin.w",
        "amomax.w",
        "amominu.w",
        "amomaxu.w",

        "lr.d",
        "sc.d",
        "amoswap.d",
        "amoadd.d",
        "amoxor.d",
        "amoand.d",
        "amoor.d",
        "amomin.d",
        "amomax.d",
        "amominu.d",
        "amomaxu.d",
        "jal",
        "jalr"
        "beq",
        "bne",
        "blt",
        "bge",
        "bltu",
        "bgeu",
        "lb",
        "lh",
        "lw",
        "lbu",
        "lhu",
        "sb",
        "sh",
        "sw",
        "lwu",
        "ld",
        "sd",
        "flw",
        "fsw",
        "csrrw",
        "csrrs",
        "csrrc",
        "csrrwi",
        "csrrsi",
        "csrrci",
        "fence",
        "fence.i"
]


#%%
acc_dist_per_bound = {}
for file in glob.glob(TAINT_MISMATCH_PATH+ "**/perfstats.json", recursive=True):
    with open(file, "r") as f:
        d = json.load(f)
    d["pretty_name_dut"] = PRETTY_NAMES_DUT[d["dut"]]
    d["n_instrs_upperbound"] = int(file.split("/")[4].split("_")[1])
    acc_dist = {}
    for key,val in d["instr_dist"].items():
        if key not in acc_dist:
            acc_dist[key if key not in SPECIAL_INSTR else SPECIAL_INSTR[key]] = val
        else:
            acc_dist[key if key not in SPECIAL_INSTR else SPECIAL_INSTR[key]] += val
    acc_dist_per_bound[int(file.split("/")[4].split("_")[1])] = acc_dist

#%%
acc_dist_df = pd.DataFrame()
for bound in acc_dist_per_bound.keys():
    s = sum(acc_dist_per_bound[bound].values())
    for key,val in acc_dist_per_bound[bound].items():
        acc_dist_df = pd.concat([
            acc_dist_df,
            pd.DataFrame(
                [
                    {
                        "bound":bound,
                        "instr":key,
                        "p":val/s*100
                    }
                ]
            )
        ])
# %%
palette = ["peru","forestgreen","black"]
fig, ax = plt.subplots(figsize=FIGSIZE_FLAT_WIDE)
instructions = [i for i in INSTRUCTIONS if len(acc_dist_df[acc_dist_df["instr"] == i])]
sns.barplot(acc_dist_df,x="instr",y="p",hue="bound",palette=palette,order=instructions)
ax.set_xticklabels(ax.get_xticklabels(),fontsize=LABELSIZE//2)
# ax.set_yticklabels(ax.get_yticklabels(), fontsize=TICKSIZE)
ax.set_yscale("log")
ax.set_ylabel("Frequency [%]",fontsize=LABELSIZE)
ax.set_xlabel("")
ax.legend(title="Upper bound #instr")
plt.savefig(TTE_PLOTS_PATH+"/upper_bound_instr_dist.svg")
# plt.tick_params(
#     axis='x',          # changes apply to the x-axis
#     which='both',      # both major and minor ticks are affected
#     bottom=False,      # ticks along the bottom edge are off
#     top=False,         # ticks along the top edge are off
#     labelbottom=False) # labels along the bottom edge are off

# %%
