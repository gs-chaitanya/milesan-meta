import subprocess
#%%
FIGSIZE_FLAT = (8,2)
FIGSIZE_RECT = (16,6)
LABELSIZE = 15
TICKSIZE = 12
LEGENDSIZE = 12

TTES_PICKLE_PATH = "/mnt/milesan-data-ccs/ttes.pickle"
CCS_PATH = "/mnt/milesan-data-ccs"
CT_VIOLATIONS_PATH = "/mnt/milesan-data-ccs/CT-VIOLATIONS-TTE/"
PERF_PATH = "/mnt/milesan-data/PERF/"
PLOT_PATH = "/mnt/milesan-meta/plotting/plots"
TABLE_PATH = "/mnt/milesan-meta/plotting/tables"
PRETTY_NAMES_DUT = {
    "openc910":"OpenC910",
    "cva6":"CVA6",
    "boom":"BOOM",
    "pt-boom":"BOOM",
    "rocket":"Rocket",
    "kronos":"Kronos"
}
TTE_SPECDOC = {
    "Spectre-V1": 26.9*3600,
    "Spectre-V2": 30.6*3600,
    "Meltdown":34.7*3600,
    "Trans. Meltdown": 26.9*3600 
}
