import os
FIGSIZE_FLAT = (8,2)
FIGSIZE_RECT = (16,6)
LABELSIZE = 15
TICKSIZE = 12
LEGENDSIZE = 12
N_RUNS = 50

BASEDIR = os.getenv("MILESAN_DATADIR")
# BASEDIR = "/mnt/milesan-data-ccs-test"

TRANS_TTES_PICKLE_PATH = "/trans-ttes.pickle"
CT_TTES_PICKLE_PATH = "/ct-ttes.pickle"
PERF_PICKLE_PATH = "/perf.pickle"

CT_VIOLATIONS_PATH = "CT-VIOLATIONS-TTE/"
TRANS_PATH = "TRANS-TTE/"
PERF_PATH =  "PERF/"
REDUCE_PATH =  "REDUCE/"
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
