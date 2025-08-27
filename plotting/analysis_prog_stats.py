#%%
import pandas as pd
import glob
import json
import seaborn as sns
import numpy as np
CCS_PATH="/mnt/milesan-data-ccs-rebuttal"
#%%
perfstats = pd.DataFrame()
for i,file in enumerate(glob.glob(CCS_PATH+ "/**/perfstats.json", recursive=True)):
    with open(file, 'r') as f:
        perfstats = pd.concat([perfstats,pd.DataFrame([json.load(f)])])
# %%
perfstats["n_instr_rand"] = perfstats["n_instrs"] - perfstats["n_instr_boot"] - perfstats["n_instr_term"]
#%%
perfstats["p_instr_rand"] = perfstats["n_instr_rand"]/perfstats["n_instrs"]
# %%
perfstats["p_instr_rand"].mean()
# %%
