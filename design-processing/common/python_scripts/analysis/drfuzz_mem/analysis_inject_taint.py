#%%
import matplotlib.pyplot as plt
import json
import pandas as pd
import seaborn as sns
import numpy as np
import numpy as np
import matplotlib.pyplot as plt
import glob
import pandas as pd
import scipy as sp
import seaborn as sns
from multiprocessing import Pool
N_PROC = 10
COV_DUMPS = "/mnt/cov_dump/"    
# COV_DUMPS = "/cascade-data/cov_dumps_mem_stdout/"
PLOT_PATH = "/mnt/cascade-meta/design-processing/common/python_scripts/analysis/drfuzz_mem/plots"
#%% reader function to parallelize reading
def read_json(p):
    with open(p, 'r') as f:
            d = json.load(f)[0]
    d["coverage"] = [i for i,j in  enumerate(d["output"]["coverage"]) if j]
    d["taints"] = [i for i,j in enumerate(d["output"]["taints"]) if j]
    d["potential"] = [i for i,(j,k) in enumerate(zip(d["output"]["taints"],d["output"]["coverage"])) if j and not k]
    d["n_taints"] = len(d["taints"])
    d["n_cov"] = len(d["coverage"])
    d["n_pot"] = len(d["potential"])
    d["i_type"] = "".join(i["type"] for i in d["instructions"])
    return pd.DataFrame([d])
#%%
data = pd.DataFrame()
files = glob.glob(f'{COV_DUMPS}/**/*.queue.json',recursive=True)
for file in files:
    data = pd.concat([data,read_json(file)])


# %%
sns.histplot([i for j in data["coverage"].values for i in j])

# %%
sns.histplot([i for j in data["taints"].values for i in j])
#%% 
sns.histplot([i for j in data["potential"].values for i in j])
#%% 
sns.histplot(data=data, x="n_pot", hue="i_type")
#%% 
sns.histplot(data=data, x="n_taints", hue="i_type")
#%% 

# %%
sns.histplot(data["n_taints"])
sns.histplot(data["n_cov"])

# %%
