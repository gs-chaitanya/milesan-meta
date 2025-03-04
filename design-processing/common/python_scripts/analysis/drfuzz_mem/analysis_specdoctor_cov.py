#%%
import numpy
import pandas as pd
import glob
import matplotlib.pyplot as plt
import seaborn as sns
#%%
N_COV_PTS_SPECDOC = 6555
N_COV_PTS_MILESAN = 7282
SPECDOC_COVERAGE_PATH = "/mnt//specdoctor-programs/coverage/"
#%%
seed_to_coverage_df = pd.DataFrame()
#%%
seed_to_coverage = []
for i,file in enumerate(glob.glob(SPECDOC_COVERAGE_PATH+ ".*cov", recursive=True)):
    with open(file, "r") as f:
        cov_map = f.read()
    # timestamp = file.split("/")[-1].split(".")[-2].split("_")[-1]
    # seconds = timestamp.split(":")[-1]
    # minutes = timestamp.split(":")[-2]

    # hours = timestamp.split(":")[-3]
    # time_to_cov[int(hours)*3600 + int(minutes)*60 + int(seconds)] = int(cov_map,16)
    seed_to_coverage += [int(cov_map,16)]
# %%
acc_cov = []
acc_cov_rel = []
for i,cov in enumerate(seed_to_coverage):
    c = 0
    for prior_cov in acc_cov:
        c |= prior_cov
    acc_cov += [c | cov]
    acc_cov_rel += [acc_cov[i].bit_count()/N_COV_PTS_SPECDOC]
    seed_to_coverage_df = pd.concat([seed_to_coverage_df, 
                                  pd.DataFrame(
                                      [
                                          {"seed": i, 
                                           "coverage": acc_cov_rel[i], 
                                           "fuzzer": "specdoc"
                                           }
                                        ]
                                        )
                                        ])

# %%

MILESAN_COVERAGE_PATH = "/mnt/milesan-data-cov/**/*"
#%%
seed_to_coverage = []
for i,file in enumerate(glob.glob(MILESAN_COVERAGE_PATH+ ".*cov", recursive=True)):
    with open(file, "r") as f:
        cov_map = f.read()
        if len(cov_map) == 0:
            continue
    # timestamp = file.split("/")[-1].split(".")[-2].split("_")[-1]
    # seconds = timestamp.split(":")[-1]
    # minutes = timestamp.split(":")[-2]

    # hours = timestamp.split(":")[-3]
    # time_to_cov[int(hours)*3600 + int(minutes)*60 + int(seconds)] = int(cov_map,16)
    seed_to_coverage += [int(cov_map.replace("X","0"),16)]

# %%
acc_cov = []
acc_cov_rel = []
for i,cov in enumerate(seed_to_coverage):
    c = 0
    for prior_cov in acc_cov:
        c |= prior_cov
    acc_cov += [c | cov]
    acc_cov_rel += [acc_cov[i].bit_count()/N_COV_PTS_MILESAN]
    seed_to_coverage_df = pd.concat([seed_to_coverage_df, 
                                  pd.DataFrame(
                                      [
                                          {"seed": i, 
                                           "coverage": acc_cov_rel[i], 
                                           "fuzzer": "cirrina"
                                           }
                                        ]
                                        )
                                        ])


# %%
fig, ax = plt.subplots()
sns.lineplot(data=seed_to_coverage_df, x="seed", y="coverage", hue="fuzzer",ax=ax)
ax.set_xlim([0,100])
ax.set_ylim([0.75,])
# %%
