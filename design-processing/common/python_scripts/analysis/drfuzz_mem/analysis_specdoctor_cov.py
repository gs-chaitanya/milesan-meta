#%%
import numpy
import pandas as pd
import glob
import matplotlib.pyplot as plt
import seaborn as sns
import json
#%%
N_COV_PTS_SPECDOC = 6555
N_COV_PTS_MILESAN = 7282
SPECDOC_COVERAGE_PATH = "/mnt//specdoctor-programs/coverage/"
MILESAN_COVERAGE_PATH = "/mnt/milesan-data-cov/**/*"
#%%
timestamp_to_coverage = {}
for i,file in enumerate(glob.glob(SPECDOC_COVERAGE_PATH+ ".*cov", recursive=True)):
    with open(file, "r") as f:
        cov_map = f.read()
    timestamp = file.split("/")[-1].split(".")[-2].split("_")[-1]
    seconds = timestamp.split(":")[-1]
    minutes = timestamp.split(":")[-2]

    hours = timestamp.split(":")[-3]
    timestamp = int(hours)*3600 + int(minutes)*60 + int(seconds)
    coverage = int(cov_map,16)
    timestamp_to_coverage[timestamp] = coverage
    
#%%
coverage_df = pd.DataFrame()
acc_coverage = 0
start = min(timestamp_to_coverage.keys())
for timestamp in sorted(timestamp_to_coverage):
    acc_coverage |= timestamp_to_coverage[timestamp]
    coverage_df = pd.concat([coverage_df,
                             pd.DataFrame(
                                 [
                                     {"time": timestamp-start, 
                                      "acc_coverage": acc_coverage.bit_count()/N_COV_PTS_SPECDOC,
                                      "fuzzer": "specdoctor"
                                      }
                                 ]
                             )
                            ])

#%%
seed_to_timestamp = {}
for i,file in enumerate(glob.glob(MILESAN_COVERAGE_PATH+ "perfstats.json", recursive=True)):
    with open(file, "r") as f:
        perfstats = json.load(f)
    seed_to_timestamp[perfstats["seed"]] = perfstats["t_total"]
#%%
acc_time = 0
seed_to_acc_time = {}
for seed in sorted(seed_to_timestamp):
    acc_time += seed_to_timestamp[seed]
    seed_to_acc_time[seed] = acc_time

#%%
seed_to_coverage = {}
for i,file in enumerate(glob.glob(MILESAN_COVERAGE_PATH+ ".*cov", recursive=True)):
    with open(file, "r") as f:
        cov_map = f.read()
        if len(cov_map) == 0:
            continue
    coverage = int(cov_map.replace("X","0"),16)
    perfstats = "/".join(file.split("/")[:-1])+"/perfstats.json"
    try:
        with open(perfstats, "r") as f:
            perfstats = json.load(f)
    except:
        continue
    seed_to_coverage[perfstats["seed"]] = coverage
#%%
acc_coverage = 0
for seed in sorted(seed_to_coverage):
    acc_coverage |= seed_to_coverage[seed]
    coverage_df = pd.concat([coverage_df,
                            pd.DataFrame(
                                [
                                    {"time": seed_to_acc_time[seed], 
                                    "acc_coverage": acc_coverage.bit_count()/N_COV_PTS_MILESAN,
                                    "fuzzer": "cirrina"
                                    }
                                ]
                            )
                        ])

# %%
fig, ax = plt.subplots()
sns.lineplot(data=coverage_df, x="time", y="acc_coverage", hue="fuzzer",ax=ax)
ax.set_xlim([0,10000])
# %%
