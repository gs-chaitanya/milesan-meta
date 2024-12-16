#%%
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import os
#%%
SOURCE_PATH = "/milesan-data/rocket/"
#%%
for root, dirs, files in os.walk(SOURCE_PATH):
  for file in files:
    if "writeback.txt" in file:
        print()
        with open(os.path.join(root,file), "r") as f:
            for line in f.read():
                sim = int(line.split(",")[-2],16)
                rtl = int(line.split(",")[-1],16)

# %%
