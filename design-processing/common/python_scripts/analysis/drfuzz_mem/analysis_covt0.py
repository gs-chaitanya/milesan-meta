#%%
COV_T0_PATH_ARCH = "/mnt/milesan-data-ccs/COV_T0/cov.arch-explosion.t0"
COV_T0_PATH_MUARCH = "/mnt/milesan-data-ccs/COV_T0/cov_spectrev1.t0"
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
#%%
arch = pd.DataFrame()
with open(COV_T0_PATH_ARCH,"r") as f:
    for line in f.read().split("\n"):
        if not len(line):
            continue
        strips = line.split(":")
        step_id = int(strips[0].strip(),16)
        muxcov_t0 = bin(int(strips[1].strip().replace("X","0").replace("x","0"),16)).count("1")
        pc_t0 = int(strips[2].strip(", ").replace("X","0").replace("x","0"),16)
        arch = pd.concat([arch,
                        pd.DataFrame([
                            {
                                "step_id": step_id,
                                "muxcov_t0": muxcov_t0,
                                "pc_t0" : pc_t0,
                                "type":"arch"
                            }]
                        )])
        

with open(COV_T0_PATH_MUARCH,"r") as f:
    for line in f.read().split("\n"):
        if not len(line):
            continue
        strips = line.split(":")
        step_id = int(strips[0].strip(),16)
        muxcov_t0 = bin(int(strips[1].strip().replace("X","0").replace("x","0"),16)).count("1")
        pc_t0 = int(strips[2].strip(", ").replace("X","0").replace("x","0"),16)
        arch = pd.concat([arch,
                        pd.DataFrame([
                            {
                                "step_id": step_id,
                                "muxcov_t0": muxcov_t0,
                                "pc_t0" : pc_t0,
                                "type":"muarch"
                            }]
                        )])
# %%
pc_taint_step_arch = min(arch[ (arch["type"] == "arch") & (arch["pc_t0"] > 0)]["step_id"])
pc_taint_step_uarch = min(arch[ (arch["type"] != "arch") & (arch["pc_t0"] > 0)]["step_id"])
diff = pc_taint_step_arch - pc_taint_step_uarch
#%%
fig, ax = plt.subplots()
sns.lineplot(arch, x="step_id",y="muxcov_t0",hue="type",ax=ax)
ax.axvline(x=pc_taint_step_arch)
# sns.lineplot(arch, x="step_id",y="pc_t0",hue="type",ax=ax)
ax.axvline(x=pc_taint_step_uarch)
# %%
#%%
fig, ax = plt.subplots()
sns.lineplot(arch[arch["type"] != "arch"], x="step_id",y="muxcov_t0",ax=ax)
ax.axvline(x=pc_taint_step_uarch)
# sns.lineplot(arch, x="step_id",y="pc_t0",hue="type",ax=ax)
# ax.axvline(x=pc_taint_step_uarch)
# %%
