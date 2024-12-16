#%%
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
LOG_REDUCE_PATH="/milesan-data/logs/boom.reduce.log"

#%%
with open(LOG_REDUCE_PATH, "r") as f:
    logs = f.read()
# %%
logs_df = pd.DataFrame()
lines = logs.split("\n")
for idx in range(len(lines)):
    entry = {}
    if "seed" in lines[idx]:
        entry["seed"] = int(lines[idx].split(" ")[-1][:-1])
        if "No mismatch detected." in lines[idx+1]:
            continue
        assert "Larger elf at" in lines[idx+1]
        entry["larger_elf"] = lines[idx+1].split(" ")[-1]
        assert "Smaller elf at" in lines[idx+2]
        entry["smaller_elf"] = lines[idx+2].split(" ")[-1]
        assert "Flatten success" in lines[idx+3]
        entry["flatten_success"] = lines[idx+3].split(" ")[-1] == "True"
        assert "Failing bb id" in lines[idx+4]
        entry["failing_bb_id"] = int(lines[idx+4].split(" ")[-1])
        assert "Failing instr id" in lines[idx+5]
        entry["failing_instr_id"] = int(lines[idx+5].split(" ")[-1])
        assert "Failing instr" in lines[idx+6]
        entry["failing_instr_addr"] = lines[idx+6].split(":")[1].strip()
        entry["failing_instr_str"]  = lines[idx+6].split(":")[-1].strip()
        entry["failing_instr"]  = lines[idx+6].split(":")[-1].split(" ")[1]
        assert "Pillar bb id" in lines[idx+7]
        entry["pillar_bb_id"] = int(lines[idx+7].split(" ")[-1])
        assert "Pillar instr id" in lines[idx+8]
        entry["pillar_instr_id"] = int(lines[idx+8].split(" ")[-1])
        assert "Pillar instr" in lines[idx+9]
        entry["pillar_instr_addr"] = lines[idx+9].split(":")[1].strip()
        entry["pillar_instr_str"]  = lines[idx+9].split(":")[-1].strip()
        entry["pillar_instr"]  = lines[idx+9].split(":")[-1].split(" ")[1]
        assert "Total number of bbs" in lines[idx+10]
        entry["n_bbs"] = int(lines[idx+10].split(" ")[-1])
        assert "Total number of non-nop instructions" in lines[idx+11]
        entry["n_instrs"] = int(lines[idx+11].split(":")[-1].split(" ")[1])
        logs_df = pd.concat([logs_df, pd.DataFrame([entry])])



# %%
