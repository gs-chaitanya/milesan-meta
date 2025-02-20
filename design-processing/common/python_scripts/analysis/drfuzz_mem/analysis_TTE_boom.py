#%%
PROG_GEN_TIME = 30
#%%
def parse_log_file(file_path):
    seed_timestamp_dict = {}
    with open(file_path, 'r') as file:
        lines = file.read().split("\n")
        for i, line in enumerate(lines):
            if "seed" in line:
                seed = int(line.split(" ")[1].strip(":"))
                timestamp = float(lines[i+3].split(" ")[1])
                seed_timestamp_dict[seed] = timestamp
    return seed_timestamp_dict

log_file_path = '/mnt/milesan-data-hypertriage-openc910-boom/S_to_U/logs/boom.taint_mismatch.log'
seed_timestamp_dict = parse_log_file(log_file_path)
print(seed_timestamp_dict)
#%%
seed_timestamp_dict = {key:seed_timestamp_dict[key] for key in sorted(seed_timestamp_dict.keys())}
# %%
seed_timestamp_sum_dict = {key: sum([seed_timestamp_dict[seed] if seed in seed_timestamp_dict else PROG_GEN_TIME for seed in range(1, key+1)]) for key in seed_timestamp_dict.keys()}
seed_timestamp_sum_dict_cpumin ={key:val/60 for key, val in seed_timestamp_sum_dict.items()}
seed_timestamp_sum_dict_cpuh ={key:val/60 for key, val in seed_timestamp_sum_dict_cpumin.items()}

# %%
