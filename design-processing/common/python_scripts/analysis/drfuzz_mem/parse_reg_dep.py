#%%
import re
import pandas as pd
p =  "/milesan-data/spikeresol368790_kronos_8_3.elf.dump"
with open(p,"r") as f:
    file = f.read()
df = pd.DataFrame()

for line in file.split("\n"):
    splits = line.split("\t")
    if len(splits) != 4:
        continue
    regs = re.findall("x[0-9]+",splits[-1])
    # print(regs)
    if len(regs) == 0:
        continue
    bytecode = splits[1].strip()[:-1]
    addr = splits[0].strip()
    op = splits[2].strip()
    df = pd.concat([df,pd.DataFrame([{
        "addr":addr,
        "bytecode":bytecode,
        "op":op,
        "rd":regs[0],
        "rs": regs[1:]
    }])])


#%%