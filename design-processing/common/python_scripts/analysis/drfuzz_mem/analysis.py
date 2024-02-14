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
            d = json.load(f)
    if 'meta' in p:
        return pd.DataFrame([d])
    coverage = np.array(d['coverage'])
    abs_coverage =  np.count_nonzero(coverage)
    rel_coverage =abs_coverage/len(coverage)
    if('taints' in d):
        taints = np.array(d['taints'])
        abs_taints = np.count_nonzero(taints)
        rel_taints = abs_taints/len(taints)
        reachable = [a and not b for a,b in zip(taints,coverage)]
        abs_reachable = np.count_nonzero(reachable)
        rel_reachable = abs_reachable/(len(coverage) - np.count_nonzero(coverage)) # the portion of untoggled mux that are tainted
        unreachable = [not a and not b for a,b in zip(taints,coverage)]
        abs_unreachable =  np.count_nonzero(unreachable)
        rel_unreachable = abs_unreachable/(len(coverage) - np.count_nonzero(coverage)) # the portion of untuggled mux that are not tainted
        max_reach_coverage = [a or b for a,b in zip(taints,coverage)]  # this is not the same as rel_taints as some mux that toggle might not be affected by dataflow so might not be tainted
        max_abs_reach_coverage = np.count_nonzero(max_reach_coverage)
        max_reach_rel_coverage = max_abs_reach_coverage/len(max_reach_coverage)
    d['abs_coverage'] = abs_coverage
    d['rel_coverage'] = rel_coverage
    # d['inst'] = p.split('/')[-4]
    if('taints' in d):
        d['abs_taints'] = abs_taints
        d['rel_taints'] = rel_taints
        d['abs_reachable'] = abs_reachable
        d['reachable'] = reachable
        d['rel_reachable'] = rel_reachable
        d['abs_unreachable'] = abs_unreachable
        d['unreachable'] = unreachable
        d['rel_unreachable'] = rel_unreachable
        d['max_abs_reach_coverage'] = max_abs_reach_coverage
        d['max_reach_coverage'] = max_reach_coverage
        d['max_reach_rel_coverage'] = max_reach_rel_coverage
        nested_freq = [[i]*d['taints'][i] for i in range(len(d['taints']))]
        d['taint_freq'] = [a for b in nested_freq for a in b]
    d['elf_type'] = 'final' if 'rtl' in d['elf'] else 'interm'
    d['n_cov_points'] = len(coverage)
    d['toggle_count'] = [i if d else None for i,d in enumerate(coverage)]
    nested_freq = [[i]*d['coverage'][i] for i in range(len(d['coverage']))]
    d['toggle_freq'] = [a for b in nested_freq for a in b]
    return pd.DataFrame([d])
#%%
data = pd.DataFrame()
files = glob.glob(f'{COV_DUMPS}/**/*.queue.json',recursive=True)
for file in files:
    data = pd.concat([data,read_json(file)])
#%%
meta = pd.DataFrame()
files = glob.glob(f'{COV_DUMPS}/**/meta.info.json',recursive=True)
for file in files:
    meta = pd.concat([meta,read_json(file)])
#%%
data = pd.DataFrame()
for fail_t in set(meta['fail_t']):
    for dut in set(meta['dut']):
        dmeta = meta[meta['dut'] == dut]
        for i, id in enumerate(dmeta[dmeta['fail_t']==fail_t]['id']):
            files = glob.glob(f'{dmeta[(dmeta["id"] == id) & (dmeta["fail_t"] == fail_t)]["cov_dir"].values[0]}/*.cov.json',recursive=True)
            for file in files:
                data = pd.concat([data,read_json(file)])
            break

#%% 
def exception_func(row):
    if row['elf'] in set(meta['elf']):
        return meta[meta['elf'] == row['elf']]['exception'].values[0]
    return None

def failed_func(row):
    if row['elf'] in set(meta['elf']):
        return meta[meta['elf'] == row['elf']]['fail_t'].values[0]
    return None

data['fail_t'] = data.apply(lambda row: failed_func(row),axis=1)
data['exception'] = data.apply(lambda row: exception_func(row),axis=1)
data = data.dropna()

#%%
ids = set(data['id'])
fig, ax = plt.subplots(len(ids),sharex=False,sharey=True)
fig.set_figheight(len(ids)*5)
fig.set_figwidth(10)
for i, id in enumerate(ids):
    id_data = data[data['id'] == id]
    if len(set(id_data['inst'])) != 2: continue
    sns.lineplot(id_data,
            x='ticks',
            y='rel_coverage',
            hue='inst',
            ax = ax[i])
plt.tight_layout()
#%% coverage interpolation over timestamp or ticks for median plots
interp = pd.DataFrame()
steps = 1000
n_duts = len(set(data['dut']))
hue_attr = 'inst' # was inst before
xval = 'ticks'

for i,dut in enumerate(set(data['dut'])):
    d = data[(data['dut']==dut)]
    max_ticks = max(d['ticks'])
    max_x = max(d[xval])
    min_x = min(d[xval])
    all_x = np.arange(min_x,max_x,steps)
    for id in set(d['id']):
        # only consider executions of elfs that we have for both rfuzz and drfuzz
        # if len(d[(d['id']==id) & (d['inst']=='rfuzz_mem')]) == 0: continue
        # if len(d[(d['id']==id) & (d['inst']=='drfuzz_mem')]) == 0: continue
        for hue in set(d[hue_attr]):
            sorted_d = d[(d['id']==id) & (d[hue_attr]==hue)].sort_values(xval, axis=0)
            if len(sorted_d) == 0: continue
            cov_points = sorted_d['rel_coverage']
            xvals = sorted_d[xval]
            interp_cov = np.interp(all_x, xvals, cov_points)
            interp_dict = {
                xval:all_x,
                'cov':interp_cov,
                'id':id,
                'dut':dut,
                hue_attr:hue,
            }
            interp = pd.concat([interp, pd.DataFrame(interp_dict)])
#%%
fig, ax = plt.subplots(n_duts)
fig.set_figheight(n_duts*5)
fig.set_figwidth(10)
# palette = {'timeout': 'r', 'reg_mismatch': 'g', 'false': 'b'}
if n_duts == 1:
    ax = [ax]
for i,dut in enumerate(set(data['dut'])):
    sns.lineplot(data=interp[interp['dut']==dut],
                x=xval,
                y='cov',
                ax=ax[i],
                hue=hue_attr)
    ax[i].set_title(dut)
    # ax[i].set_ylim([0.6,0.8])
    # ax[i].set_xlim([0,10000])
plt.tight_layout()
# plt.savefig(f"{PLOT_PATH}/median_over_timestamp_0.png")
#%%
fail_types = set(data['fail_t'])
fig, ax = plt.subplots(len(fail_types))
fig.set_figheight(len(fail_types)*5)
fig.set_figwidth(10)
N_IDS = 10
subset_ids = []
for fail_t in fail_types:
    subset_ids += list(set(data[data['fail_t']==fail_t]['id']))[-N_IDS:]

subset_data = pd.DataFrame()
for subset_id in subset_ids:
    subset_data = pd.concat([data[data['id'] == subset_id],subset_data])

for i,fail_t in enumerate(fail_types):
    sns.lineplot(data=subset_data[subset_data['fail_t'] == fail_t],
                x='ticks',
                y='rel_coverage',
                ax=ax[i],
                hue='id')
    ax[i].set_title(fail_t)
    ax[i].set_xlim([0,2000])


#%%
ids = set(data['id'])
fig, ax = plt.subplots(len(ids),sharex=True,sharey=True)
for i, id in enumerate(ids):
    sns.lineplot(data[data['id'] == id],x='ticks',y='rel_coverage',hue='fail_t',ax=ax[i])
    ax[i].set_xlim([150,200])
    ax[i].set_ylim([0.7,0.8])

#%%
max_data = pd.DataFrame()
for id in set(data['id']):
    max_ticks =  max(data[data['id'] == id]['ticks']),
    new_d = {
        'id' : id,
        'rel_coverage': max(data[data['id'] == id]['rel_coverage']),
        'ticks': max_ticks,
        'fail_t': data[data['id'] == id]['fail_t'].values[0],
        'coverage':data[(data['id'] == id) & (data['ticks'] == max_ticks)]['coverage'].values[0],
        'toggle_freq':data[(data['id'] == id) & (data['ticks'] == max_ticks)]['toggle_freq'].values[0]
    }
    max_data = pd.concat([max_data,pd.DataFrame([new_d])])
#%%
max_data_acc = pd.DataFrame()
for fail_t in set(data['fail_t']):
    new_d = {
        'fail_t': fail_t,
        'flat_toggle': [item for sublist in  max_data[max_data['fail_t'] == fail_t]['toggle_freq'].values for item in sublist]
    }
    max_data_acc = pd.concat([max_data_acc, pd.DataFrame([new_d])])

#%%
fig, ax = plt.subplots(len(set(data['fail_t'])))
fig.set_figheight(10)
fig.set_figwidth(10)
for i,fail_t in enumerate(set(data['fail_t'])):
    sns.histplot(max_data_acc[max_data_acc['fail_t'] == fail_t]['flat_toggle'].values[0],ax=ax[i])
    ax[i].set_title(fail_t)
plt.tight_layout()
#%% coverage interpolation over ticks for median plots
interp_ticks = pd.DataFrame()
steps = 10**5
fig, ax = plt.subplots(len(set(data['dut'])))
fig.set_figheight(10)
fig.set_figwidth(10)
min_ticks = {}
max_ticks = {}
if len(set(data['dut'])) == 1:
    ax = [ax]
for i,dut in enumerate(set(data['dut'])):
    dut_data = data[data['dut']==dut]
    for inst in set(dut_data['inst']):
        d = dut_data[dut_data['inst'] == inst]
        max_ticks[inst] = max(d['ticks'])
        min_ticks[inst] = min(d['ticks'])
        all_ticks = np.arange(min_ticks[inst],max_ticks[inst],steps)
        for id in set(d['id']):
            # only consider executions of elfs that we have for both rfuzz and drfuzz
            # if len(data[(data['id']==id) & (data['inst']=='rfuzz_mem')]) == 0: continue
            # if len(data[(data['id']==id) & (data['inst']=='drfuzz_mem')]) == 0: continue
            sorted_d = d[(d['id']==id) & (d['inst']==inst)].sort_values('ticks', axis=0)
            cov_points = sorted_d['rel_coverage']
            ticks = sorted_d['ticks']
            interp_cov = np.interp(all_ticks, ticks, cov_points)
            interp_dict = {
                'ticks':all_ticks,
                'cov':interp_cov,
                'id':id,
                'dut':dut,
                'inst':inst,
            }
            interp_ticks = pd.concat([interp_ticks, pd.DataFrame(interp_dict)])
 
    sns.lineplot(data=interp_ticks[interp_ticks['dut']==dut],
            x='ticks',
            y='cov',
            ax=ax[i],
            hue='inst')
    ax[i].set_title(dut)
    ax[i].set_xlim([min_ticks['rfuzz_mem'], max_ticks['drfuzz_mem']+10**7])


plt.tight_layout()
# plt.savefig(f"{PLOT_PATH}/median_over_ticks_0png")
#%%
for id in set(data['id']):
    id_data = data[data['id'] == id]
    cov_dict = {}
    for inst in set(data['inst']):
        inst_id_data = id_data[id_data['inst']==inst]
        min_ticks = min(inst_id_data['ticks'])
        cov = inst_id_data[inst_id_data['ticks'] == min_ticks]['rel_coverage']
        cov_dict[inst] = cov.values[0]
    if cov_dict['rfuzz_mem'] is not cov_dict['drfuzz_mem']:
        print(f"{id}: {cov_dict['drfuzz_mem']} != {cov_dict['rfuzz_mem']}")

#%% coverage interpolation over ticks for median plots, compare number of max basic blocks
interp_ticks = pd.DataFrame()
steps = 10**5

for i,dut in enumerate(set(data['dut'])):
    dut_data = data[data['dut']==dut]
    for inst in set(dut_data['inst']):
        d = dut_data[dut_data['inst'] == inst]
        max_ticks = max(d['ticks'])
        min_ticks = min(d['ticks'])
        all_ticks = np.arange(min_ticks,max_ticks,steps)
        for id in set(d['id']):
            for t in set(d['type']):
                # only consider executions of elfs that we have for both rfuzz and drfuzz
                sorted_d = d[(d['id']==id) & (d['inst']==inst) & (d['type'] == t)].sort_values('ticks', axis=0)
                if not len(sorted_d): continue
                cov_points = sorted_d['rel_coverage']
                ticks = sorted_d['ticks']
                interp_cov = np.interp(all_ticks, ticks, cov_points)
        
                interp_dict = {
                    'ticks':all_ticks,
                    'cov':interp_cov,
                    'id':id,
                    'dut':dut,
                    'inst':inst,
                    'type': t
                }
                interp_ticks = pd.concat([interp_ticks, pd.DataFrame(interp_dict)])

#%% plot for coverage interpolation for intermediate and final elf
fig, ax = plt.subplots(len(set(data['dut'])), 2,sharex='row',sharey='row')
fig.set_figheight(10)
fig.set_figwidth(10)
palette = {'rfuzz_mem': 'r', 'drfuzz_mem': 'b'}

for i,dut in enumerate(set(data['dut'])):
    for j,t in enumerate(set(data['type'])):
        sns.lineplot(data=interp_ticks[(interp_ticks['dut']==dut) & (interp_ticks['type']==t)],
                x='ticks',
                y='cov',
                ax=ax[i,j],
                hue='inst',
                palette=palette)
        ax[i,j].set_title(f'{dut}:{t}')
        ax[i,j].set_xlim([0,max(interp_ticks[(interp_ticks['dut']==dut) & (interp_ticks['inst']=='drfuzz_mem')]['ticks'])])

plt.tight_layout()
# plt.savefig(f"{PLOT_PATH}/bbs_50_1000.png")
#%% checking deviation of starting coverage to drop those from dataframe
drop_ids = []
for dut in set(data['dut']):
    boom = interp_ticks[(interp_ticks['dut'] == dut) & (interp_ticks['type'] == 'final')]
    ids = set(boom['id'])
    fig, ax = plt.subplots(len(ids),sharex = True,  sharey= True)
    fig.set_figheight(3*len(ids))
    fig.set_figwidth(10)
    for i,id in enumerate(ids):
        boom_id = boom[boom['id'] == id]
        min_tick_rfuzz = min(boom_id[boom_id['inst'] == 'rfuzz_mem']['ticks'])
        min_tick_drfuzz = min(boom_id[boom_id['inst'] == 'drfuzz_mem']['ticks'])
        max_tick_drfuzz = max(boom_id[boom_id['inst'] == 'drfuzz_mem']['ticks'])
        min_cov_rfuzz = min(boom_id[(boom_id['inst'] == 'rfuzz_mem') & (boom_id['ticks'] == min_tick_rfuzz)]['cov'])
        min_cov_drfuzz = min(boom_id[(boom_id['inst'] == 'drfuzz_mem') & (boom_id['ticks'] == min_tick_drfuzz)]['cov'])
        sns.lineplot(data=boom_id,
                    x = 'ticks',
                    y = 'cov',
                    hue='inst',
                    ax=ax[i])
        ax[i].set_xlim([0,2*min_tick_drfuzz])
        ax[i].set_title(id)
        if abs(min_cov_rfuzz-min_cov_drfuzz) > 0.01: drop_ids += [id]
    fig.tight_layout()

#%%

#%% coverage interpolation over ticks for median plots, compare number of max basic blocks
interp_ticks_drop = pd.DataFrame()
steps = 10**5

for i,dut in enumerate(set(data['dut'])):
    dut_data = data[data['dut']==dut]
    for inst in set(dut_data['inst']):
        d = dut_data[dut_data['inst'] == inst]
        max_ticks = max(d['ticks'])
        min_ticks = min(d['ticks'])
        all_ticks = np.arange(min_ticks,max_ticks,steps)
        for id in set(d['id']):
            if id in drop_ids: continue
            for t in set(d['type']):
                # only consider executions of elfs that we have for both rfuzz and drfuzz
                sorted_d = d[(d['id']==id) & (d['inst']==inst) & (d['type'] == t)].sort_values('ticks', axis=0)
                if not len(sorted_d): continue
                cov_points = sorted_d['rel_coverage']
                ticks = sorted_d['ticks']
                interp_cov = np.interp(all_ticks, ticks, cov_points)
        
                interp_dict = {
                    'ticks':all_ticks,
                    'cov':interp_cov,
                    'id':id,
                    'dut':dut,
                    'inst':inst,
                    'type': t
                }
                interp_ticks_drop = pd.concat([interp_ticks_drop, pd.DataFrame(interp_dict)])


#%% plot for coverage interpolation for intermediate and final elf
fig, ax = plt.subplots(len(set(data['dut'])), 2,sharex='row',sharey='row')
fig.set_figheight(10)
fig.set_figwidth(10)
palette = {'rfuzz_mem': 'r', 'drfuzz_mem': 'b'}

for i,dut in enumerate(set(data['dut'])):
    for j,t in enumerate(set(data['type'])):
        sns.lineplot(data=interp_ticks_drop[(interp_ticks_drop['dut']==dut) & (interp_ticks_drop['type']==t)],
                x='ticks',
                y='cov',
                ax=ax[i,j],
                hue='inst',
                palette=palette)
        ax[i,j].set_title(f'{dut}:{t}')
        ax[i,j].set_xlim([0,max(interp_ticks_drop[(interp_ticks_drop['dut']==dut) & (interp_ticks_drop['inst']=='drfuzz_mem')]['ticks'])])

plt.tight_layout()

#%% compute median improvements
deltas = pd.DataFrame()
for id in set(data['id']):
    id_data = data[data['id']==id]
    for inst in set(id_data['inst']):
        inst_data = id_data[id_data['inst']==inst]
        delta = max(inst_data['rel_coverage'])-min(inst_data['rel_coverage'])
        pd_dict = {
            'id':id,
            'dut':list(set(inst_data['dut'].values))[0],
            'inst':inst,
            'delta': delta,
            'type' : list(inst_data[inst_data['id'] == id]['type'])[0]
        }
        deltas = pd.concat([deltas,pd.DataFrame([pd_dict])])
#%% achieved coverage rfuzz vs drfuzz
#%% histogram plots for deltas
fig, ax = plt.subplots(len(set(data['dut'])), 2)
fig.set_figheight(10)
fig.set_figwidth(10)
for i,dut in enumerate(set(data['dut'])):
    for j,inst in  enumerate(set(data['inst'])):
        sns.histplot(data=deltas[(deltas['dut']==dut) & (deltas['inst'] == inst)], x='delta',hue='type',ax=ax[i,j])
        ax[i,j].set_title(f"{dut}:{inst}")
plt.tight_layout()

#%%
fig, ax = plt.subplots(len(set(data['dut'])),2)
fig.set_figheight(10)
fig.set_figwidth(10)
for i,dut in enumerate(set(data['dut'])):
    for j,inst in enumerate(set(data['inst'])):
        sns.histplot(data=data[(data['dut']==dut) & (data['inst'] == inst)], x='status',ax=ax[i,j])
        ax[i,j].set_title(f"{dut}:{inst}")
plt.tight_layout()



#%%
acc_res = pd.DataFrame()
fig, ax = plt.subplots(2,len(np.unique(data['dut'])),sharex='col',figsize=(10, 5))
duts = np.unique(data['dut'])
for i, dut in  enumerate(duts):
    dut_data = data[(data['dut']==dut) & (data['inst']=='drfuzz_mem')]
    acc = {}
    acc['coverage'] = np.sum([d for d in dut_data['coverage']],axis=0)
    acc['rel_coverage'] = np.count_nonzero(acc['coverage'])/len(acc['coverage'])
    acc['taints'] = np.sum([d for d in dut_data['taints']],axis=0)
    acc['rel_taints'] = np.count_nonzero(acc['taints'])/len(acc['taints'])
    acc['reachable'] = [a and not b for a,b in zip(acc['taints'],acc['coverage'])]
    acc['rel_reachable'] = np.count_nonzero(acc['reachable'])/(len(acc['coverage'])-np.count_nonzero(acc['coverage']))
    acc['unreachable'] = [not a and not b for a,b in zip(acc['taints'],acc['coverage'])]
    acc['rel_unreachable'] = np.count_nonzero(acc['unreachable'])/(len(acc['coverage'])-np.count_nonzero(acc['coverage']))
    acc['max_reach_coverage'] = [a or b for a,b in zip(acc['coverage'],acc['taints'])]
    acc['max_reach_rel_coverage'] = np.count_nonzero(acc['max_reach_coverage'])/len(acc['max_reach_coverage'])
    acc['dut'] = dut
    acc['toggle_count'] = [a for a in data['toggle_count'][i] for i in range(len(dut_data['toggle_count']))]
    acc['toggle_freq'] = [a for b in dut_data['toggle_freq'] for a in b]
    acc['taint_freq'] = [a for b in dut_data['taint_freq'] for a in b]

    acc_res = pd.concat([acc_res, pd.DataFrame([acc])], ignore_index=True)
    sns.histplot(acc['toggle_freq'], stat='count',ax=ax[0,i])
    ax[0,i].set_xlim([0,len(acc['coverage'])])
    ax[0,i].set_title(f'{dut}: mux toggle histogram')

    sns.histplot(acc['taint_freq'], stat='count',ax=ax[1,i])
    ax[1,i].set_xlim([0,len(acc['taints'])])
    ax[1,i].set_title(f'{dut}: mux taint histogram')
    plt.tight_layout()

#%%
acc_res = pd.DataFrame()
fig, ax = plt.subplots(2,len(np.unique(data['dut'])),sharex='col',figsize=(10, 5))
duts = np.unique(data['dut'])
for i, dut in  enumerate(duts):
    dut_data = data[(data['dut']==dut) & (data['inst']=='drfuzz_mem')]
    acc = {}
    acc['coverage'] = np.sum([d for d in dut_data['coverage']],axis=0)
    acc['rel_coverage'] = np.count_nonzero(acc['coverage'])/len(acc['coverage'])
    acc['dut'] = dut
    acc['toggle_count'] = [a for a in data['toggle_count'][i] for i in range(len(dut_data['toggle_count']))]
    acc['toggle_freq'] = [a for b in dut_data['toggle_freq'] for a in b]

    acc_res = pd.concat([acc_res, pd.DataFrame([acc])], ignore_index=True)
    sns.histplot(acc['toggle_freq'], stat='count',ax=ax[0,i])
    ax[0,i].set_xlim([0,len(acc['coverage'])])
    ax[0,i].set_title(f'{dut}: mux toggle histogram, drfuzz')

    dut_data = data[(data['dut']==dut) & (data['inst']=='rfuzz_mem')]
    acc = {}
    acc['coverage'] = np.sum([d for d in dut_data['coverage']],axis=0)
    acc['rel_coverage'] = np.count_nonzero(acc['coverage'])/len(acc['coverage'])
    acc['dut'] = dut
    acc['toggle_count'] = [a for a in data['toggle_count'][i] for i in range(len(dut_data['toggle_count']))]
    acc['toggle_freq'] = [a for b in dut_data['toggle_freq'] for a in b]

    acc_res = pd.concat([acc_res, pd.DataFrame([acc])], ignore_index=True)

    acc_res = pd.concat([acc_res, pd.DataFrame([acc])], ignore_index=True)
    sns.histplot(acc['toggle_freq'], stat='count',ax=ax[1,i])
    ax[1,i].set_xlim([0,len(acc['coverage'])])
    ax[1,i].set_title(f'{dut}: mux toggle histogram, rfuzz')
