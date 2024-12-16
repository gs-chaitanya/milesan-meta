#%%
import matplotlib.pyplot as plt
import json
import pandas as pd
import seaborn as sns
from os import listdir, path
import numpy as np
import pickle
import numpy as np
import matplotlib.pyplot as plt
import glob
import pandas as pd
import seaborn as sns
COV_DUMPS = "/cellift-meta/design-processing/common/python_scripts/analysis/cov_dumps"
MILESAN_DATA = "/milesan-data"
Sodors = [f'Sodor{i}Stage' for i in [1,3,5]]
# DUTs = ['PicoRV','VexRiscV']
# DUTs = Sodors

#%%
# LOAD MILESAN RESULTS
n_mux = {'vexriscv':628,
        'picorv32':172}
dutname = {
    'vexriscv':'VexRiscV',
    'picorv32': 'PicoRV'
}
milesan = pd.DataFrame()
for p in glob.glob(f'{MILESAN_DATA}/*1000_100.json'):
    if('rocket' in p): continue
    if('boom' in p): continue
    with open(p, 'r') as f:
        d = json.load(f)
    tmp = {}
    times = [sum(d['durations'][0:i]) for i in range(len(d['durations']))]
    for c,t in zip(d['coverage_sequence'],times):
        if(t==-1): continue
        dut = p.split('/')[-1].split('_')[-3]
        tmp['DUT'] = dutname[dut]
        tmp['rel_coverage'] = c/n_mux[dut]
        tmp['timestamp'] = t
        tmp['inst'] = 'milesan'
        pd_dict = pd.DataFrame([tmp])
        milesan = pd.concat([milesan,pd_dict],ignore_index=True)
    
# %%
cpp = pd.DataFrame()
for p in glob.glob(f'{COV_DUMPS}/*/*/*/cov/*',recursive=True):

    splits = p.split('/')
    dut = splits[7]
    inst = splits[8]
    seed = splits[9]
    io = splits[-1].split('.')[-2]        
    with open(p, 'r') as f:
            d = json.load(f)
    coverage = np.array(d['coverage'])
    rel_coverage = np.count_nonzero(coverage)/len(coverage)
    # taints = np.array(d['taints'])
    # rel_taints = np.count_nonzero(taints)/len(taints)
    d['rel_coverage'] = rel_coverage
    # d['rel_taints'] = rel_taints
    d['inst'] = inst
    # d['seed'] = seed
    d['DUT'] = dut
    d['fuzzer'] = 'cpp'
    pd_dict = pd.DataFrame([d])
    cpp = pd.concat([cpp, pd_dict], ignore_index = True)

# cpp = pd.concat([cpp, milesan], ignore_index = True)
DUTs = np.unique(cpp['DUT'])
#%% compute intersections
perf_stats = pd.DataFrame()
for dut in DUTs:
    cond = (cpp['DUT']==dut) & (cpp['inst'] == 'rfuzz') 
    max_rfuzz = max(cpp[cond]['rel_coverage'])
    cond = (cpp['DUT']==dut) & (cpp['inst'] == 'drfuzz') 
    max_drfuzz = max(cpp[cond]['rel_coverage'])
    rel_improvement = (max_drfuzz-max_rfuzz)/max_rfuzz
    print(f"{dut} coverage improvement: {rel_improvement}")

    cond = (cpp['DUT']==dut) & (cpp['inst'] == 'rfuzz')  & (cpp['rel_coverage'] >= max_rfuzz)
    min_tick_rfuzz = min(cpp[cond]['ticks'])
    cond = (cpp['DUT']==dut) & (cpp['inst'] == 'drfuzz')  & (cpp['rel_coverage'] >= max_rfuzz)
    min_tick_drfuzz = min(cpp[cond]['ticks'])
    rel_speedup = (min_tick_rfuzz-min_tick_drfuzz)/min_tick_drfuzz
    print(f"{dut} speedup: {rel_speedup}")

    cond = (cpp['DUT']==dut) & (cpp['inst'] == 'rfuzz')  & (cpp['rel_coverage'] >= max_rfuzz)
    min_tstamp_rfuzz = min(cpp[cond]['timestamp'])
    cond = (cpp['DUT']==dut) & (cpp['inst'] == 'drfuzz')  & (cpp['rel_coverage'] >= max_rfuzz)
    min_tstamp_drfuzz = min(cpp[cond]['timestamp'])
    rel_slowdown = (min_tstamp_drfuzz-min_tstamp_rfuzz)/min_tstamp_rfuzz
    print(f"{dut} slowdown: {rel_slowdown}")

    stat_dict = {
        'DUT':dut,
        'coverage':rel_improvement,
        'speedup':rel_speedup,
        'slowdown':rel_slowdown,
        'ratio':rel_speedup/rel_slowdown,
        'gain':rel_improvement*rel_speedup/rel_slowdown
    }
    perf_stats = pd.concat([perf_stats,pd.DataFrame.from_dict([stat_dict])],ignore_index=True)

fig,ax = plt.subplots(2,2,sharex='col')
fig.set_figheight(10)
fig.set_figwidth(10)
sns.barplot(data=perf_stats,x='DUT',y='coverage',ax=ax[0,0])
sns.lineplot(data=perf_stats,x='DUT',y='coverage',ax=ax[0,0],marker='o', color='k',sort = False)
sns.barplot(data=perf_stats,x='DUT',y='gain',ax=ax[0,1])
sns.lineplot(data=perf_stats,x='DUT',y='gain',ax=ax[0,1],marker='o', color='k',sort = False)
sns.barplot(data=perf_stats,x='DUT',y='speedup',ax=ax[1,0])
sns.lineplot(data=perf_stats,x='DUT',y='speedup',ax=ax[1,0],marker='o', color='k',sort = False)
sns.barplot(data=perf_stats,x='DUT',y='slowdown',ax=ax[1,1])
sns.lineplot(data=perf_stats,x='DUT',y='slowdown',ax=ax[1,1],marker='o', color='k',sort = False)

ax[0,0].tick_params(axis='both', which='major', labelsize=13)
ax[0,1].tick_params(axis='both', which='major', labelsize=13)
ax[1,0].tick_params(axis='both', which='major', labelsize=13)
ax[1,1].tick_params(axis='both', which='major', labelsize=13)

ax[0,0].set_ylabel('Coverage Improvement [1]',fontsize=15)
ax[0,1].set_ylabel('Gain [1]',fontsize=15)
ax[1,0].set_ylabel('Tick Speedup [1]',fontsize=15)
ax[1,1].set_ylabel('Simulation Slowdown [1]',fontsize=15)

ax[0,0].set_xlabel('',fontsize=15)
ax[0,1].set_xlabel('',fontsize=15)
ax[1,0].set_xlabel('DUT',fontsize=15)
ax[1,1].set_xlabel('DUT',fontsize=15)



plt.tight_layout()
# plt.savefig("/cellift-meta/design-processing/common/python_scripts/analysis/plots/parallel/performance.png")


#%% PLATEAU PLOT

fig, ax = plt.subplots(3,sharey='row',sharex='col')
fig.set_figheight(10)
fig.set_figwidth(15)

i = 0
for dut in DUTs:
    sns.lineplot(data=cpp[cpp['DUT']==dut], 
                x='timestamp', 
                y='rel_coverage',
                ax=ax[i], 
                hue='inst')
    ax[i].set_ylabel('coverage [1]',fontsize=15)
    ax[i].set_xlabel('time [s]',fontsize=15)
    ax[2].legend(fontsize=18,loc='best')
    if(i != 2): ax[i].legend().remove()
    ax[i].tick_params(axis='both', which='major', labelsize=13)
    ax[i].set_title(f'{dut}',fontsize=18)
    ax[i].set_ylim([0.8,1])
    ax[i].grid()
    ax[i].axhline(y=max(cpp[(cpp['DUT']==dut) & (cpp['inst']=='rfuzz')]['rel_coverage']), color="dodgerblue", linestyle="--")

    i+=1

    # ax.set_ylim([0,1])

plt.tight_layout()
plt.savefig("/cellift-meta/design-processing/common/python_scripts/analysis/plots/parallel/plateau.png")



# %%
## RFUZZ/DRFUZZ TIME
fig, ax = plt.subplots(2,len(DUTs),sharey='row',sharex='col')
fig.set_figheight(10)
fig.set_figwidth(15)
margin = 0.05

min_y = min([max(cpp[(cpp['DUT']==dut) & (cpp['inst']==inst)]['rel_coverage']) for dut in DUTs for inst in np.unique(cpp['inst'])]) - margin
max_y = max([max(cpp[cpp['DUT']==dut]['rel_coverage']) for dut in DUTs]) + margin
if(max_y > 1): max_y = 1

# xlims = {
#     'PicoRV': [0,1500],
#     'VexRiscV': [0,5000]
# }
i = 0
for dut in DUTs:
    sns.lineplot(data=cpp[cpp['DUT']==dut], 
                x='timestamp', 
                y='rel_coverage',
                ax=ax[0,i], 
                hue='inst')
    ax[0,i].set_ylabel('coverage [1]',fontsize=15)
    ax[0,i].set_xlabel('time [s]',fontsize=15)
    ax[0,0].legend(fontsize=18,loc='best')
    if(i != 0): ax[0,i].legend().remove()
    ax[0,i].tick_params(axis='both', which='major', labelsize=13)
    ax[0,i].set_title(f'{dut}',fontsize=18)
    ax[0,i].set_ylim([0,1])
    ax[0,i].grid()
    i+=1

i = 0
for dut in DUTs:
    sns.lineplot(data=cpp[cpp['DUT']==dut], 
                    x='timestamp', 
                    y='rel_coverage',
                    ax=ax[1,i], 
                    hue='inst')

    ax[1,i].set_ylabel('coverage [1]',fontsize=15)
    ax[1,i].set_xlabel('time [s]',fontsize=15)
    ax[1,i].legend().remove()
    ax[1,i].tick_params(axis='both', which='major', labelsize=13)
    ax[1,i].set_title(f'{dut}',fontsize=18)
    ax[1,i].set_ylim([min_y,max_y])
    # ax[1,i].set_xlim(xlims[dut])
    ax[1,i].grid()
    ax[1,i].axhline(y=max(cpp[(cpp['DUT']==dut) & (cpp['inst']=='drfuzz')]['rel_coverage']), color="dodgerblue", linestyle="--")
    ax[1,i].axhline(y=max(cpp[(cpp['DUT']==dut) & (cpp['inst']=='rfuzz')]['rel_coverage']), color="orange", linestyle="--")
    # ax[1,i].axhline(y=max(cpp[(cpp['DUT']==dut) & (cpp['inst']=='milesan')]['rel_coverage']), color="green", linestyle="--")

    i +=1 
    # ax.set_ylim([0,1])

plt.tight_layout()
# ax.set_ylim([0.9,1])

plt.savefig(f"{MILESAN_DATA}/milesan_drfuzz.png")

#%%

## RFUZZ/DRFUZZ TICKS

fig, ax = plt.subplots(2,len(DUTs),sharey='row',sharex='row')
fig.set_figheight(10)
fig.set_figwidth(15)
i = 0
margin = 0.05
min_y = min([max(cpp[(cpp['DUT']==dut) & (cpp['inst']==inst)]['rel_coverage']) for dut in DUTs for inst in np.unique(cpp['inst'])]) - margin
max_y = max([max(cpp[cpp['DUT']==dut]['rel_coverage']) for dut in DUTs]) + margin
if(max_y > 1): max_y = 1

for dut in DUTs:
    sns.lineplot(data=cpp[cpp['DUT']==dut], 
                x='ticks', 
                y='rel_coverage',
                ax=ax[0,i], 
                hue='inst')
    ax[0,i].set_ylabel('coverage [1]',fontsize=15)
    ax[0,i].set_xlabel('ticks [1]',fontsize=15)
    ax[0,0].legend(fontsize=18,loc='best')
    if(i != 0): ax[0,i].legend().remove()
    ax[0,i].tick_params(axis='both', which='major', labelsize=13)
    ax[0,i].set_title(f'{dut}',fontsize=18)
    ax[0,i].set_ylim([0,1])
    ax[0,i].grid()
    i+=1

i = 0
for dut in DUTs:
    sns.lineplot(data=cpp[cpp['DUT']==dut], 
                    x='ticks', 
                    y='rel_coverage',
                    ax=ax[1,i], 
                    hue='inst')

    ax[1,i].set_ylabel('coverage [1]',fontsize=15)
    ax[1,i].set_xlabel('ticks [1]',fontsize=15)
    ax[1,i].legend().remove()
    ax[1,i].tick_params(axis='both', which='major', labelsize=13)
    ax[1,i].set_title(f'{dut}',fontsize=18)
    ax[1,i].set_ylim([min_y,max_y])
    ax[1,i].grid()
    ax[1,i].axhline(y=max(cpp[(cpp['DUT']==dut) & (cpp['inst']=='drfuzz')]['rel_coverage']), color="dodgerblue", linestyle="--")
    ax[1,i].axhline(y=max(cpp[(cpp['DUT']==dut) & (cpp['inst']=='rfuzz')]['rel_coverage']), color="orange", linestyle="--")

    i +=1 
    # ax.set_ylim([0,1])

plt.tight_layout()
# ax.set_ylim([0.9,1])

# plt.savefig("/cellift-meta/design-processing/common/python_scripts/analysis/plots/parallel/ticks.png")

#%%
## TAINT ANALYSIS
taint_df = pd.DataFrame()
for dut in DUTs:
    for inst in ['drfuzz']:
        for seed in ['seed10']:
            for p in listdir(f'{COV_DUMPS}/{dut}/{inst}/{seed}'):
                with open(path.join(f'{COV_DUMPS}/{dut}/{inst}/{seed}', p), 'r') as f:
                    d = json.load(f)
                coverage = np.array(d['coverage'])
                rel_coverage = np.count_nonzero(coverage)/len(coverage)
                taints = np.array(d['taints'])
                rel_taints = np.count_nonzero(taints)/len(taints)
                d['rel_coverage'] = rel_coverage
                d['rel_taints'] = rel_taints
                d['inst'] = inst
                d['DUT'] = dut
                d['fuzzer'] = 'cpp'
                pd_dict = pd.DataFrame([d])
                taint_df = pd.concat([taint_df, pd_dict], ignore_index = True)

#%%

fig, ax = plt.subplots(3,sharey='row',sharex='row')
fig.set_figheight(10)
fig.set_figwidth(15)

i = 0
for dut in DUTs:
    sns.lineplot(data=taint_df[taint_df['DUT']==dut], 
                x='ticks', 
                y='rel_taints',
                ax=ax[i])
    ax[i].set_ylabel('total taint [1]',fontsize=15)
    ax[i].set_xlabel('ticks [1]',fontsize=15)
    # ax[0,2].legend(fontsize=18,loc='best')
    # if(i != 2): ax[0,i].legend().remove()
    ax[i].tick_params(axis='both', which='major', labelsize=13)
    ax[i].set_title(f'{dut}',fontsize=18)
    ax[i].set_ylim([0,1])
    ax[i].grid()
    i+=1


plt.tight_layout()


# %%
## RUST DATA
PICKLES='/mnt/rfuzz/analysis/backup/pickles_assert/'
rust = pd.DataFrame()
for dut in DUTs:
    for seed in ['seed5','seed10']:
        with open(f'{PICKLES}/{dut}/yosys_opt0_{seed}','rb') as f:
                data = pickle.load(f)
        r_pd= pd.DataFrame({
                            'rel_coverage':data['cov'], 
                            'timestamp':data['disco_times'], 
                            'inst':'rfuzz',
                            'fuzzer':'rust',
                            'seed':seed,
                            'DUT':dut}
                            )
        rust = pd.concat([rust,r_pd])



# sns.lineplot(data=data, x='disco_times', y='cov')
#%%
RUST_CPP_PATH="/mnt/cellift-picorv32/cellift/analysis/plots/rust_cpp"

fig, ax = plt.subplots(2,3,sharey='row',sharex='row')
fig.set_figheight(10)
fig.set_figwidth(15)

all = pd.concat([cpp,rust])
i = 0
# ylims = {'Sodor1Stage':[0.9,1], 'Sodor3Stage':[0.9,1], 'Sodor5Stage':[0.7,0.9]}
for dut in DUTs:
    config = (all['DUT']==dut) & (all['seed']=='seed10') & (all['inst']=='rfuzz')
    sns.lineplot(data=all[config],x='timestamp',y='rel_coverage',hue='fuzzer',ax = ax[0,i])
    ax[0,2].legend(fontsize=18,loc='best')
    if(i != 2): ax[0,i].legend().remove()
    ax[0,i].set_ylabel('coverage [1]',fontsize=15)
    ax[0,i].set_xlabel('time [s]',fontsize=15)
    ax[0,i].tick_params(axis='both', which='major', labelsize=13)
    ax[0,i].set_title(f'{dut}',fontsize=18)
    # ax[0,i].set_xlim([0,400])
    ax[0,i].set_ylim([0,1])
    ax[0,i].grid()

    i+=1
i=0
for dut in DUTs:
    config = (all['DUT']==dut) & (all['seed']=='seed10') & (all['inst']=='rfuzz')
    sns.lineplot(data=all[config],x='timestamp',y='rel_coverage',hue='fuzzer',ax = ax[1,i])
    ax[1,i].legend().remove()
    ax[1,i].set_ylabel('coverage [1]',fontsize=15)
    ax[1,i].set_xlabel('time [s]',fontsize=15)
    ax[1,i].tick_params(axis='both', which='major', labelsize=13)
    ax[1,i].set_title(f'{dut}',fontsize=18)
    # ax[1,i].set_xlim([0,400])
    ax[1,i].set_ylim([0.8,1])
    ax[1,i].grid()
    ax[1,i].axhline(y=max(all[config & (all['fuzzer']=='rust')]['rel_coverage']), color="dodgerblue", linestyle="--")
    ax[1,i].axhline(y=max(all[config & (all['fuzzer']=='cpp')]['rel_coverage']), color="orange", linestyle="--")

    i+=1



plt.tight_layout()

plt.savefig(f'/cellift-meta/design-processing/common/python_scripts/analysis/plots/rust_cpp/cpp_rust.png')
# %%


color_cycle = [color['color'] for color in list(plt.rcParams['axes.prop_cycle'])]
ylimits = {
        'Sodor1Stage': [0.8,1],
        'Sodor3Stage': [0.8, 1],
        'Sodor5Stage': [0.8, 1],
        'TLSPI': [0.2, 0.5],
        'TLI2C': [0.1, 0.4],
        'FFTSmall': [0,1]}
fig, ax = plt.subplots(2,3,sharey='row',sharex='row')
fig.set_figheight(10)
fig.set_figwidth(15)
i = 0
for dut_path in glob.glob(f'{PICKLES}/*'):
    if 'Sodor' not in dut_path: continue
    dut = dut_path.split('/')[-1]
    bs_opts = set(['_'.join(s.split('/')[-1].split('_')[:-1]) for s in glob.glob(f'{dut_path}/*')])
    for bs_opt in bs_opts:
        if 'opt1' in bs_opt: continue
        disco_times, means, stds  = analyse_multi(dut_path,bs_opt,True)
        ax[0,i].plot(disco_times,means,label=bs_opt[:-5])
        ax[0,i].set_title(f'{dut}',fontsize=18)

    ax[0,i].set_ylim([0,1])
    ax[0,0].legend(fontsize=15)
    ax[0,0].set_ylabel('coverage [1]',fontsize=15)
    ax[0,i].set_xlabel('time [s]',fontsize=15)
    ax[0,i].tick_params(axis='both', which='major', labelsize=13)
    ax[0,i].grid()

    i += 1



i = 0
for dut_path in glob.glob(f'{PICKLES}/*'):
    if 'Sodor' not in dut_path: continue
    dut = dut_path.split('/')[-1]
    bs_opts = set(['_'.join(s.split('/')[-1].split('_')[:-1]) for s in glob.glob(f'{dut_path}/*')])
    for bs_opt in bs_opts:
        if 'opt1' in bs_opt: continue
        disco_times, means, stds  = analyse_multi(dut_path,bs_opt,True)
        ax[1,i].plot(disco_times,means,label=bs_opt[:-5])
        ax[1,i].set_title(f'{dut}',fontsize=18)

    ax[1,i].set_ylim(ylimits[dut])
    # ax[1,0].legend(fontsize=15)
    ax[1,0].set_ylabel('coverage [1]',fontsize=15)
    ax[1,i].set_xlabel('time [s]',fontsize=15)
    ax[1,i].tick_params(axis='both', which='major', labelsize=13)
    ax[1,i].grid()
    

    i += 1


plt.tight_layout()


#%%
cpp_interp = pd.DataFrame()
for dut in ['Sodor1Stage']:
    for inst in ['rfuzz','drfuzz']:
        loc = (cpp['inst']==inst) & (cpp['DUT']==dut)
        start_tick = min(cpp[loc]['ticks'])
        for seed in ['seed5','seed7','seed10','seed12']:
            loc =  (cpp['seed']==seed) & (cpp['inst']==inst) & (cpp['DUT']==dut)
            d = cpp[loc].sort_values('ticks')
            ticks = d['ticks']
            covs = d['rel_coverage']
            all_ticks = np.arange(start_tick,max(ticks),1000)
            all_covs = np.interp(all_ticks,ticks,covs)
            print(f"interpolating {seed}")
            for tick,cov in zip(all_ticks,all_covs):
                new_dict = {
                    'DUT':dut,
                    'inst':inst,
                    'seed':seed,
                    'fuzzer':'cpp',
                    'interp_coverage':cov,
                    'ticks':tick
                }
                pd_dict = pd.DataFrame([new_dict])
                cpp_interp = pd.concat([cpp_interp, pd_dict],ignore_index = True)


#%%
## QUEUE ANALYSIS

queues = pd.DataFrame()
for p in glob.glob(f'{COV_DUMPS}/*/*/*/queue/*',recursive=True):

    splits = p.split('/')
    dut = splits[7]
    inst = splits[8]
    seed = splits[9]
    io = splits[-1].split('.')[-2]

    with open(p, 'r') as f:
        d = json.load(f)
    
    if(d['parent'] != 0):
        if('taints' in d):
            taints = np.array(d['taints']).flatten()
            rel_taints = np.count_nonzero(taints)/len(taints)
            d['rel_taints'] = rel_taints


    d['inst'] = inst
    d['seed'] = seed
    d['DUT'] = dut
    d['io'] = io                    
    pd_dict = pd.DataFrame([d])
    queues = pd.concat([queues, pd_dict], ignore_index = True)


#%%


#%%
fig, ax = plt.subplots(len(DUTs),sharey='row')
for dut,i in zip(DUTs,range(len(DUTs))):
    sns.lineplot(data=queues[(queues['io']=='inputs') & (queues['DUT']==dut)], x = 'ticks', y='rel_taints',ax=ax[i],ci=None)
    sns.lineplot(data=cpp[(cpp['DUT']==dut) & (cpp['inst']=='drfuzz')], x = 'ticks', y='rel_coverage',ax=ax[i],hue='inst')
    # ax[i].set_xlim([0,10**6])
fig.set_figheight(10)
fig.set_figwidth(15)

# %%
