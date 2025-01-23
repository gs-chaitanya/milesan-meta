# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import PATH_TO_TMP

import json
import os
import matplotlib.pyplot as plt
import numpy as np

# Number of coverage points per design. Manually collected from the instrumented designs.
NUM_COVERAGE_POINTS = {
    'picorv32': 172,
    'kronos': 178,
    'vexriscv': 634,
    'rocket': 2265,
    'boom': 7752,
}

DESIGN_PRETTY_NAMES = {
    'picorv32': 'PicoRV32',
    'kronos': 'Kronos',
    'vexriscv': 'VexRiscv',
    'rocket': 'Rocket',
    'boom': 'BOOM',
}

X_MAX_SECONDS = 100
X_SECONDS_AFTER_RFUZZ_END = None

assert X_SECONDS_AFTER_RFUZZ_END is None or X_MAX_SECONDS is None

# Display the perftuples as stacked bars
def plot_rfuzz(active_rfuzz_coverage_path_per_design: dict, passive_rfuzz_coverage_path_per_design: dict):

    design_names = list(NUM_COVERAGE_POINTS.keys())
    ignored_design_names = set()

    # Load the coverage data and durations
    coverage_durations_dicts = {}
    for design_name in design_names:
        json_path = active_rfuzz_coverage_path_per_design[design_name]
        if not os.path.exists(json_path):
            print(f"Warning: Skipping design {design_name}. File `{json_path}` does not exist.")
            ignored_design_names.add(design_name)
        else:
            with open(json_path, 'r') as f:
                coverage_durations_dicts[design_name] = json.load(f)

    # Load the coverage data and durations for milesan on rfuzz coverage
    coverage_durations_dicts_milesan = {}
    for design_name in design_names:
        json_path = passive_rfuzz_coverage_path_per_design[design_name]
        if not os.path.exists(json_path):
            print(f"Warning: Skipping design {design_name}. File `{json_path}` does not exist.")
            ignored_design_names.add(design_name)
        else:
            with open(json_path, 'r') as f:
                coverage_durations_dicts_milesan[design_name] = json.load(f)

    # Remove absent design names
    for design_name in ignored_design_names:
        design_names.remove(design_name)

    coverage_dict = {design_name: 100*np.array(coverage_durations_dicts[design_name]['coverage_sequence'])/NUM_COVERAGE_POINTS[design_name] for design_name in design_names}
    durations_seconds_dict = {design_name: np.array(coverage_durations_dicts[design_name]['durations']) for design_name in design_names}

    coverage_dict_milesan = {design_name: 100*np.array(coverage_durations_dicts_milesan[design_name]['coverage_sequence'])/NUM_COVERAGE_POINTS[design_name] for design_name in design_names}
    durations_seconds_dict_milesan = {design_name: np.array(coverage_durations_dicts_milesan[design_name]['durations']) for design_name in design_names}

    # Cumulative sum of durations
    durations_seconds_dict_cumsum_milesan = {design_name: [sum(durations_seconds_dict_milesan[design_name][0:id_in_tuple]) for id_in_tuple in range(len(durations_seconds_dict_milesan[design_name]))] for design_name in durations_seconds_dict.keys()}

    fig, axs = plt.subplots(len(design_names), 1, figsize=(7, 6), sharex=True)

    for i, ax in enumerate(axs):
        design_name = design_names[i]
        X = durations_seconds_dict[design_name]
        Y = np.array(coverage_dict[design_name])
        X_milesan = durations_seconds_dict_cumsum_milesan[design_name]
        Y_milesan = np.array(coverage_dict_milesan[design_name])

        # Truncate after X_SECONDS_AFTER_RFUZZ_END more
        if X_SECONDS_AFTER_RFUZZ_END is not None:
            for j, x in enumerate(X_milesan):
                if x > X[-1] + X_SECONDS_AFTER_RFUZZ_END:
                    X_milesan = X_milesan[:j+1]
                    Y_milesan = Y_milesan[:j+1]
                    break
        if X_MAX_SECONDS is not None:
            ax.set_xlim(0, X_MAX_SECONDS)
            for j, x in enumerate(X_milesan):
                if x > X_MAX_SECONDS:
                    X_milesan = X_milesan[:j+1]
                    Y_milesan = Y_milesan[:j+1]
                    break

        # Extend X and Y to the max of X_milesan
        X = np.append(X, X_milesan[-1])
        Y = np.append(Y, Y[-1])

        ax.plot(X_milesan, Y_milesan, zorder=3, color='k', label='Cascade')
        ax.plot(X, Y, zorder=3, color='red', label='RFUZZ')
        ax.set_title(f"{DESIGN_PRETTY_NAMES[design_name]} ({NUM_COVERAGE_POINTS[design_name]} coverage points)")
        ax.grid(zorder=0)

        ax.set_ylim(0, 100)

        ax.set_ylabel(' ')
        ax.legend(framealpha=1, loc='center right')
    # fig.y_label('Coverage points (%)')
    fig.text(0, 0.5, 'Coverage points (%)', va='center', rotation='vertical')

    ax.set_xlabel('Time (seconds)')
    fig.tight_layout()

    # Display the plot
    print('Saving figure to', os.path.join(PATH_TO_TMP, 'rfuzz.png'))
    plt.savefig(os.path.join(PATH_TO_TMP, 'rfuzz.png'), dpi=300)
