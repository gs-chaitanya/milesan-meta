#!/bin/bash
python fuzz_and_reduce.py fuzzconfigs/trans-tte-boom.json # TTE plot of BOOM
python fuzz_and_reduce.py fuzzconfigs/ct-violations-tte-openc910.json # TTE plot for OpenC910
python fuzz_and_reduce.py fuzzconfigs/ct-violations-tte-cva6.json # TTE plot for CVA6
python fuzz_and_reduce.py fuzzconfigs/throughput.json # fuzzing throuput plot
python fuzz_and_reduce.py fuzzconfigs/reduction-perf.json # reduction component-wise performance
