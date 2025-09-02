#!/bin/bash
mkdir plots tables
python analysis_perf.py $1
python analysis_TTE_ct.py $1
python analysis_TTE_trans.py $1
