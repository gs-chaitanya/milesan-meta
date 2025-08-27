
import numpy as np

def s_to_cpuh(s):
    return f"{int(s//3600)}h{int((s%3600)//60)}m"

def compute_min_tte(x):
    return  min(x["tte"])

def compute_median_tte(x):
    return np.median(x["tte"])


def compute_mean_tte(x):
    return np.mean(x["tte"])

def compute_stddev_tte(x):
    return np.std(x["tte"])

def compute_min_tte(x):
    return np.std(x["tte"])

def compute_stddev_acc(x):
    stddev = np.std(x["tte"])
    return s_to_cpuh(stddev)