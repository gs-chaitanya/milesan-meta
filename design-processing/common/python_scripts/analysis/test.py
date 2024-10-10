#%%
from copy import copy
def find_elem(a):
    right_bound = len(a)//2
    left_bound = 0
    while left_bound < right_bound:
        a_test = copy(a)
        for _ in range(right_bound, len(a_test)): # start with right side so the left bound does not change
            del a_test[-1]
        for _ in range(0, left_bound):
            del a_test[0]
        delta = right_bound - left_bound
        if sum(a_test) == 1: # gadget is between [left_bound, right_bound). Move left bound up
            right_bound = left_bound + delta//2
        else: # gadget is in [right_bound, right_bound+(left_bound-right_bound+1)/2)
            left_bound = right_bound
            right_bound =  left_bound + (delta+1)//2
        print(f"[{left_bound},{right_bound})")
    assert a[left_bound] == 1, f"{left_bound},{a}"
    return left_bound, right_bound
#%%
def find_elems(a):
    right_bound = len(a)//2
    left_bound = 0
    while left_bound < right_bound:
        a_test = copy(a)
        for _ in range(right_bound, len(a_test)): # start with right side so the left bound does not change
            del a_test[-1]
        for _ in range(0, left_bound):
            del a_test[0]
        delta = right_bound - left_bound
        if sum(a_test) == 1: # gadget is between [left_bound, right_bound). Move left bound up
            right_bound = left_bound + delta//2
        else: # gadget is in [right_bound, right_bound+(left_bound-right_bound+1)/2)
            left_bound = right_bound
            right_bound =  left_bound + (delta+1)//2
        print(f"[{left_bound},{right_bound})")
    assert a[left_bound] == 1, f"{left_bound},{a}"
    return left_bound, right_bound# %%
