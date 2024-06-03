# here, we make exceptions for the mmu there is a lot

'''
PAGE_FAULT:
    - If SUM not set, accessing a user page
    - If MPRV is set and mpp != M, access an unmapped page
    - if priv != M access an unmapped page
    - satp write to change layouts, without generating the exception handler

INSTRUCTION ACCESS FAULT can be triggered by an satp write 

LOAD_PAGE_FAULT can be triggered by addresses that are not mapped with a load

'''