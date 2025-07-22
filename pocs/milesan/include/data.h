#ifdef NODATA
  #padding
  .rep 8
  .dword 0x0
  .endr
#else
// this is the data section for user data
.section .data , "adw"
data:
  .dword 0xffffffffffffffff
  .dword 0x000000000fffffff
  .dword 0xcacacafedeadbeef
  .dword 0xcacacafedeadbeef
  .dword 0xcacacafedeadbeef
  .dword 0xcacacafedeadbeef
  .dword 0xcacacafedeadbeef
  .dword 0xcacacafedeadbeef
#endif
