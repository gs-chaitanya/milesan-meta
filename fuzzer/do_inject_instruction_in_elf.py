from drfuzz_mem.inject_instruction_in_elf import inject_instrucion_in_elf
import os, sys

if __name__ == "__main__":
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    if len(sys.argv) < 2:
        raise Exception("Usage: python3 do_fuzz_good_seeds.py <queue>")

    inject_instrucion_in_elf(sys.argv[1])