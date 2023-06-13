import os

# tmpdir
if "CASCADE_ENV_SOURCED" not in os.environ:
    raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

PATH_TO_TMP = os.path.join(os.environ['CASCADE_DATADIR'], 'python-tmp')

DO_ASSERT = True
DO_EXPENSIVE_ASSERT = False # More expensive assertions

NO_REMOVE_TMPFILES = True # Used for debugging purposes.

RUN_TIMEOUT_SECONDS = 60*60*2 # A program is not supposed to run longer than this in RTL simulation.
