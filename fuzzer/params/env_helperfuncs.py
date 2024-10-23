import os
# Helper functions for environment variables with default values
def get_env_bool(var_name, default):
    value = bool(int(os.getenv(var_name, default)))
    if var_name in os.environ:
        print(f"Setting {var_name} = {value} from env vars.")
    return value

def get_env_int(var_name, default):
    value = int(os.getenv(var_name, default))
    if var_name in os.environ:
        print(f"Setting {var_name} = {value} from env vars.")
    return value

def get_env_str(var_name, default):
    value = os.getenv(var_name, default)
    if var_name in os.environ:
        print(f"Setting {var_name} = {value} from env vars.")
    return value
