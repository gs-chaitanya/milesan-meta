import json
import time
class PerformanceMonitor:
    logfile_path: str
    t_spike: float = 0
    t_insitu: float = 0
    t_rtl: float = 0
    t_validate_insitu: float = 0


    spike_clk : float = 0
    insitu_clk : float = 0
    rtl_clk : float = 0
    validate_insitu_clk : float = 0
    def __init__(self, logfile_path: str) -> None:
        self.logfile_path = logfile_path

    def dump(self):
        with open(self.logfile_path, "w") as f:
            json.dump({
                "t_insitu":self.t_insitu,
                "t_spike": self.t_spike,
                "t_rtl": self.t_rtl,
                "t_validate_insitu": self.t_validate_insitu
            },f)
    
    def print(self):
        print(f"spike: {self.t_spike}")
        print(f"insitu: {self.t_insitu}")
        print(f"rtl: {self.t_rtl}")
        print(f"validate_insitu: {self.t_validate_insitu}")

    
    def start_spike(self):
        assert self.spike_clk == 0
        self.spike_clk = time.time()
    
    def stop_spike(self):
        assert self.spike_clk != 0
        self.t_spike += time.time()-self.spike_clk
        self.spike_clk = 0
    
    def start_insitu(self):
        assert self.insitu_clk == 0
        self.insitu_clk = time.time()
    
    def stop_insitu(self):
        assert self.insitu_clk != 0
        self.t_insitu += time.time()-self.insitu_clk
        self.insitu_clk = 0

    def start_rtl(self):
        assert self.rtl_clk == 0
        self.rtl_clk = time.time()
    
    def stop_rtl(self):
        assert self.rtl_clk != 0
        self.t_rtl += time.time()-self.rtl_clk
        self.rtl_clk = 0
    
    def start_validate_insitu(self):
        assert self.validate_insitu_clk == 0
        self.validate_insitu_clk = time.time()
    
    def stop_insitu(self):
        assert self.validate_insitu_clk != 0
        self.t_validate_insitu += time.time()-self.validate_insitu_clk
        self.validate_insitu_clk = 0



    
