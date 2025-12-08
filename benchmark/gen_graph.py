import matplotlib.pyplot as plt
import json
import os
import numpy as np
import numpy.typing as npt
NDArray = npt.NDArray[np.float64]


# User-defined options
target_server = "bokaibi.com" # server running iperf3 in server mode
target_port = 5142            # iperf3 server port
total_seconds = 30            # total time to run iperf3
report_interval = 0.1         # report interval for iperf3
ccas = ["cubic", "bpf_cubic", "ebpfccp", "ccp"] # list of CCAs to benchmark, must all be registered
trials = 10                   # amount of trials to average performance over
y_unit = "bytes"              
use_sum = True
# End of user-defined options
                

class Result:
    def __init__(self, x_arr: NDArray, y_arr: NDArray, cca: str):
        self.x_arr = x_arr
        self.y_arr = y_arr
        self.cca = cca

y_units = ["snd_cwnd", "bytes", "bits_per_second", "retransmits", "rtt"]

def get_xy_array(intervals: list[dict], y_unit: str, use_sum: bool) -> tuple[NDArray, NDArray]:
    # get x&y array from intervals data given, takes 1 json file
    if y_unit not in y_units:
        print("Invalid y_unit")
        return
    if y_unit == "rtt" and use_sum:
        print("Cannot use sum for rtt")
        return
    
    x_arr = np.empty(len(intervals))
    y_arr = np.empty(len(intervals))
    for ind, interval in enumerate(intervals):
        if use_sum:
            analyzed_unit = "sum"
            x = interval[analyzed_unit]["start"]
            y = interval[analyzed_unit][y_unit]
        else:
            analyzed_unit = "streams"
            x = interval[analyzed_unit][0]["start"]
            y = interval[analyzed_unit][0][y_unit]
        x_arr[ind] = x
        y_arr[ind] = y
    
    return (x_arr, y_arr)

mode = input('''Choose mode:
1. Delete all .json files in the current directory and rerun benchmark
2. Process existing .json files and generate graph
>>''')

if mode == "1":
    # Delete all .json files in the current directory
    for file in os.listdir(os.getcwd()):
        if file.endswith(".json") or file.endswith("_cpu_perf"):
            os.remove(file)
    print("Deleted all .json files in the current directory")

    # run benchmark
    print("Running the benchmark for the following CCAs: ", ccas)
    print(f"Parameters: target_server={target_server}, target_port={target_port}, total_seconds={total_seconds}, report_interval={report_interval}, trials={trials}")
    default_waittime = 5
    print(f"Expected run time: {trials * (total_seconds + default_waittime) * len(ccas)}")
    for t in range(trials):
        for cca in ccas:
            os.system(f"sudo bash benchmark.sh {target_server} {target_port} {total_seconds} {report_interval} {cca} {t+1}")
else:
    print(f"Data processing options: y_unit={y_unit}, use_sum={use_sum}")
    results = []
    perf_results = {}
    for cca in ccas:
        # process each json file for each cca
        cca_xs = []
        cca_ys = []
        total_cpu_perf = 0
        for trial in range(1, trials+1):
            file = os.path.join(os.getcwd(), f"{cca}_{trial}.json")
            try:
                with open(file, "r") as f:
                    data = json.load(f)
                    intervals = data["intervals"]
                    (xs, ys) = get_xy_array(intervals, y_unit, use_sum)
                    cca_xs.append(xs)
                    cca_ys.append(ys)
            except FileNotFoundError:
                print(f"File {file} not found")
                continue
            cpu_perf_file = os.path.join(os.getcwd(), f"{cca}_{trial}_cpu_perf")
            try:
                with open(cpu_perf_file, "r") as f:
                    cpu_perf = int(f.read())
                    total_cpu_perf += cpu_perf
            except FileNotFoundError:
                print(f"File {cpu_perf_file} not found")
                continue
            except ValueError:
                print(f"Invalid value in {cpu_perf_file}")
                continue
        max_len = len(max(cca_xs, key=len))
        print(max_len)
        def pad_length(arr: NDArray) -> NDArray:
            after = np.pad(arr, (0, max_len - len(arr)), constant_values=arr[-1])
            print(f"Before: {arr.shape}, after: {after.shape}")
            return after
        cca_xs = np.array(list(map(pad_length, cca_xs)))
        cca_ys = np.array(list(map(pad_length, cca_ys)))
        average_xs = np.mean(cca_xs, axis=0)
        prev = 0
        for x in average_xs:
            if x < prev:
                print(f"Decrease detected: prev: {prev}, curr: {x}")
            prev = x
        average_ys = np.mean(cca_ys, axis=0)
        results.append(Result(average_xs, average_ys, cca))
        perf_results[cca] = total_cpu_perf / trials

    # Plot the graph
    for result in results:
        plt.plot(result.x_arr, result.y_arr, label=result.cca)
    plt.autoscale(enable=True, axis="x")
    plt.xlabel("Time (s)")
    plt.ylabel(y_unit)
    plt.legend(title = "CCA:")
    plt.title(f"CCA Network Behavior")
    plt.savefig("CCA_Behavior.png")

    plt.clf()
    # Plot performance as bar graph
    plt.bar(perf_results.keys(), perf_results.values())
    plt.xlabel("CCA")
    plt.ylabel("CPU Performance (average Python additions)")
    plt.savefig("CCA_Performance.png")

                

