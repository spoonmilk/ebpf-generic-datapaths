import os
import sys
import time

# first argument: output file, second argument: duration
if len(sys.argv) != 3:
    print("Usage: python cpu_bench.py <output_file> <duration>")
    sys.exit(1)

output_file = sys.argv[1]
duration = sys.argv[2]

# while duration is not reached, loop to increment a variable
start_time = time.time()
output = 0
while time.time() - start_time < float(duration):
    output += 1

# append the output to the output file on a new line
with open(output_file, "a") as f:
    f.write(str(output) + "\n")
