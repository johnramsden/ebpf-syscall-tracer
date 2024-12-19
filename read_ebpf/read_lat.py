#!/usr/bin/python3

import signal
import sys
import time
import csv

def signal_handler(sig, frame):
    """Handle SIGINT (Ctrl+C) to gracefully exit."""
    print("\nExiting...")
    sys.exit(0)

def main():
    # Set up signal handling for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    trace_pipe_path = "/sys/kernel/debug/tracing/trace_pipe"

    num_traces = 10000

    opens = []

    with open(trace_pipe_path, "r") as trace_pipe:
        time.sleep(2)

        while True:
            test_file = f"/tmp/test"

            # Open the file to trigger the eBPF program
            with open(test_file, 'w') as f:
                start = time.time_ns()

            # Read one line at a time
            line = trace_pipe.readline().strip()
            if line and "READMETRIC" in line:
                end = time.time_ns()
                duration_ms = (end - start) / 1_000_000

                opens.append(duration_ms)
                if len(opens) >= num_traces:
                    break

    print(f"AVG={sum(opens)/num_traces}")

    with open('latency.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['latency'])  # Write header
        writer.writerows([[x] for x in opens])

if __name__ == "__main__":
    main()
