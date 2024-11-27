#!/usr/bin/python3

import signal
import sys
import select
import time

def signal_handler(sig, frame):
    sys.exit(0)

def main():
    # Ctrl+C signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Open the trace_pipe file for reading and a plain text file for writing
    with open("/sys/kernel/debug/tracing/trace_pipe", "r") as trace_pipe, open("output.txt", "w") as output_file:
        while True:
            # Wait for data to become available, 1s timeout
            ready, _, _ = select.select([trace_pipe], [], [], 1.0)
            if ready:
                line = trace_pipe.readline().strip()
                if not line:  # EOF or no data
                    time.sleep(0.1)
                    continue

                if "IDSTAG," in line:

                    # Extract the part starting from "IDSTAG,"
                    trace_data = line.split("IDSTAG,", 1)[1].strip()

                    # Format the row as a single line with spaces between entries
                    formatted_row = " ".join(trace_data.split(","))

                    # Write the formatted row to the output file
                    output_file.write(formatted_row + " ")
                    output_file.flush()

if __name__ == "__main__":
    main()
