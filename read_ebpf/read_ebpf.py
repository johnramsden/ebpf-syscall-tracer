#!/usr/bin/python3

import signal
import sys
import select
import time

def signal_handler(sig, frame):
    """Handle SIGINT (Ctrl+C) to gracefully exit."""
    print("\nExiting...")
    sys.exit(0)

def main():
    # Set up signal handling for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    trace_pipe_path = "/sys/kernel/debug/tracing/trace_pipe"
    output_file_path = "output.txt"

    try:
        with open("/sys/kernel/debug/tracing/buffer_size_kb", "w") as buf_size:
            buf_size.write("1024")  # Set buffer size to 1024 KB
    except PermissionError:
        print("Warning: Unable to adjust kernel buffer size. Run as root for better performance.")

    with open(trace_pipe_path, "r") as trace_pipe, open(output_file_path, "w") as output_file:
        poller = select.poll()
        poller.register(trace_pipe, select.POLLIN)

        line_counter = 0  # Flush every 10 lines

        while True:
            # Poll with 1s timeout
            events = poller.poll(1000)
            if events:
                # Read all from the pipe
                lines = trace_pipe.read().splitlines()
                for line in lines:
                    if "IDSTAG," in line:
                        trace_data = line.split("IDSTAG,", 1)[1].strip()
                        formatted_row = " ".join(trace_data.split(","))
                        output_file.write(formatted_row + " ")

                        line_counter += 1
                        if line_counter % 10 == 0:
                            output_file.flush()

            # Sleep briefly to reduce CPU
            time.sleep(0.1)

if __name__ == "__main__":
    main()
