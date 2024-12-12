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

    try:
        with open("/sys/kernel/debug/tracing/buffer_size_kb", "w") as buf_size:
            buf_size.write("1024")  # Set buffer size to 1024 KB
    except PermissionError:
        print("Warning: Unable to adjust kernel buffer size. Run as root for better performance.")

    with open(trace_pipe_path, "r") as trace_pipe:
        poller = select.poll()
        poller.register(trace_pipe, select.POLLIN)

        has_opened = False

        while True:
            # Create test file with timestamp name
            start = time.time_ns()
            test_file = f"/tmp/test_{start}"

            if not has_opened:
                # Open the file to trigger the eBPF program
                with open(test_file, 'w') as f:
                    pass
                has_opened = True

            # Poll with tiny timeout
            events = poller.poll(1)
            if events:
                # Read all from the pipe
                lines = trace_pipe.read().splitlines()
                for line in lines:

                    if start in line:
                        has_opened = False

                        end = time.time_ns()

                        duration_ms = (end - start) / 1_000_000
                        print(f"Read {test_file} metric took {duration_ms:.3f} milliseconds")
                        print(line)

if __name__ == "__main__":
    main()
