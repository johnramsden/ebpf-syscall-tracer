import csv
import signal
import sys

# Define the headers for the CSV output
headers = [
    "Tag (PE)", "syscall", "PID", "process", "uid", "gid", "ruid", "euid", "suid",
    "rgid", "egid", "sgid", "pathname", "owner", "group", "fd", "mode", "fsuid",
    "fsgid", "flags", "nstype", "op", "addr", "len", "prot", "ptrace_pid", "operation"
]

def signal_handler(sig, frame):
    # print("\nStopping trace reading...")
    sys.exit(0)

# Register the Ctrl+C signal handler
signal.signal(signal.SIGINT, signal_handler)

# Open the trace_pipe file for reading
with open("/sys/kernel/debug/tracing/trace_pipe", "r") as trace_pipe:
    # Print the CSV header
    csv_writer = csv.writer(sys.stdout)
    csv_writer.writerow(headers)

    # Continuously read lines from trace_pipe
    for line in trace_pipe:
        # Find the portion of the line starting with "PE"
        if "PE," in line:
            # Extract the part starting from "PE,"
            trace_data = line.split("PE,", 1)[1].strip()

            # Split the data into CSV fields by commas
            csv_row = ["PE"] + trace_data.split(",")

            # Output the row to CSV
            csv_writer.writerow(csv_row)
