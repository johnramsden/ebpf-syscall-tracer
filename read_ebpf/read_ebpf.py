import signal
import sys

# Define the signal handler for graceful termination
def signal_handler(sig, frame):
    sys.exit(0)

# Register the Ctrl+C signal handler
signal.signal(signal.SIGINT, signal_handler)

# Open the trace_pipe file for reading and a plain text file for writing
with open("/sys/kernel/debug/tracing/trace_pipe", "r") as trace_pipe, open("output.txt", "w") as output_file:
    # Continuously read lines from trace_pipe
    for line in trace_pipe:
        # Find the portion of the line starting with "PE"
        if "IDSTAG," in line:
            if "sudo" in line or "sshd" in line:
                continue
            # Extract the part starting from "PE,"
            trace_data = line.split("IDSTAG,", 1)[1].strip()

            # Format the row as a single line with spaces between entries
            formatted_row = " ".join(trace_data.split(","))

            # Write the formatted row to the output file
            output_file.write(formatted_row + " ")
