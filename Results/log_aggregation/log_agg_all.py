import os
import re
import sys

def find_log_files(directory):
    # Pattern to match log file names
    log_pattern = re.compile(r'remote_exec_(\w+)_(\d+)-(\d+)_(\w+)_24\.log')

    log_files = []

    for file_name in os.listdir(directory):
        match = log_pattern.match(file_name)
        if match:
            day_start = int(match.group(2))
            day_end = int(match.group(3))
            month = match.group(4)
            log_files.append((day_start, day_end, month, file_name))

    # Sort files by starting and ending day
    log_files.sort(key=lambda x: (x[3], x[0], x[1]))

    return [file[3] for file in log_files]

def merge_logs(directory, output_file):
    log_files = find_log_files(directory)

    if not log_files:
        print("No log files found.")
        sys.exit(1)

    with open(output_file, 'w') as outfile:
        for log_file in log_files:
            file_path = os.path.join(directory, log_file)
            print(f"Merging {log_file}...")
            with open(file_path, 'r') as infile:
                outfile.write(f"--- Start of {log_file} ---\n")
                outfile.write(infile.read())
                outfile.write(f"--- End of {log_file} ---\n\n")

    print(f"Logs successfully merged into {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 log_agg_all.py <input_directory> <output_file>")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_file = sys.argv[2]

    merge_logs(input_dir, output_file)
