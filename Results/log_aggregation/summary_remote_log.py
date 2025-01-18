import re
from collections import defaultdict
from datetime import datetime
import json
import sys



# COMMAND PER IP PER DATE UNIQUE
def parse_logs(file_path):
    summary = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

    log_pattern = re.compile(
        r"(\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2}\.\d+ - \('([\d\.]+)', \d+\) - (.+)"
    )

    command_split_pattern = re.compile(r'(?:;|&&?|\|\|?)')

    base_command_pattern = re.compile(r'^(\w+)')

    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                date, src_ip, commands_str = match.groups()

                commands = [cmd.strip() for cmd in command_split_pattern.split(commands_str) if cmd.strip()]

                for command in commands:

                    base_command_match = base_command_pattern.match(command)
                    if base_command_match:
                        base_command = base_command_match.group(1)
                        summary[date][src_ip][base_command] += 1

    return summary


def convert_summary_to_json(summary):
    summary_dict = {date: {ip: dict(commands) for ip, commands in ips.items()} for date, ips in summary.items()}
    return summary_dict


if __name__ == "__main__":
    
    if len(sys.argv) != 3:
        print("Usage: python3 script.py <input_log_file> <output_json_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        parsed_data = parse_logs(input_file)
    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
        sys.exit(1)

    summary_json = convert_summary_to_json(parsed_data)

    with open(output_file, "w") as json_file:
        json.dump(summary_json, json_file, indent=4)

    print(f"Summary report saved to:", output_file)

   
