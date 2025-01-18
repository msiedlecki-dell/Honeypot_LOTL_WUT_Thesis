import re
from collections import defaultdict
from datetime import datetime
import json
import sys




# COMMAND LINE UNIQUE PER IP
def parse_logs(file_path):
    summary = defaultdict(int)
    summary_detailed = defaultdict(int)

    # Regex pattern to match the real log structure
    log_pattern = re.compile(
        r"(\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2}\.\d+ - \('([\d\.]+)', \d+\) - (.+)"
    )

    command_split_pattern = re.compile(r'(?:;|&&?|\|\|?)')

    base_command_pattern = re.compile(r'^(\w+)')

    with open(file_path, 'r') as file:
        analyzed = []
        for line in file:
            match = log_pattern.match(line)
            if match:
                date, src_ip, commands_str = match.groups()

                commands = [cmd.strip() for cmd in command_split_pattern.split(commands_str) if cmd.strip()]
                for command in commands:

                    if src_ip + command not in analyzed:
                        print(src_ip+command)
                        analyzed.append(src_ip + command)
                        base_command_match = base_command_pattern.match(command)
                        if base_command_match:
                            base_command = base_command_match.group(1)
                            summary[base_command] += 1
                            summary_detailed[command] += 1

    return summary,summary_detailed




if __name__ == "__main__":
    
    if len(sys.argv) != 3:
        print("Usage: python3 unique_commands_per_ip.py <input_log_file> <output_json_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        parsed_data = parse_logs(input_file)[0]
        parsed_data_detailed = parse_logs(input_file)[1]
    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
        sys.exit(1)


    sorted_data = dict(sorted(parsed_data.items(), key=lambda item: item[1], reverse=True))
    print(sorted_data)
    
    sorted_data_detailed = dict(sorted(parsed_data_detailed.items(), key=lambda item: item[1], reverse=True))
    print(sorted_data_detailed)

    with open(output_file, "w") as json_file:
        json.dump(sorted_data, json_file, indent=4)

    with open("test.json", "w") as json_file:
        json.dump(sorted_data_detailed, json_file, indent=4)    


   
