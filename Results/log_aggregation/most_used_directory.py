import re
from collections import defaultdict
from datetime import datetime
import json
import sys




def parse_logs(file_path):
    summary = defaultdict(lambda: defaultdict(int))
    summary_with_dates = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    summary_global = defaultdict(int)
    log_pattern = re.compile(
        r"(\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2}\.\d+ - \('([\d\.]+)', \d+\) - (.+)"
    )
    command_split_pattern = re.compile(r'(?:;|&&?|\|\|?)')
    base_command_pattern = re.compile(r'^(\w+)')
    directory_pattern = re.compile(r'(\/(?:[a-zA-Z0-9._-]+\/?)*)')

    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                date, src_ip, commands_str = match.groups()

                commands = [cmd.strip() for cmd in command_split_pattern.split(commands_str) if cmd.strip()]

                for command in commands:
                    directories = directory_pattern.findall(command)
                    for directory in directories:
                        if directory.startswith('/'):  # Ensure it's a valid path
                            summary[src_ip][f"{directory}"] += 1
                            summary_with_dates[date][src_ip][f"{directory}"] += 1
                            summary_global[f"{directory}"] += 1

    return summary, summary_with_dates, summary_global



def parse_logs_per_src_ip(file_path):
    summary = defaultdict(int)

    log_pattern = re.compile(
        r"(\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2}\.\d+ - \('([\d\.]+)', \d+\) - (.+)"
    )
    command_split_pattern = re.compile(r'(?:;|&&?|\|\|?)')
    base_command_pattern = re.compile(r'^(\w+)')
    directory_pattern = re.compile(r'(\/(?:[a-zA-Z0-9._-]+\/?)*)')



    with open(file_path, 'r') as file:
        analyzed = []
        for line in file:
            match = log_pattern.match(line)
            if match:
                date, src_ip, commands_str = match.groups()

                # Split commands by delimiters
                commands = [cmd.strip() for cmd in command_split_pattern.split(commands_str) if cmd.strip()]

                for command in commands:
                    if src_ip+command not in analyzed:
                        analyzed.append(src_ip+command)
                        directories = directory_pattern.findall(command)
                        for directory in directories:
                            if directory.startswith('/'):  # Ensure it's a valid path
                                summary[f"{directory}"] += 1

    return summary



 #Converts a nested defaultdict to a regular dictionary and formats it as JSON.
def convert_to_json(summary):

    def default_to_regular(d):
        if isinstance(d, defaultdict):
            return {k: default_to_regular(v) for k, v in d.items()}
        else:
            return d

    regular_dict = default_to_regular(summary)
    return json.dumps(regular_dict, indent=4)



def save_json(data, file):
    
    if file.endswith("global.json"):    
        data = dict(sorted(data.items(), key=lambda item: item[1], reverse=True))
     
    try:
        # Ensure the data is a dictionary
        if not isinstance(data, dict):
            raise TypeError("Data must be a dictionary.")

        
        with open(file, "w") as f:
            json.dump(data, f, indent=4)
        print(f"Data successfully saved to {file}.")
        
    except FileNotFoundError:
        print(f"Error: The file {file} was not found.")
    except TypeError as e:
        print(f"Error: Invalid data type. {e}")
    except PermissionError:
        print(f"Error: Permission denied when writing to {file}.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    
    if len(sys.argv) != 3:
        print("Usage: python3 most_used_directory.py <input_log_file> <output_json_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Parse the logs
    try:
        parsed_data, parsed_data_with_dates, parsed_data_global = parse_logs(input_file)
        parsed_per_src_ip = parse_logs_per_src_ip(input_file)
    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
        sys.exit(1)

    json_result = convert_to_json(parsed_data)
    print(json_result)


    json_result_with_dates = convert_to_json(parsed_data_with_dates)
    print( json_result_with_dates)

    json_result_global = convert_to_json(parsed_data_global)
    print(json_result_global)


    sorted_data = dict(sorted(parsed_per_src_ip.items(), key=lambda item: item[1], reverse=True))

    output_file_per_src_ip = output_file.split(".json")[0] + "_per_src_ip.json" 
    save_json(sorted_data, output_file_per_src_ip)


    save_json(parsed_data, output_file)
    output_file_dates = output_file.split(".json")[0] + "_dates.json" 
    save_json(parsed_data_with_dates, output_file_dates)


    output_file_global = output_file.split(".json")[0] + "_global.json"
    save_json(parsed_data_global, output_file_global)
