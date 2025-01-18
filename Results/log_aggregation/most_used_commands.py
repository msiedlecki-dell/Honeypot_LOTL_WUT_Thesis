import json
import time
import sys


def load_json(file_name):
    try:

        with open(file_name,"r") as json_file:
            data = json.load(json_file)
            print("JSON loaded successfully.")
            return data

    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
    except json.JSONDecodeError:
        print("Error: The file is not a valid JSON.")

        
def parse_json(data):
    commands = {"test_command" : 1}
    for date, ips_json in data.items():
        for ips, commands_json in ips_json.items():
            for command, count in commands_json.items():
                if command in commands:
                    commands[command] += count
                else:
                    commands[command] = count    
           
    return commands


def save_json(data, file):
    sorted_data = dict(sorted(data.items(), key=lambda item: item[1], reverse=True))
    try:
        # Ensure the data is a dictionary
        if not isinstance(sorted_data, dict):
            raise TypeError("Data must be a dictionary.")

        with open(file, "w") as f:
            json.dump(sorted_data, f, indent=4)
        print(f"Data successfully saved to {file}.")
        
    except FileNotFoundError:
        print(f"Error: The file {file} was not found.")
    except TypeError as e:
        print(f"Error: Invalid data type. {e}")
    except PermissionError:
        print(f"Error: Permission denied when writing to {file}.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 most_used_commands.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    data = load_json(input_file)
    parsed_json = parse_json(data) 
    save_json(parsed_json, output_file)



if __name__ == "__main__":
    main()