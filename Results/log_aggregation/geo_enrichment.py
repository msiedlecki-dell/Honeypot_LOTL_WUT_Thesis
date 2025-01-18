from ip2geotools.databases.noncommercial import DbIpCity
import sys 
import json
import requests
import time


def get_coordinates(ip):
    try:
        info = requests.get("http://ip-api.com/json/"+ip)
        return info.json()
    except Exception as e:
        print(f"Error during gathering data for IP {ip}: {e}")
        return None


def geo_enrichment(data):
    data_enriched = {}

    for ip, count in data.items():
        enrichment = get_coordinates(ip)
        print(enrichment)
        data_enriched[ip] = {
            "count" : count,
            "geo_lat" : enrichment["lat"],
            "geo_lon" : enrichment["lon"],
            "infor" : enrichment
        }
        time.sleep(2)

    return data_enriched

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


def save_json(data, file):
    try:
        # Ensure the data is a dictionary
        if not isinstance(data, dict):
            raise TypeError("Data must be a dictionary.")

        # Save to file
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


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 geo_enrichment.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    data = load_json(input_file)

    enriched_data = geo_enrichment(data)
    
    save_json(enriched_data, output_file)

if __name__ == "__main__":
    main()