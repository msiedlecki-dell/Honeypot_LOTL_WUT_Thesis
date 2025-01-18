import json



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



def join_json(aggregated, data):

	for ip,json in data.items():

		if ip not in aggregated.keys():
			print(aggregated.keys())
			aggregated[ip] = {
				'geo_lat' : json.get('geo_lat'),
				'geo_lon' : json.get('geo_lon'),
				'count'	  : json.get('count')
			}
		else:
			aggregated[ip]['count'] +=	json.get('count')
			
	return aggregated



def main():
	proxmox = load_json("Proxmox_geo.json")
	madrid = load_json("madrid_geo.json")
	mumbai = load_json("Mumbai_geo.json")
	dallas = load_json("Dallas_geo.json")

	aggregated = dict()

	aggregated = join_json(aggregated,proxmox)
	print("proxmox")
	aggregated = join_json(aggregated,madrid)
	print("madrid")

	aggregated = join_json(aggregated,mumbai)
	print("mumbai")

	aggregated = join_json(aggregated,dallas)

	#print(aggregated)
	save_json(aggregated,"Agg_geo.json")



if __name__ == '__main__':
	main()