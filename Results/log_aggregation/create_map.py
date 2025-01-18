import matplotlib.pyplot as plt
import cartopy.crs as ccrs
import cartopy.feature as cfeature
import sys
import json
import time


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


def get_coordinates(data):
    coordinates = []
    for ips in data:
        lat = data[ips].get('geo_lat')
        lon = data[ips].get('geo_lon')
        count = data[ips].get('count', 1)  # Default to 1 if missing
        if lat is not None and lon is not None:
            coordinates.append((lat, lon, count))
    return coordinates



def main():
    
    if len(sys.argv) != 3:
        print("Usage: python3 create_map.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    data = load_json(input_file)

    coordinates = get_coordinates(data)

    fig, ax = plt.subplots(figsize=(12, 6), subplot_kw={"projection": ccrs.PlateCarree()})
    ax.set_global()

    ax.add_feature(cfeature.LAND, edgecolor='black')
    ax.add_feature(cfeature.COASTLINE)
    ax.add_feature(cfeature.BORDERS, linestyle=':')



    for lat, lon, count in coordinates:
    # Set minimum size to 500 and adjust scaling
        marker_size = max(300, min(count * 10, 2000))  # Min size: 500, Max size: 2000
        
        # Plot markers with edge customization
        ax.scatter(
            lon, lat, 
            s=marker_size,       
            c='red',             
            edgecolor='black',   
            linewidths=2,        
            alpha=0.7, 
            transform=ccrs.PlateCarree()
        )


    plt.savefig(output_file, dpi=200, bbox_inches='tight')
    print(f"Map saved as {output_file}")

if __name__ == "__main__":
    main()


