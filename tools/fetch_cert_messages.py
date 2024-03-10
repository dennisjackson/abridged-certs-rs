import subprocess
from tqdm import tqdm
import os

def call_tstclnt_with_argument(line):
    # Modify the command as needed
    command = ["/Users/djackson/Documents/codebases/dist/Debug/bin/tstclnt","-D", "-h", line.strip()]

    try:
        # Run the command and capture the output
        result = subprocess.run(command, check=True, text=True, capture_output=True)

        # Print the output of the command
        print(f"Output for line '{line.strip()}':\n{result.stdout}")

    except subprocess.CalledProcessError as e:
        # Handle errors, print error message and output (if any)
        print(f"Error for line '{line.strip()}':\n{e.stderr}")

def main():
    # Specify the path to the text file
    txt_file_path = "/Users/djackson/Documents/codebases/abridged-certs/data/tranco-top10k.csv"

    try:
        print("Current Working Directory:", os.getcwd())
        # Open the text file and read lines
        with open(txt_file_path, "r") as file:
            for line in tqdm(file):
                line = line.split(",")[-1]
                call_tstclnt_with_argument(line)
    except FileNotFoundError:
        print(f"Error: File '{txt_file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
