import os
import re

# Fixed directory
target_path = "/Users/jingnan/Desktop/authguard-ai/dataset"

if not os.path.exists(target_path):
    print(f"Directory does not exist: {target_path}")
    exit(1)

base_name = input("Please enter the base name for the files (e.g., 'file'): ")
count = int(input("How many file"))

# Find existing files and get highest number
existing_numbers = []

pattern = re.compile(rf"^{re.escape(base_name)}_(\d+)\.js$")

for file in os.listdir(target_path):
    match = pattern.match(file)
    if match:
        existing_numbers.append(int(match.group(1)))

# Determine starting number
start_number = max(existing_numbers) + 1 if existing_numbers else 1

# Create new files
for i in range(count):
    number = start_number + i
    file_name = f"{base_name}_{number}.js"
    full_path = os.path.join(target_path, file_name)

    with open(full_path, "w") as f:
        f.write(f"/* {""} */")

    print(f"Created: {full_path}")

print("Done!")