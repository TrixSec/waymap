import os
import socket

# Function to check internet connectivity
def check_internet_connection():
    try:
        # Try to connect to a well-known site (Google DNS)
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

# Function to check if necessary files exist
def check_required_files(data_dir, session_dir, required_files):
    missing_files = []
    for file_path in required_files:
        full_path = os.path.join(data_dir, file_path)
        if not os.path.exists(full_path):
            missing_files.append(file_path)
    return missing_files

# Function to check if required directories exist
def check_required_directories(directories):
    missing_dirs = []
    for directory in directories:
        if not os.path.exists(directory):
            missing_dirs.append(directory)
    return missing_dirs

# Function to handle error messages
def handle_error(message):
    print(f"[×] Error: {message}")
    exit(1)