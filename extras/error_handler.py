# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission.

import os
import socket

def check_internet_connection():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

def check_required_files(data_dir, session_dir, required_files):
    missing_files = []
    for file_path in required_files:
        full_path = os.path.join(data_dir, file_path)
        if not os.path.exists(full_path):
            missing_files.append(file_path)
    return missing_files

def check_required_directories(directories):
    missing_dirs = []
    for directory in directories:
        if not os.path.exists(directory):
            missing_dirs.append(directory)
    return missing_dirs

def handle_error(message):
    print(f"[×] Error: {message}")
    exit(1)