# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# random_headers.py

import random
import json
import os

data_dir = os.path.join(os.getcwd(), 'data')

def load_user_agents():
    ua_file_path = os.path.join(data_dir, 'ua.txt')
    try:
        with open(ua_file_path, 'r') as file:
            user_agents = file.readlines()
        return [ua.strip() for ua in user_agents]
    except FileNotFoundError:
        print(f"Error: {ua_file_path} not found.")
        return []

def load_headers_data():
    headers_file_path = os.path.join(data_dir, 'headers.json')
    try:
        with open(headers_file_path, 'r') as file:
            headers_data = json.load(file)
        return headers_data
    except FileNotFoundError:
        print(f"Error: {headers_file_path} not found.")
        return {}

def generate_random_headers():
    user_agents = load_user_agents()
    headers_data = load_headers_data()

    if not user_agents or not headers_data:
        return {}

    user_agent = random.choice(user_agents)

    headers = {
        "User-Agent": user_agent,
        "Accept": random.choice(headers_data["Accept"]),
        "Accept-Language": random.choice(headers_data["Accept-Language"]),
        "Accept-Encoding": random.choice(headers_data["Accept-Encoding"]),
        "Connection": random.choice(headers_data["Connection"]),
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}", 
        "X-Forwarded-Proto": random.choice(headers_data["X-Forwarded-Proto"])
    }
    
    return headers 