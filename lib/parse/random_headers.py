# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Random HTTP Headers Generator."""

import os
import json
import random
from typing import Dict, List

from lib.core.config import get_config
from lib.core.logger import get_logger

config = get_config()
logger = get_logger(__name__)

def load_user_agents() -> List[str]:
    """Load user agents from file."""
    ua_file_path = os.path.join(config.DATA_DIR, 'ua.txt')
    try:
        with open(ua_file_path, 'r') as file:
            user_agents = file.readlines()
        return [ua.strip() for ua in user_agents if ua.strip()]
    except FileNotFoundError:
        logger.error(f"User agents file not found: {ua_file_path}")
        return ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]

def load_headers_data() -> Dict:
    """Load headers data from JSON file."""
    headers_file_path = os.path.join(config.DATA_DIR, 'headers.json')
    try:
        with open(headers_file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        logger.error(f"Headers file not found: {headers_file_path}")
        return {
            "Accept": ["*/*"],
            "Accept-Language": ["en-US,en;q=0.9"],
            "Accept-Encoding": ["gzip, deflate"],
            "Connection": ["keep-alive"],
            "X-Forwarded-Proto": ["https"]
        }

def generate_random_headers() -> Dict[str, str]:
    """Generate random HTTP headers for requests."""
    user_agents = load_user_agents()
    headers_data = load_headers_data()

    if not user_agents or not headers_data:
        return {"User-Agent": "Mozilla/5.0"}

    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept": random.choice(headers_data.get("Accept", ["*/*"])),
        "Accept-Language": random.choice(headers_data.get("Accept-Language", ["en-US"])),
        "Accept-Encoding": random.choice(headers_data.get("Accept-Encoding", ["gzip"])),
        "Connection": random.choice(headers_data.get("Connection", ["keep-alive"])),
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "X-Forwarded-Proto": random.choice(headers_data.get("X-Forwarded-Proto", ["https"]))
    }
    
    return headers