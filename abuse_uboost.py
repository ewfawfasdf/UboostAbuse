import requests
import time
import uuid
import os
import re

session = requests.Session()
session.headers.update({
    "User-Agent": "uboost-android/1.1.1.31",
    "X-Device-Id": str(uuid.uuid4()),
    "Accept": "application/json",
    "Accept-Charset": "UTF-8",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
})

MAIL_API = "https://api.mail.tm"

if not os.path.exists("keys"):
    os.makedirs("keys")


def create_temp_email():
    domain = requests.get(f"{MAIL_API}/domains").json()['hydra:member'][0]['domain']
    email = f"{uuid.uuid4().hex[:10]}@{domain}"
    password = "password123"

    acc_resp = requests.post(f"{MAIL_API}/accounts", json={"address": email, "password": password})
    if acc_resp.status_code != 201:
        return None, None

    token_resp = requests.post(f"{MAIL_API}/token", json={"address": email, "password": password})
    if token_resp.status_code != 200:
        return None, None

    return email, token_resp.json()["token"]


def get_latest_code(token):
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(30):
        resp = requests.get(f"{MAIL_API}/messages", headers=headers).json()
        if resp["hydra:member"]:
            msg = requests.get(f"{MAIL_API}/messages/{resp['hydra:member'][0]['id']}", headers=headers).json()
            code = re.search(r'\b\d{4}\b', msg["text"])
            if code:
                print(f"[+] Код получен: {code.group(0)}")
                return code.group(0)
        time.sleep(2)
    return None


def request_email_verification(email):
    url = f"https://api.ubstv.click/api/v1/auth/request_email_verification/?reason=mobile_request&email={email}"
    try:
        return session.get(url, timeout=10).json()
    except:
        return None


def submit_mobile_request(email, otp_code):
    url = "https://api.ubstv.click/api/v1/mobile_request/"
    data = {"email": email, "otp_code": otp_code}
    try:
        return session.post(url, json=data, timeout=10).json()
    except:
        return None


def download_mobile_request_key(public_request_id):
    url = f"https://api.ubstv.click/api/v1/wg_keys/download_mobile_request_key?type_key=uboost_vpn&public_request_id={public_request_id}"
    try:
        for _ in range(10):
            resp = session.get(url, timeout=10)
            if resp.status_code == 200 and resp.text.strip():
                return resp.text
            time.sleep(2)
    except:
        return None
    return None


def get_next_key_index():
    files = [f for f in os.listdir("keys") if f.startswith("key") and f.endswith(".conf")]
    nums = [int(re.search(r'key(\d+)\.conf', f).group(1)) for f in files if re.search(r'key(\d+)\.conf', f)]
    return max(nums, default=0) + 1


if __name__ == "__main__":
    while True:
        try:
            email, token = create_temp_email()
            if not email:
                print("[err] mail error")
                continue

            print(f"[+] Почта создана: {email}")

            request_email_verification(email)
            code = get_latest_code(token)
            if not code:
                print("[err] Код не получен")
                continue

            result = submit_mobile_request(email, code)
            if result and "data" in result and "request" in result["data"]:
                req_id = result["data"]["request"].get("public_request_id")
                if req_id:
                    key = download_mobile_request_key(req_id)
                    if key:
                        # Убираем пробел в начале
                        key = key.lstrip()

                        # Добавляем пустую строку перед [Peer]
                        key = re.sub(r"(\[Interface\][^\[]+)(\[Peer\])", r"\1\n\2", key, flags=re.S)

                        idx = get_next_key_index()
                        with open(f"keys/key{idx}.conf", "w") as f:
                            f.write(key)

                        print(f"[+] Сохранён: keys/key{idx}.conf")
                        time.sleep(6)
                        continue

            print("[err] fail")
        except Exception as e:
            print(f"[err] exception: {e}")
            continue
