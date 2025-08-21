import requests, time, uuid

h={"Accept-Language":"ru,en;q=0.9","Cache-Control":"no-cache","Connection":"keep-alive","Origin":"chrome-extension://jddgbeighonaipjikdnfdpiefhoomlae","Pragma":"no-cache","Sec-Fetch-Dest":"empty","Sec-Fetch-Mode":"cors","Sec-Fetch-Site":"none","Sec-Fetch-Storage-Access":"active","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 YaBrowser/25.8.0.0 Safari/537.36","X-Client-Version":"7.15.2","accept":"application/json","content-type":"application/json"}
ip="127.0.0.1"
prox=""
p=None if not prox else {"http":prox,"https":prox}

def req(url, method="POST", headers=None, json=None, proxies=None, delay=0.1):
    time.sleep(delay)
    if method.upper()=="POST":
        return requests.post(url, headers=headers, json=json, proxies=proxies)
    else:
        return requests.get(url, headers=headers, params=json, proxies=proxies)

while True:
    try:
        d=str(uuid.uuid4())
        u=req("https://uubb.website/premium/api/v1/uboost-premium/create-new-user", headers=h, json={"deviceId":d,"deviceIp":ip}, proxies=p).json().get("userId")
        print("newid:",u)
        req("https://uubb.website/premium/api/v1/uboost-premium/setup-tariff", headers=h, json={"userId":u,"deviceId":d,"deviceIp":ip,"tariff":"free_trial"}, proxies=p)
        req("https://uubb.website/api/v2/premium/update-and-get-subscription", headers=h, json={"userId":u,"deviceId":d,"deviceIp":ip}, proxies=p)
        r=req("https://uubb.website/premium/api/v2/uboost-premium/get-proxy", headers=h, json={"userId":u,"deviceId":d,"deviceIp":ip,"with_auth":"false"}, proxies=p).json()
        for x in r.get("proxies",[]):
            if x.get("proxy_type")=="vpn":
                s=f"{x['host']}:{x['port']}"
                print("proxy:",s)
                open("proxies.txt","a",encoding="utf-8").write(s+"\n")
                prox=f"http://{s}";p={"http":prox,"https":prox}
    except Exception as e: print("error:",e)
    time.sleep(0.5)
