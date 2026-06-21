from flask import Flask, request, jsonify
import requests
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

GATEWAY_API_KEY = "hdhxhs827dhsb"

DEPSEARCH_TOKEN = "WDTHx2vqZGE38gchBe7oAewzB9ZPNpxU"
SNUSBASE_KEY = "sb5029dec66mht55m78fx8bsw6tm8a"
OFDATA_KEY = "DiC9ALodH5T12BfR"
ABUSEIPDB_KEY = "70bcb231c3ae0194917804f23f6f96843bffec2bf2304f09f24b327c3f340d2d769689af42c8790d"
SHODAN_KEY = "i7SlTEgdEoz3aNPKn6tH7aHFKwqmPrPF"

DEPSEARCH_BASE = "https://api.depsearch.sbs"
SNUSBASE_URL = "https://api.snusbase.com/data/search"
OFDATA_BASE = "https://api.ofdata.ru/v2"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
SHODAN_URL = "https://api.shodan.io/shodan/host"

def check_auth():
    auth_key = request.headers.get("X-API-Key")
    if not auth_key:
        auth_key = request.args.get("api_key")
    if not auth_key and request.is_json:
        data = request.get_json(silent=True)
        if data:
            auth_key = data.get("api_key")
    return auth_key == GATEWAY_API_KEY

def detect_type(query):
    q = str(query).strip()
    q_lower = q.lower()
    
    if q_lower.startswith('tt:') or 'tiktok.com' in q_lower:
        return "tiktok"
    if q_lower.startswith(('г.', 'addr:', 'адрес:')):
        return "address"
    if 'vk.com/' in q_lower or q_lower.startswith('vkid'):
        return "vk"
    if q_lower.startswith('nick:'):
        return "nick"
    if q_lower.startswith('pass:'):
        return "pass"
    if q_lower.startswith('snils') or (re.match(r'^\d{11}$', re.sub(r'[^\d]', '', q))):
        return "snils"
    if q_lower.startswith('inn') or (re.match(r'^\d{10}$|^\d{12}$', re.sub(r'[^\d]', '', q))):
        return "inn"
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', q):
        return "email"
    if q_lower.startswith('ip:') or re.match(r'^(\d{1,3}\.){3}\d{1,3}$', q):
        return "ip"
    if re.match(r'^[78][\d]{10}$', re.sub(r'[^\d]', '', q)):
        return "phone"
    if re.match(r'^[A-HJ-NPR-Z0-9]{17}$', q, re.IGNORECASE) or re.match(r'^[A-ZА-Я]\d{3}[A-ZА-Я]{2}\d{2,3}$', q, re.IGNORECASE):
        return "auto"
    if re.search(r'[А-Я]', q) and len(q) > 3:
        return "ofdata"
    return "text"

def depsearch(query, search_type):
    q = str(query).strip()
    
    if search_type == "tiktok":
        if "tiktok.com/" in q:
            match = re.search(r'@([a-zA-Z0-9._]+)', q)
            username = match.group(1) if match else q.split('/')[-1]
            quest = f"tt:{username}"
        else:
            quest = q if q.lower().startswith("tt:") else f"tt:{q}"
    elif search_type == "vk":
        if "vk.com/id" in q.lower():
            quest = f"vkid{re.sub(r'[^\d]', '', q)}"
        elif q.lower().startswith("vkid"):
            quest = q
        else:
            quest = f"vkid{q}"
    elif search_type == "snils":
        digits = re.sub(r'[^\d]', '', q)
        quest = f"snils{digits}" if not q.lower().startswith("snils") else q
    elif search_type == "inn":
        digits = re.sub(r'[^\d]', '', q)
        quest = f"inn{digits}" if not q.lower().startswith("inn") else q
    elif search_type == "ip":
        quest = q if q.lower().startswith("ip:") else f"ip:{q}"
    elif search_type == "phone":
        quest = re.sub(r'[^\d]', '', q)
    else:
        quest = q

    url = f"{DEPSEARCH_BASE}/quest={requests.utils.quote(quest)}&token={DEPSEARCH_TOKEN}&lang=ru"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return {"source": "DepSearch", "data": r.json()}
        return {"source": "DepSearch", "error": r.status_code}
    except:
        return {"source": "DepSearch", "error": "timeout"}

def snusbase(query):
    try:
        headers = {"Content-Type": "application/json", "Auth": SNUSBASE_KEY}
        payload = {"terms": [query], "types": ["email"], "wildcard": False}
        r = requests.post(SNUSBASE_URL, headers=headers, json=payload, timeout=15)
        if r.status_code == 200:
            return {"source": "Snusbase", "data": r.json()}
        return {"source": "Snusbase", "error": r.status_code}
    except:
        return {"source": "Snusbase", "error": "timeout"}

def ofdata_search(query, search_type):
    endpoints = {
        "ofdata_company": f"/search?by=name&obj=org&query={query}",
        "ofdata_fio": f"/search?by=founder-name&obj=org&query={query}",
        "ofdata_inn": f"/person?inn={query}",
        "ofdata_ogrn": f"/inspections?ogrn={query}"
    }
    
    if search_type == "ofdata":
        q = str(query).strip()
        if re.match(r'^\d{10}$|^\d{12}$', q):
            endpoint = endpoints["ofdata_inn"]
        elif re.match(r'^\d{13}$', q):
            endpoint = endpoints["ofdata_ogrn"]
        elif re.search(r'[А-Я]', q) and len(q.split()) >= 2:
            endpoint = endpoints["ofdata_fio"]
        else:
            endpoint = endpoints["ofdata_company"]
    else:
        return {"source": "OFDATA", "error": "unsupported_type"}
    
    url = f"{OFDATA_BASE}{endpoint}&key={OFDATA_KEY}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            if data.get('meta', {}).get('status') == 'ok':
                records = data.get('data', {}).get('Записи', data.get('data', {}))
                if records:
                    return {"source": "OFDATA", "data": records}
        return {"source": "OFDATA", "error": r.status_code}
    except:
        return {"source": "OFDATA", "error": "timeout"}

def abuseipdb(ip):
    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            return {"source": "AbuseIPDB", "data": r.json()}
        return {"source": "AbuseIPDB", "error": r.status_code}
    except:
        return {"source": "AbuseIPDB", "error": "timeout"}

def shodan(ip):
    try:
        url = f"{SHODAN_URL}/{ip}?key={SHODAN_KEY}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return {"source": "Shodan", "data": r.json()}
        return {"source": "Shodan", "error": r.status_code}
    except:
        return {"source": "Shodan", "error": "timeout"}

@app.route('/search', methods=['POST', 'GET'])
def search():
    if not check_auth():
        return jsonify({"error": "Unauthorized. Invalid or missing API key."}), 401

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        query = data.get('query') or data.get('search')
    else:
        query = request.args.get('query') or request.args.get('search')
    
    if not query:
        return jsonify({"error": "Missing 'query'"}), 400
    
    search_type = detect_type(query)
    result = {
        "query": query,
        "type": search_type,
        "sources": []
    }
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        futures[executor.submit(depsearch, query, search_type)] = "DepSearch"
        
        if search_type == "email":
            futures[executor.submit(snusbase, query)] = "Snusbase"
        
        if search_type in ["ofdata", "inn", "fio"]:
            futures[executor.submit(ofdata_search, query, search_type)] = "OFDATA"
        
        if search_type == "ip":
            futures[executor.submit(abuseipdb, query)] = "AbuseIPDB"
            futures[executor.submit(shodan, query)] = "Shodan"
        
        for future in as_completed(futures):
            res = future.result()
            if res and ("data" in res or "error" in res):
                result["sources"].append(res)
    
    result["found"] = len([s for s in result["sources"] if "data" in s]) > 0
    return jsonify(result)

@app.route('/')
def home():
    return jsonify({
        "name": "EasyAPI ",
        "version": "Beta",
        "author": "y3Huk_iphone",
        "sources": ["DepSearch", "Snusbase", "OFDATA", "AbuseIPDB", "Shodan"],
        "endpoint": f"/search?query={SearchType}&api_key={GATEWAY_API_KEY}"
    })

@app.route('/status')
def status():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "status": "online",
        "sources": ["DepSearch", "Snusbase", "OFDATA", "AbuseIPDB", "Shodan"]
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
