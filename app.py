from flask import Flask, request, jsonify
import requests
import re
import os
import json
import secrets
import string
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

app = Flask(__name__)

app.config['JSON_AS_ASCII'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
try:
    app.json.ensure_ascii = False
    app.json.compact = False
except AttributeError:
    pass

MASTER_KEY = "hsjdjfhrnjdjd72jrhfbsbxjdndn772hdjd92hrjdjx72nrkfusk8qkrklmrwoco52jrmfn95eufjr"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(BASE_DIR, "api_keys.json")
LOG_FILE = os.path.join(BASE_DIR, "keys_log.txt")

SNUSBASE_KEY = "sb5029dec66mht55m78fx8bsw6tm8a"
OFDATA_KEY = "DiC9ALodH5T12BfR"
INFINITY_KEY = "N7xQ4Lp2ZWk8F5VcD1mR9H6TyU3E0BJa"
SEON_KEY = "758f5f54-befb-4125-bd17-931689af6633"
VK_TOKEN = "0af157510af157510af15751aa0a89e69600af10af157516a0bc15996e74fe2b440998c"
SHODAN_KEY = "xx6gSg9pWYmJcND1hEMbcWuOJtjbHSZ5"

SNUSBASE_URL = "https://api.snusbase.com/data/search"
OFDATA_BASE = "https://api.ofdata.ru/v2"
INFINITY_URL = "https://infinity-check.online/find.php"
SEON_URL = "https://api.seon.io/SeonRestService/phone-api/v2"
SHODAN_BASE_URL = "https://api.shodan.io"

def write_to_log(message):
    print(message)
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{message}\n")
    except Exception as e:
        print(f"[ERROR LOGGING] {e}")

def generate_random_key(length=24):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def parse_duration(duration_str):
    if not duration_str:
        return None
    match = re.match(r'^(\d+)\s*(day|days|hour|hours|min|mins|minute|minutes)$', str(duration_str).strip().lower())
    if not match:
        return None
    
    amount = int(match.group(1))
    unit = match.group(2)
    
    if 'day' in unit:
        return timedelta(days=amount)
    elif 'hour' in unit:
        return timedelta(hours=amount)
    elif 'min' in unit:
        return timedelta(minutes=amount)
    return None

def init_keys():
    default_keys = {"hdhxhs827dhsb": {"expires_at": None}}
    if not os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, 'w', encoding='utf-8') as f:
                json.dump(default_keys, f, indent=2, ensure_ascii=False)
        except:
            pass
        return default_keys
    try:
        with open(KEYS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                migrated = {k: {"expires_at": None} for k in data}
                with open(KEYS_FILE, 'w', encoding='utf-8') as wf:
                    json.dump(migrated, wf, indent=2, ensure_ascii=False)
                return migrated
            return data
    except:
        return default_keys

ALLOWED_KEYS = init_keys()

def save_keys_to_file():
    try:
        with open(KEYS_FILE, 'w', encoding='utf-8') as f:
            json.dump(ALLOWED_KEYS, f, indent=2, ensure_ascii=False)
    except:
        pass

def check_auth():
    auth_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if not auth_key and request.is_json:
        data = request.get_json(silent=True)
        if data:
            auth_key = data.get("api_key")
            
    if auth_key == MASTER_KEY:
        return True
        
    if auth_key in ALLOWED_KEYS:
        expires_at_str = ALLOWED_KEYS[auth_key].get("expires_at")
        if expires_at_str:
            expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expires_at:
                log_msg = f"[EXPIRED LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Ключ '{auth_key}' заблокирован ({expires_at_str})."
                write_to_log(log_msg)
                return False
        return True
    return False

SUPPORTED_PARAMS = ['pass', 'email', 'inn', 'text', 'фио', 'fio', 'phone', 'vkid', 'ip']

def detect_type(query):
    q = str(query).strip()
    q_lower = q.lower()
    
    if q_lower.startswith('pass:'):
        return "pass"
    if q_lower.startswith('inn') or (re.match(r'^\d{10}$|^\d{12}$', re.sub(r'[^\d]', '', q)) and len(re.sub(r'[^\d]', '', q)) in [10, 12]):
        return "inn"
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', q):
        return "email"
    if re.match(r'^\+?\d{10,15}$', re.sub(r'[^\d+]', '', q)):
        return "phone"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', q):
        return "ip"
    
    return "text"

def snusbase(query, search_type):
    try:
        headers = {"Content-Type": "application/json", "Auth": SNUSBASE_KEY}
        snus_type = "password" if search_type == "pass" else "email"
        payload = {
            "terms": [str(query).strip()],
            "types": [snus_type],
            "wildcard": False
        }
        r = requests.post(SNUSBASE_URL, headers=headers, json=payload, timeout=15)
        if r.status_code == 200:
            return {"source": "Snusbase", "data": r.json()}
        return {"source": "Snusbase", "error": r.status_code}
    except:
        return {"source": "Snusbase", "error": "timeout"}

def ofdata(query, search_type):
    q = str(query).strip()
    headers = {"User-Agent": "Mozilla/5.0"}
    collected_data = {}

    if search_type == "inn":
        digits = re.sub(r'[^\d]', '', q)
        if len(digits) == 12:
            url = f"{OFDATA_BASE}/person?key={OFDATA_KEY}&inn={digits}"
            try:
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code == 200:
                    collected_data["person_info"] = r.json()
            except:
                pass
        elif len(digits) == 10:
            for endpoint in ["company", "bank"]:
                url = f"{OFDATA_BASE}/{endpoint}?key={OFDATA_KEY}&inn={digits}"
                try:
                    r = requests.get(url, headers=headers, timeout=10)
                    if r.status_code == 200:
                        collected_data[f"{endpoint}_info"] = r.json()
                except:
                    pass
    elif search_type in ["text", "фио", "fio"]:
        url = f"{OFDATA_BASE}/search?key={OFDATA_KEY}&query={requests.utils.quote(q)}"
        try:
            r = requests.get(url, headers=headers, timeout=12)
            if r.status_code == 200:
                collected_data["search_results"] = r.json()
        except:
            pass

    if collected_data:
        return {"source": "Ofdata", "data": collected_data}
    return {"source": "Ofdata", "error": "no_data_found"}

def infinity_check(query, search_type):
    try:
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
            "Connection": "keep-alive"
        }
        
        q = str(query).strip()
        param_name = None
        if search_type == "phone":
            param_name = "phone"
        elif search_type == "email":
            param_name = "email"
        elif search_type in ["text", "фио", "fio"]:
            param_name = "fio"
            
        if not param_name:
            return None

        params = {param_name: q, "token": INFINITY_KEY}
        r = session.get(INFINITY_URL, headers=headers, params=params, timeout=(5, 25))
        if r.status_code == 200:
            try:
                res_data = r.json()
            except:
                res_data = r.text
            return {"source": "InfinityCheck", "data": res_data}
        return {"source": "InfinityCheck", "error": f"HTTP status {r.status_code}"}
    except Exception as e:
        return {"source": "InfinityCheck", "error": str(e)}

def lookup_phone_via_seon(query):
    try:
        clean_phone = re.sub(r'[^\d]', '', str(query).strip())
        headers = {
            "X-API-KEY": SEON_KEY,
            "Content-Type": "application/json"
        }
        # Исправлено: SEON требует POST-метод и данные внутри JSON-body
        payload = {
            "phone": clean_phone
        }
        r = requests.post(SEON_URL, headers=headers, json=payload, timeout=15)
        if r.status_code == 200:
            return {"source": "SEON", "data": r.json()}
        return {"source": "SEON", "error": f"HTTP status {r.status_code}"}
    except Exception as e:
        return {"source": "SEON", "error": str(e)}

def lookup_vk(query):
    try:
        url = "https://api.vk.com/method/users.get"
        params = {
            "user_ids": str(query).strip(),
            "access_token": VK_TOKEN,
            "v": "5.199",
            "fields": "first_name,last_name,bdate,city,country,contacts,online"
        }
        r = requests.get(url, params=params, timeout=15)
        if r.status_code == 200:
            return {"source": "VK", "data": r.json()}
        return {"source": "VK", "error": f"HTTP status {r.status_code}"}
    except Exception as e:
        return {"source": "VK", "error": str(e)}

def lookup_shodan(query):
    try:
        ip = str(query).strip()
        url = f"{SHODAN_BASE_URL}/shodan/host/{ip}"
        params = {"key": SHODAN_KEY}
        r = requests.get(url, params=params, timeout=15)
        
        # Исправлено: Если ключ заблокирован/не имеет прав (403), переключаемся на бесплатную базу без токена
        if r.status_code == 403:
            fallback_url = f"https://internetdb.shodan.io/{ip}"
            r_fallback = requests.get(fallback_url, timeout=10)
            if r_fallback.status_code == 200:
                return {"source": "Shodan (InternetDB Fallback)", "data": r_fallback.json()}
                
        if r.status_code == 200:
            return {"source": "Shodan", "data": r.json()}
        return {"source": "Shodan", "error": f"HTTP status {r.status_code}"}
    except Exception as e:
        return {"source": "Shodan", "error": str(e)}

@app.route('/key/create', methods=['POST', 'GET'])
def create_key():
    master = request.headers.get("X-Master-Key") or request.args.get("master_key")
    if not master and request.is_json:
        master = request.get_json(silent=True).get("master_key")
        
    if master != MASTER_KEY:
        return jsonify({"error": "Unauthorized."}), 401
        
    new_key = request.args.get("new_key")
    duration_param = request.args.get("duration")
    
    if not new_key and request.is_json:
        json_data = request.get_json(silent=True) or {}
        new_key = json_data.get("new_key")
        duration_param = json_data.get("duration")
        
    global ALLOWED_KEYS

    if not new_key:
        while True:
            new_key = generate_random_key(24)
            if new_key not in ALLOWED_KEYS:
                break
    else:
        if new_key in ALLOWED_KEYS:
            return jsonify({"error": "Already exists."}), 400
        
    expires_at_str = None
    if duration_param:
        time_delta = parse_duration(duration_param)
        if time_delta:
            expire_datetime = datetime.now() + time_delta
            expires_at_str = expire_datetime.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return jsonify({"error": "Invalid duration format."}), 400
            
    ALLOWED_KEYS[new_key] = {"expires_at": expires_at_str}
    save_keys_to_file()
    
    log_msg = f"[CREATE LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Ключ: '{new_key}' | Истекает: {expires_at_str if expires_at_str else 'Permanent'}"
    write_to_log(log_msg)
    
    return jsonify({
        "success": True, 
        "key": new_key,
        "expires_at": expires_at_str if expires_at_str else "Permanent"
    })

@app.route('/key/delete', methods=['POST', 'GET'])
def delete_key():
    master = request.headers.get("X-Master-Key") or request.args.get("master_key")
    if not master and request.is_json:
        master = request.get_json(silent=True).get("master_key")
        
    if master != MASTER_KEY:
        return jsonify({"error": "Unauthorized."}), 401
        
    target_key = request.args.get("target_key")
    if not target_key and request.is_json:
        target_key = request.get_json(silent=True).get("target_key")
        
    if not target_key:
        return jsonify({"error": "Missing parameter."}), 400
        
    global ALLOWED_KEYS
    if target_key not in ALLOWED_KEYS:
        return jsonify({"error": "Not found."}), 404
        
    del ALLOWED_KEYS[target_key]
    save_keys_to_file()
    
    log_msg = f"[DELETE LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Удален ключ: '{target_key}'"
    write_to_log(log_msg)
    
    return jsonify({"success": True, "message": "Removed."})

@app.route('/key/list', methods=['GET'])
def list_keys():
    master = request.headers.get("X-Master-Key") or request.args.get("master_key")
    if master != MASTER_KEY:
        return jsonify({"error": "Unauthorized."}), 401
    return jsonify({"allowed_api_keys": ALLOWED_KEYS})

@app.route('/search', methods=['POST', 'GET'])
def search():
    if not check_auth():
        return jsonify({"error": "Unauthorized."}), 401

    query = None
    search_type = None

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        for param in SUPPORTED_PARAMS:
            if param in data:
                query = data[param]
                search_type = param
                break
        if not query:
            query = data.get('query') or data.get('search')
    else:
        for param in SUPPORTED_PARAMS:
            val = request.args.get(param)
            if val:
                query = val
                search_type = param
                break
        if not query:
            query = request.args.get('query') or request.args.get('search')
    
    if not query:
        return jsonify({"error": "Missing search term"}), 400
    
    if not search_type:
        search_type = detect_type(query)
        
    result = {
        "query": query,
        "type": search_type,
        "sources": []
    }
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        
        if search_type in ["email", "pass"]:
            futures[executor.submit(snusbase, query, search_type)] = "sn"
            
        if search_type in ["inn", "text", "фио", "fio"]:
            futures[executor.submit(ofdata, query, search_type)] = "of"
            
        if search_type in ["phone", "email", "text", "фио", "fio"]:
            futures[executor.submit(infinity_check, query, search_type)] = "inf"

        if search_type == "phone":
            futures[executor.submit(lookup_phone_via_seon, query)] = "seon"

        if search_type == "vkid":
            futures[executor.submit(lookup_vk, query)] = "vk"

        if search_type == "ip":
            futures[executor.submit(lookup_shodan, query)] = "shodan"
            
        for future in as_completed(futures):
            res = future.result()
            if res and ("data" in res or "error" in res):
                result["sources"].append(res)
    
    result["found"] = len([s for s in result["sources"] if "data" in s]) > 0
    return jsonify(result)

@app.route('/')
def home():
    return jsonify({
        "name": "EasyApi",
        "author": "@y3Huk_iphone",
        "sources": ["Snusbase", "Ofdata", "InfinityCheck", "SEON", "VK", "Shodan"]
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
