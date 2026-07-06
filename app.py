from fastapi import FastAPI, Request, Query, Response
import requests
import re
import os
import json
import secrets
import string
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import httpx
import uvicorn

app = FastAPI()

MASTER_KEY = "hsjdjfhrnjdjd72jrhfbsbxjdndn772hdjd92hrjdjx72nrkfusk8qkrklmrwoco52jrmfn95eufjr"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(BASE_DIR, "api_keys.json")
LOG_FILE = os.path.join(BASE_DIR, "keys_log.txt")

# API Keys Configuration
SNUSBASE_KEYS = [
    "sb5029dec66mht55m78fx8bsw6tm8a",
    "sbmeovhou6ecsn9fd9wcwnwwvsvwnc"
]
OFDATA_KEY = "DiC9ALodH5T12BfR"
INFINITY_KEY = "N7xQ4Lp2ZWk8F5VcD1mR9H6TyU3E0BJa"
SEON_KEY = "758f5f54-befb-4125-bd17-931689af6633"
VK_TOKEN = "0af157510af157510af15751aa0a89e69600af10af157516a0bc15996e74fe2b440998c"
SHODAN_KEY = "xx6gSg9pWYmJcND1hEMbcWuOJtjbHSZ5"
REASON_KEY = "jupit-54cb687d48b31e8234d6ab7f4f"

# Endpoints
SNUSBASE_URL = "https://api.snusbase.com/data/search"
OFDATA_BASE = "https://api.ofdata.ru/v2"
INFINITY_URL = "https://infinity-search.fun/find.php"
SEON_URL = "https://api.seon.io/SeonRestService/phone-api/v2"
SHODAN_BASE_URL = "https://api.shodan.io"
REASON_URL = "https://graph.maybebot.icu/japi/v2/search"

ALLOWED_KEYS = {}
banned_ips = {}
failed_attempts = {}

def render_json(data, status_code=200):
    """Выводит чистый, неэкранированный UTF-8 JSON без маршалинга"""
    return Response(
        content=json.dumps(data, ensure_ascii=False, indent=2),
        status_code=status_code,
        media_type="application/json"
    )

def load_keys():
    global ALLOWED_KEYS
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

ALLOWED_KEYS = load_keys()

def save_keys_to_file():
    try:
        with open(KEYS_FILE, 'w', encoding='utf-8') as f:
            json.dump(ALLOWED_KEYS, f, indent=2, ensure_ascii=False)
    except:
        pass

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

def get_real_ip(request: Request):
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.client.host if request.client else "127.0.0.1"

def is_ip_banned(ip):
    if ip in banned_ips:
        if datetime.now() < banned_ips[ip]:
            return True
        else:
            del banned_ips[ip]
    return False

def ban_ip(ip, days=30):
    banned_ips[ip] = datetime.now() + timedelta(days=days)

def check_auth(request: Request):
    ip = get_real_ip(request)
    auth_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    
    if is_ip_banned(ip):
        return False
    
    if ip in failed_attempts and failed_attempts[ip] >= 15:
        ban_ip(ip, 30)
        return False
    
    if not auth_key:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        return False
    
    if auth_key == MASTER_KEY:
        failed_attempts[ip] = 0
        return True
    
    if auth_key in ALLOWED_KEYS:
        expires_at_str = ALLOWED_KEYS[auth_key].get("expires_at")
        if expires_at_str:
            expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expires_at:
                write_to_log(f"[EXPIRED LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Ключ '{auth_key}' заблокирован ({expires_at_str}).")
                return False
        failed_attempts[ip] = 0
        return True
    
    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    return False

def sanitize_query(query):
    if not query:
        return query
    return re.sub(r'[^a-zA-Z0-9\s@\.\-_+:яёА-ЯЁ]', '', query)

SUPPORTED_PARAMS = [
    'pass', 'email', 'inn', 'text', 'фио', 'fio', 'phone', 
    'vkid', 'vk', 'ip', 'snils', 'passport', 'ogrn', 'company',
    'nick', 'telegram', 'vin'
]

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
    if re.match(r'^[0-9]{4}\s?[0-9]{6}$', q) or re.match(r'^[А-Я]{2}\s?[0-9]{7}$', q):
        return "passport"
    if re.match(r'^[0-9]{3}-?[0-9]{3}-?[0-9]{3}-?[0-9]{2}$', q):
        return "snils"
    if re.match(r'^\d{13}$', q):
        return "ogrn"
    if re.match(r'^[A-HJ-NPR-Z0-9]{17}$', q.upper()):
        return "vin"
    if q.startswith('@'):
        return "telegram"
    if re.match(r'^[А-ЯЁA-Z][а-яёa-zА-ЯЁA-Z0-9\s\-\.\,]+$', q) and len(q) > 3:
        return "company"
    return "text"

# --- Workers ---

def reason_search(query, search_type):
    try:
        type_mapping = {
            "phone": "phone", "email": "email", "inn": "inn", "ip": "ip",
            "passport": "passport", "fio": "fio", "фио": "fio", "vk": "vk",
            "vkid": "vk", "nick": "nick", "telegram": "telegram", "vin": "vin", "text": "fio"
        }
        api_type = type_mapping.get(search_type, "fio")
        headers = {"access_token": REASON_KEY, "Content-Type": "application/json"}
        payload = {"search_type": api_type, "query": str(query).strip()}
        r = requests.post(REASON_URL, headers=headers, json=payload, timeout=10)
        if r.status_code == 200:
            return {"source": "ReasonAPI", "data": r.json()}
        return {"source": "ReasonAPI", "error": r.status_code}
    except:
        return {"source": "ReasonAPI", "error": 504}

def snusbase(query, search_type):
    try:
        headers = {"Content-Type": "application/json"}
        snus_type = "password" if search_type == "pass" else "email"
        payload = {"terms": [str(query).strip()], "types": [snus_type], "wildcard": False}
        for key in SNUSBASE_KEYS:
            try:
                headers["Auth"] = key
                r = requests.post(SNUSBASE_URL, headers=headers, json=payload, timeout=8)
                if r.status_code == 200:
                    return {"source": "Snusbase", "data": r.json()}
                if r.status_code in [402, 429]:
                    continue
                return {"source": "Snusbase", "error": r.status_code}
            except:
                continue
        return {"source": "Snusbase", "error": "All keys exhausted"}
    except:
        return {"source": "Snusbase", "error": 504}

def ofdata(query, search_type):
    q = str(query).strip()
    headers = {"User-Agent": "Mozilla/5.0"}
    collected_data = {}
    status_code = 404

    type_map = {
        "inn": ("person", "inn"), "phone": ("search", "phone"), "email": ("search", "email"),
        "passport": ("person", "passport"), "snils": ("person", "snils"), "fio": ("search", "fio"),
        "фио": ("search", "fio"), "ogrn": ("company", "ogrn"), "company": ("company", "query"),
        "text": ("search", "query")
    }
    endpoint, param = type_map.get(search_type, ("search", "query"))
    
    if search_type == "company":
        if re.match(r'^\d{10}$|^\d{12}$', q):
            url = f"{OFDATA_BASE}/company?key={OFDATA_KEY}&inn={q}"
        elif re.match(r'^\d{13}$', q):
            url = f"{OFDATA_BASE}/company?key={OFDATA_KEY}&ogrn={q}"
        else:
            url = f"{OFDATA_BASE}/company?key={OFDATA_KEY}&query={requests.utils.quote(q)}"
        try:
            r = requests.get(url, headers=headers, timeout=8)
            status_code = r.status_code
            if r.status_code == 200:
                collected_data["company_info"] = r.json()
        except:
            status_code = 504
        return {"source": "Ofdata", "data": collected_data} if collected_data else {"source": "Ofdata", "error": status_code}

    if search_type in ["fio", "фио"]:
        parts = q.split()
        if len(parts) >= 2:
            params = {
                "key": OFDATA_KEY, "first_name": parts[0], "last_name": parts[1],
                "middle_name": parts[2] if len(parts) > 2 else ""
            }
            url = f"{OFDATA_BASE}/search"
            try:
                r = requests.get(url, headers=headers, params=params, timeout=8)
                status_code = r.status_code
                if r.status_code == 200:
                    collected_data["search_results"] = r.json()
            except:
                status_code = 504
            return {"source": "Ofdata", "data": collected_data} if collected_data else {"source": "Ofdata", "error": status_code}

    params = {"key": OFDATA_KEY, param: q}
    url = f"{OFDATA_BASE}/{endpoint}"
    try:
        r = requests.get(url, headers=headers, params=params, timeout=8)
        status_code = r.status_code
        if r.status_code == 200:
            collected_data["result"] = r.json()
    except:
        status_code = 504

    return {"source": "Ofdata", "data": collected_data} if collected_data else {"source": "Ofdata", "error": status_code}

def infinity_check(query, search_type):
    try:
        session = requests.Session()
        from requests.adapters import HTTPAdapter
        from urllib3.util import Retry
        retries = Retry(total=2, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*", "Connection": "keep-alive"
        }
        
        q = str(query).strip()
        param_name = None
        if search_type == "phone":
            param_name = "phone"
        elif search_type == "email":
            param_name = "email"
        elif search_type in ["text", "фио", "fio", "company"]:
            param_name = "fio"
            
        if not param_name:
            return None

        params = {param_name: q, "token": INFINITY_KEY}
        r = session.get(INFINITY_URL, headers=headers, params=params, timeout=(3, 8))
        if r.status_code == 200:
            try:
                res_data = r.json()
            except:
                try:
                    res_data = json.loads(r.text)
                except:
                    res_data = r.text
            return {"source": "InfinityCheck", "data": res_data}
        return {"source": "InfinityCheck", "error": r.status_code}
    except:
        return {"source": "InfinityCheck", "error": 504}

def lookup_phone_via_seon(query):
    try:
        clean_phone = re.sub(r'[^\d]', '', str(query).strip())
        headers = {"X-API-KEY": SEON_KEY, "Content-Type": "application/json"}
        payload = {"phone": clean_phone}
        r = requests.post(SEON_URL, headers=headers, json=payload, timeout=8)
        if r.status_code == 200:
            return {"source": "SEON", "data": r.json()}
        return {"source": "SEON", "error": r.status_code}
    except:
        return {"source": "SEON", "error": 504}

def lookup_vk(query):
    try:
        url = "https://api.vk.com/method/users.get"
        params = {
            "user_ids": str(query).strip(), "access_token": VK_TOKEN,
            "v": "5.199", "fields": "first_name,last_name,bdate,city,country,contacts,online"
        }
        r = requests.get(url, params=params, timeout=8)
        if r.status_code == 200:
            return {"source": "VK", "data": r.json()}
        return {"source": "VK", "error": r.status_code}
    except:
        return {"source": "VK", "error": 504}

def lookup_shodan(query):
    try:
        ip = str(query).strip()
        url = f"{SHODAN_BASE_URL}/shodan/host/{ip}"
        params = {"key": SHODAN_KEY}
        r = requests.get(url, params=params, timeout=8)
        if r.status_code == 403:
            fallback_url = f"https://internetdb.shodan.io/{ip}"
            r_fallback = requests.get(fallback_url, timeout=8)
            if r_fallback.status_code == 200:
                return {"source": "Shodan (InternetDB Fallback)", "data": r_fallback.json()}
            return {"source": "Shodan", "error": r_fallback.status_code}
        if r.status_code == 200:
            return {"source": "Shodan", "data": r.json()}
        return {"source": "Shodan", "error": r.status_code}
    except:
        return {"source": "Shodan", "error": 504}

# --- Routes ---

@app.api_route("/search", methods=["GET", "POST"])
async def search(request: Request):
    try:
        if not check_auth(request):
            ip = get_real_ip(request)
            if is_ip_banned(ip):
                return render_json({"error": "Your IP is banned for 30 days."}, 403)
            return render_json({"error": "Unauthorized."}, 401)

        query = None
        search_type = None

        if request.method == "POST":
            try:
                data = await request.json()
            except:
                data = {}
            for param in SUPPORTED_PARAMS:
                if param in data:
                    query = data[param]
                    search_type = param
                    break
            if not query:
                query = data.get('query') or data.get('search')
        else:
            for param in SUPPORTED_PARAMS:
                val = request.query_params.get(param)
                if val:
                    query = val
                    search_type = param
                    break
            if not query:
                query = request.query_params.get('query') or request.query_params.get('search')
        
        if not query:
            return render_json({"error": "Missing search term"}, 400)
        
        query = sanitize_query(query)
        if not search_type:
            search_type = detect_type(query)
        
        result = {"query": query, "type": search_type, "found": False, "data": None}
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}
            if search_type in ["phone", "email", "inn", "ip", "passport", "fio", "фио", "vk", "vkid", "nick", "telegram", "vin", "text"]:
                futures[executor.submit(reason_search, query, search_type)] = "reason"
            if search_type in ["email", "pass"]:
                futures[executor.submit(snusbase, query, search_type)] = "sn"
            if search_type in ["inn", "text", "фио", "fio", "snils", "passport", "ogrn", "company"]:
                futures[executor.submit(ofdata, query, search_type)] = "of"
            if search_type in ["phone", "email", "text", "фио", "fio", "company"]:
                futures[executor.submit(infinity_check, query, search_type)] = "inf"
            if search_type == "phone":
                futures[executor.submit(lookup_phone_via_seon, query)] = "seon"
            if search_type in ["vkid", "vk"]:
                futures[executor.submit(lookup_vk, query)] = "vk"
            if search_type == "ip":
                futures[executor.submit(lookup_shodan, query)] = "shodan"
                
            all_data = {}
            for future in as_completed(futures):
                res = future.result()
                if res and "data" in res:
                    source_name = res.get("source", "Unknown")
                    raw_data = res["data"]
                    if isinstance(raw_data, str):
                        try:
                            raw_data = json.loads(raw_data)
                        except:
                            pass
                    all_data[source_name] = raw_data
            
            if all_data:
                result["found"] = True
                result["data"] = all_data
        
        return render_json(result)
    except Exception as e:
        return render_json({"error": "Internal server error", "details": str(e)}, 500)

@app.api_route("/key/create", methods=["POST", "GET"])
async def create_key(request: Request):
    try:
        master = request.headers.get("X-Master-Key") or request.query_params.get("master_key")
        if request.method == "POST":
            try:
                data = await request.json()
            except:
                data = {}
            if not master:
                master = data.get("master_key")
        
        if master != MASTER_KEY:
            return render_json({"error": "Unauthorized."}, 401)
        
        new_key = request.query_params.get("new_key")
        duration_param = request.query_params.get("duration")
        if request.method == "POST":
            try:
                data = await request.json()
            except:
                data = {}
            if not new_key:
                new_key = data.get("new_key")
            if not duration_param:
                duration_param = data.get("duration")
        
        global ALLOWED_KEYS
        if not new_key:
            while True:
                new_key = generate_random_key(24)
                if new_key not in ALLOWED_KEYS:
                    break
        else:
            if new_key in ALLOWED_KEYS:
                return render_json({"error": "Already exists."}, 400)
        
        expires_at_str = None
        if duration_param:
            time_delta = parse_duration(duration_param)
            if time_delta:
                expire_datetime = datetime.now() + time_delta
                expires_at_str = expire_datetime.strftime("%Y-%m-%d %H:%M:%S")
            else:
                return render_json({"error": "Invalid duration format."}, 400)
        
        ALLOWED_KEYS[new_key] = {"expires_at": expires_at_str}
        save_keys_to_file()
        
        log_msg = f"[CREATE LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Ключ: '{new_key}' | Истекает: {expires_at_str if expires_at_str else 'Permanent'}"
        write_to_log(log_msg)
        
        return render_json({"success": True, "key": new_key, "expires_at": expires_at_str if expires_at_str else "Permanent"})
    except Exception as e:
        return render_json({"error": str(e)}, 500)

@app.api_route("/key/delete", methods=["POST", "GET"])
async def delete_key(request: Request):
    try:
        master = request.headers.get("X-Master-Key") or request.query_params.get("master_key")
        if request.method == "POST":
            try:
                data = await request.json()
            except:
                                data = {}
            if not master:
                master = data.get("master_key")
        
        if master != MASTER_KEY:
            return render_json({"error": "Unauthorized."}, 401)
        
        target_key = request.query_params.get("target_key")
        if request.method == "POST":
            try:
                data = await request.json()
            except:
                data = {}
            if not target_key:
                target_key = data.get("target_key")
        
        if not target_key:
            return render_json({"error": "Missing parameter."}, 400)
        
        global ALLOWED_KEYS
        if target_key not in ALLOWED_KEYS:
            return render_json({"error": "Not found."}, 404)
        
        del ALLOWED_KEYS[target_key]
        save_keys_to_file()
        
        log_msg = f"[DELETE LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Удален ключ: '{target_key}'"
        write_to_log(log_msg)
        
        return render_json({"success": True, "message": "Removed."})
    except Exception as e:
        return render_json({"error": str(e)}, 500)
