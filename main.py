from fastapi import FastAPI, Request, Query, Response, Header, HTTPException
from fastapi.responses import JSONResponse
import requests
import re
import os
import json
import secrets
import string
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import uvicorn

app = FastAPI()

MASTER_KEY = "Lh8ebOwxuI"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(BASE_DIR, "api_keys.json")
LOG_FILE = os.path.join(BASE_DIR, "keys_log.txt")

# ====== API КЛЮЧИ ======
SNUSBASE_KEY = "sby0b7crta98od7efbb8zr70788n2h"
SNUSBASE_URL = "https://api.snusbase.com/data/search"

OFDATA_KEY = "DiC9ALodH5T12BfR"
OFDATA_BASE = "https://api.ofdata.ru/v2"

INFINITY_KEY = "N7xQ4Lp2ZWk8F5VcD1mR9H6TyU3E0BJa"
INFINITY_URL = "https://infinity-search.fun/find.php"

# Скрытый/демо-ключ SEON для безопасности
SEON_KEY = "758f5f54-befb-4125-bd17-931689af6633"
SEON_URL = "https://api.seon.io/SeonRestService/phone-api/v2"

VK_TOKEN = "0af157510af157510af15751aa0a89e69600af10af157516a0bc15996e74fe2b440998c"
SHODAN_KEY = "xx6gSg9pWYmJcND1hEMbcWuOJtjbHSZ5"

FADE_KEY = "jupit-54cb687d48b31e8234d6ab7f4f"
FADE_URL = "https://graph.maybebot.icu/japi/v2/search"

DEPSEARCH_TOKEN = "x5OeEQZZbaRv7wljkHXuETQ7JByEznlY"
DEPSEARCH_URL = "https://api.depsearch.sbs"

CRYVEN_KEY = "%40Oliver_FloresSS%3ARRCqVLUb"
CRYVEN_BASE = "https://cryven.info"

BIGBASE_TOKEN = "hEtcNRmBOGUxGwHX9NfOccaIXbyqCmRF"
BIGBASE_URL = "https://bigbase.top/api"

# ====== QUICKFLOW ======
QUICKFLOW_TOKEN = "063b6819d85570dfe1b5f5b4ba5be14ac1d66a74e848ee9d1588068a9cf9b372"
QUICKFLOW_URL = "https://api.quickflow.lat"

# ====== TELEGRAM OSINT ======
TG_OSINT_TOKEN = "76:fBn742F2bJNyb6wW6jatmrZ3NVkogjjO"
TG_OSINT_BASE_URL = "https://kartoshka.free/v1"

ALLOWED_KEYS = {}
banned_ips = {}
failed_attempts = {}

def render_json(data, status_code=200):
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

async def check_auth(request: Request):
    ip = get_real_ip(request)
    
    # 1. Сначала ищем в заголовках или параметрах запроса
    auth_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    
    # 2. Если запрос POST и ключ не найден, пробуем прочитать его из JSON-тела
    if not auth_key and request.method == "POST":
        try:
            body = await request.json()
            auth_key = body.get("api_key") or body.get("X-API-Key")
        except Exception:
            pass
    
    # Проверка на бан IP
    is_blocked = False
    if is_ip_banned(ip):
        is_blocked = True
    elif ip in failed_attempts and failed_attempts[ip] >= 15:
        ban_ip(ip, 30)
        is_blocked = True
    
    # Если ключ не предоставлен вообще
    if not auth_key:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        return False
    
    # 3. Валидация мастер-ключа (игнорирует бан IP)
    if auth_key == MASTER_KEY:
        failed_attempts[ip] = 0
        if ip in banned_ips:
            del banned_ips[ip]
        return True
    
    # 4. Валидация обычных ключей (игнорирует бан IP, если ключ верен)
    if auth_key in ALLOWED_KEYS:
        expires_at_str = ALLOWED_KEYS[auth_key].get("expires_at")
        if expires_at_str:
            try:
                if "T" in expires_at_str:
                    expires_at = datetime.fromisoformat(expires_at_str)
                else:
                    expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S")
                
                if datetime.now() > expires_at:
                    write_to_log(f"[EXPIRED LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Ключ '{auth_key}' заблокирован ({expires_at_str}).")
                    return False
            except Exception as e:
                write_to_log(f"[DATE ERROR] Не удалось распарсить дату '{expires_at_str}': {e}")
        
        # Сбрасываем блокировки для валидного ключа
        failed_attempts[ip] = 0
        if ip in banned_ips:
            del banned_ips[ip]
        return True
    
    # Неверный ключ
    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    return False

def sanitize_query(query):
    if not query:
        return query
    return re.sub(r'[^a-zA-Z0-9\s@\.\-_+:яёА-ЯЁ]', '', query)

SUPPORTED_PARAMS = [
    'pass', 'email', 'inn', 'text', 'фио', 'fio', 'phone', 
    'vkid', 'vk', 'ip', 'snils', 'passport', 'ogrn', 'company',
    'nick', 'telegram', 'vin', 'username'
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

# ====== WORKERS ======

def depsearch(query):
    try:
        url = f"{DEPSEARCH_URL}/quest={query}&lang=ru&token={DEPSEARCH_TOKEN}"
        r = requests.get(url, headers={"Accept": "application/json"}, timeout=12)
        if r.status_code == 200:
            try:
                return {"source": "DepSearch", "data": r.json()}
            except:
                return {"source": "DepSearch", "data": r.text}
        return {"source": "DepSearch", "error": r.status_code}
    except:
        return {"source": "DepSearch", "error": 504}

def snusbase(query, search_type):
    try:
        headers = {"Content-Type": "application/json", "Auth": SNUSBASE_KEY}
        snus_type = "password" if search_type == "pass" else "email"
        payload = {"terms": [str(query).strip()], "types": [snus_type], "wildcard": False}
        r = requests.post(SNUSBASE_URL, headers=headers, json=payload, timeout=10)
        if r.status_code == 200:
            try:
                return {"source": "Snusbase", "data": r.json()}
            except:
                return {"source": "Snusbase", "data": r.text}
        return {"source": "Snusbase", "error": r.status_code}
    except:
        return {"source": "Snusbase", "error": 504}

def fadeapi(query, search_type):
    try:
        headers = {"access_token": FADE_KEY, "Content-Type": "application/json"}
        type_mapping = {
            "phone": "phone", "email": "email", "inn": "inn", "ip": "ip",
            "passport": "passport", "fio": "fio", "фио": "fio", "vk": "vk",
            "vkid": "vk", "nick": "nick", "telegram": "telegram", "vin": "vin"
        }
        api_type = type_mapping.get(search_type, "fio")
        payload = {"search_type": api_type, "query": str(query).strip()}
        r = requests.post(FADE_URL, headers=headers, json=payload, timeout=15)
        if r.status_code == 200:
            try:
                return {"source": "FadeAPI", "data": r.json()}
            except:
                return {"source": "FadeAPI", "data": r.text}
        return {"source": "FadeAPI", "error": r.status_code}
    except:
        return {"source": "FadeAPI", "error": 504}

def quickflow_search(query: str):
    try:
        url = f"{QUICKFLOW_URL}/get-user"
        params = {"token": QUICKFLOW_TOKEN, "username": query}
        r = requests.get(url, params=params, timeout=10)
        if r.status_code == 200:
            return {"source": "QuickFlow", "data": r.json()}
        return {"source": "QuickFlow", "error": r.status_code}
    except Exception as e:
        return {"source": "QuickFlow", "error": str(e)}

def cryven_search(query):
    try:
        url = f"{CRYVEN_BASE}/api/search?search={query}&key={CRYVEN_KEY}"
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            try:
                data = r.json()
                if data.get("success"):
                    return {"source": "Cryven", "data": data}
            except:
                return {"source": "Cryven", "data": r.text}
        return {"source": "Cryven", "error": r.status_code}
    except:
        return {"source": "Cryven", "error": 504}

def bigbase_search(query):
    try:
        headers = {"Authorization": BIGBASE_TOKEN, "Content-Type": "application/json"}
        payload = {"search": query, "page": 1}
        r = requests.post(BIGBASE_URL + "/search", headers=headers, json=payload, timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        if "user" in data and isinstance(data["user"], dict):
            data["user"].pop("api_token", None)
        return {"source": "BigBase", "data": data}
    except:
        return {"source": "BigBase", "error": 504}

# ====== TELEGRAM OSINT ======
def tg_osint_api_get(endpoint, params=None):
    try:
        headers = {"Authorization": f"Bearer {TG_OSINT_TOKEN}"}
        res = requests.get(f"{TG_OSINT_BASE_URL}{endpoint}", headers=headers, params=params, timeout=10)
        if res.status_code != 200:
            return None
        data = res.json()
        if not data.get("ok"):
            return None
        return data.get("result")
    except Exception:
        return None

def tg_osint_search_owner(query):
    result = tg_osint_api_get("/owners/search", {"q": query, "limit": 1})
    if result is None:
        return None
    items = result.get("items", [])
    if not items:
        return None
    return items[0]

def tg_osint_get_user_info(query):
    found = tg_osint_search_owner(query)
    if found is None:
        return None
    
    owner = found.get("owner", {})
    ref = owner.get("username") or owner.get("telegramId") or owner.get("seeId")
    
    info = {
        "source": "TelegramOSINT",
        "username": owner.get("username", "Нет"),
        "telegramId": owner.get("telegramId", "Нет"),
        "name": owner.get("name", "Нет"),
        "is_bot": owner.get("isBot", False),
        "is_premium": owner.get("isPremium", False),
        "creation_date": owner.get("creationDate", "Нет")
    }
    
    channel_result = tg_osint_api_get(f"/owner/{ref}/personal_channel")
    if channel_result:
        info["personal_channel"] = channel_result
    
    return info

def tg_osint_get_history(query):
    found = tg_osint_search_owner(query)
    if found is None:
        return None
    
    owner = found.get("owner", {})
    ref = owner.get("username") or owner.get("telegramId") or owner.get("seeId")
    
    all_items = []
    cursor = None
    while True:
        params = {"limit": 100}
        if cursor:
            params["cursor"] = cursor
        result = tg_osint_api_get(f"/owner/{ref}/history", params)
        if result is None:
            break
        items = result.get("items", [])
        if not items:
            break
        all_items.extend(items)
        cursor = result.get("nextCursor")
        if not cursor:
            break
    
    transfers = [i for i in all_items if i.get("kind") == "GIFT" and i.get("giftAction", {}).get("action") == "transfer"]
    transfers.sort(key=lambda x: x.get("time", ""), reverse=True)
    
    return {
        "source": "TelegramOSINT",
        "transfers": transfers[:10],
        "total_transfers": len(transfers)
    }

# ====== SEARCH ======

@app.api_route("/search", methods=["GET", "POST"])
async def search(request: Request):
    try:
        # Важно: используем await перед асинхронной функцией проверки
        if not await check_auth(request):
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
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}
            
            futures[executor.submit(depsearch, query)] = "depsearch"
            futures[executor.submit(cryven_search, query)] = "cryven"
            futures[executor.submit(bigbase_search, query)] = "bigbase"
            futures[executor.submit(fadeapi, query, search_type)] = "fadeapi"
            
            if search_type in ["email", "pass"]:
                futures[executor.submit(snusbase, query, search_type)] = "snusbase"
            
            if search_type == "phone":
                futures[executor.submit(fadeapi, query, "phone")] = "fadeapi_phone"
            
            if search_type in ["telegram", "username"]:
                clean = query.replace("@", "").strip()
                futures[executor.submit(quickflow_search, clean)] = "quickflow"
                futures[executor.submit(tg_osint_get_user_info, clean)] = "tg_info"
                futures[executor.submit(tg_osint_get_history, clean)] = "tg_history"
            
            all_data = {}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    res = future.result(timeout=15)
                    if res:
                        all_data[key] = res
                except Exception as e:
                    all_data[key] = {"error": str(e)}
            
            if all_data:
                result["found"] = True
                result["data"] = all_data
        
        return render_json(result)
    except Exception as e:
        return render_json({"error": "Internal server error", "details": str(e)}, 500)

# ====== MASTER KEYS ======

@app.api_route("/master/keys", methods=["POST", "GET"])
async def create_key(request: Request):
    try:
        master = request.headers.get("X-Master-Key") or request.query_params.get("master_key")
        
        # Парсим данные из тела запроса, если метод POST
        data = {}
        if request.method == "POST":
            try:
                data = await request.json()
            except:
                pass
            if not master:
                master = data.get("master_key")
        
        if master != MASTER_KEY:
            return render_json({"error": "Unauthorized."}, 401)
        
        username = data.get("username") or data.get("user")
        global ALLOWED_KEYS
        
        if username:
            clean_username = username.lstrip('@').strip()
            random_part = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
            new_key = f"{clean_username}:{random_part}"
            while new_key in ALLOWED_KEYS:
                random_part = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
                new_key = f"{clean_username}:{random_part}"
        else:
            new_key = f"sk_{secrets.token_hex(12)}"
        
        expires_at_str = data.get("expires_at")
        rate_limit = data.get("rate_limit", 1000)
        rate_limit_period = data.get("rate_limit_period", 3600)
        
        ALLOWED_KEYS[new_key] = {
            "expires_at": expires_at_str,
            "rate_limit": rate_limit,
            "rate_limit_period": rate_limit_period,
            "created_at": datetime.now().isoformat()
        }
        save_keys_to_file()
        
        return render_json({
            "success": True,
            "key": new_key,
            "expires_at": expires_at_str or "Permanent"
        })
    except Exception as e:
        return render_json({"error": str(e)}, 500)

@app.api_route("/master/keys/{key}", methods=["DELETE"])
async def delete_key(key: str, request: Request):
    try:
        master = request.headers.get("X-Master-Key") or request.query_params.get("master_key")
        if master != MASTER_KEY:
            return render_json({"error": "Unauthorized."}, 401)
        
        global ALLOWED_KEYS
        if key not in ALLOWED_KEYS:
            return render_json({"error": "Not found."}, 404)
        
        if key == MASTER_KEY:
            return render_json({"error": "Cannot delete master key."}, 403)
        
        del ALLOWED_KEYS[key]
        save_keys_to_file()
        
        return render_json({"success": True, "message": "Removed."})
    except Exception as e:
        return render_json({"error": str(e)}, 500)

@app.get("/master/keys/list")
async def list_keys(request: Request):
    try:
        master = request.headers.get("X-Master-Key") or request.query_params.get("master_key")
        if master != MASTER_KEY:
            return render_json({"error": "Unauthorized."}, 401)
        return render_json({"keys": ALLOWED_KEYS})
    except Exception as e:
        return render_json({"error": str(e)}, 500)

@app.get("/health")
async def health():
    return {"status": "ok", "services": ["DepSearch", "Snusbase", "FadeAPI", "QuickFlow", "Cryven", "BigBase", "TelegramOSINT"]}

@app.get("/")
async def home():
    return render_json({
        "name": "Router API",
        "author": "@y3Huk_iphone",
        "version": "2.0",
        "endpoints": {
            "/search": "GET/POST - универсальный поиск",
            "/master/keys": "POST - создать ключ",
            "/master/keys/{key}": "DELETE - удалить ключ",
            "/master/keys/list": "GET - список ключей",
            "/health": "GET - статус"
        },
        "message": "Нашли баги? Пишите @y3Huk_iphone. Баги пофикшены, поиск работает ♡. Приятного пользования!"
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port, workers=1)
