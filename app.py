from fastapi import FastAPI, HTTPException, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import requests
import re
import os
import json
import secrets
import string
from datetime import datetime, timedelta
import asyncio
import httpx
import uvicorn
from contextlib import asynccontextmanager

app = FastAPI()

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

MASTER_KEY = "hsjdjfhrnjdjd72jrhfbsbxjdndn772hdjd92hrjdjx72nrkfusk8qkrklmrwoco52jrmfn95eufjr"

SNUSBASE_KEYS = [
    "sb5029dec66mht55m78fx8bsw6tm8a",
    "sbmeovhou6ecsn9fd9wcwnwwvsvwnc"
]
OFDATA_KEY = "DiC9ALodH5T12BfR"
INFINITY_KEY = "N7xQ4Lp2ZWk8F5VcD1mR9H6TyU3E0BJa"
SEON_KEY = "758f5f54-befb-4125-bd17-931689af6633"
VK_TOKEN = "0af157510af157510af15751aa0a89e69600af10af157516a0bc15996e74fe2b440998c"
SHODAN_KEY = "xx6gSg9pWYmJcND1hEMbcWuOJtjbHSZ5"

SNUSBASE_URL = "https://api.snusbase.com/data/search"
OFDATA_BASE = "https://api.ofdata.ru/v2"
INFINITY_URL = "https://infinity-search.fun/find.php"
SEON_URL = "https://api.seon.io/SeonRestService/phone-api/v2"
SHODAN_BASE_URL = "https://api.shodan.io"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(BASE_DIR, "api_keys.json")
LOG_FILE = os.path.join(BASE_DIR, "keys_log.txt")

ALLOWED_KEYS = {}
banned_ips = {}
failed_attempts = {}

def load_keys():
    global ALLOWED_KEYS
    default_keys = {"hdhxhs827dhsb": {"expires_at": None}}
    if not os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'w') as f:
            json.dump(default_keys, f)
        return default_keys
    try:
        with open(KEYS_FILE, 'r') as f:
            return json.load(f)
    except:
        return default_keys

ALLOWED_KEYS = load_keys()

def save_keys():
    with open(KEYS_FILE, 'w') as f:
        json.dump(ALLOWED_KEYS, f)

async def is_banned(ip: str) -> bool:
    if ip in banned_ips:
        if datetime.now() < banned_ips[ip]:
            return True
        else:
            del banned_ips[ip]
    return False

async def check_auth(api_key: str, ip: str) -> bool:
    if await is_banned(ip):
        return False
    
    if ip in failed_attempts and failed_attempts[ip] >= 15:
        banned_ips[ip] = datetime.now() + timedelta(days=30)
        return False
    
    if not api_key:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        return False
    
    if api_key == MASTER_KEY:
        failed_attempts[ip] = 0
        return True
    
    if api_key in ALLOWED_KEYS:
        expires_at_str = ALLOWED_KEYS[api_key].get("expires_at")
        if expires_at_str:
            expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expires_at:
                return False
        failed_attempts[ip] = 0
        return True
    
    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    return False

def detect_type(query: str) -> str:
    q = query.strip()
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
    if re.match(r'^[А-ЯЁA-Z][а-яёa-zА-ЯЁA-Z0-9\s\-\.\,]+$', q) and len(q) > 3:
        return "company"
    return "text"

async def snusbase(query: str):
    q = str(query).strip()
    snus_type = "password" if detect_type(query) == "pass" else "email"
    payload = {"terms": [q], "types": [snus_type], "wildcard": False}
    async with httpx.AsyncClient(timeout=8) as client:
        for key in SNUSBASE_KEYS:
            try:
                r = await client.post(SNUSBASE_URL, json=payload, headers={"Auth": key})
                if r.status_code == 200:
                    return {"source": "Snusbase", "data": r.json()}
            except:
                continue
    return None

async def ofdata(query: str):
    q = str(query).strip()
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            r = await client.get(f"{OFDATA_BASE}/search?key={OFDATA_KEY}&query={q}")
            if r.status_code == 200:
                return {"source": "Ofdata", "data": r.json()}
        except:
            pass
    return None

async def infinity_check(query: str):
    q = str(query).strip()
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            r = await client.get(f"{INFINITY_URL}?fio={q}&token={INFINITY_KEY}")
            if r.status_code == 200:
                return {"source": "InfinityCheck", "data": r.json()}
        except:
            pass
    return None

async def lookup_phone_via_seon(query: str):
    q = str(query).strip()
    clean_phone = re.sub(r'[^\d]', '', q)
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            r = await client.post(SEON_URL, json={"phone": clean_phone}, headers={"X-API-KEY": SEON_KEY})
            if r.status_code == 200:
                return {"source": "SEON", "data": r.json()}
        except:
            pass
    return None

async def lookup_vk(query: str):
    q = str(query).strip()
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            r = await client.get(f"https://api.vk.com/method/users.get?user_ids={q}&access_token={VK_TOKEN}&v=5.199&fields=first_name,last_name,bdate,city,country,contacts,online")
            if r.status_code == 200:
                return {"source": "VK", "data": r.json()}
        except:
            pass
    return None

async def lookup_shodan(query: str):
    q = str(query).strip()
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            r = await client.get(f"{SHODAN_BASE_URL}/shodan/host/{q}?key={SHODAN_KEY}")
            if r.status_code == 200:
                return {"source": "Shodan", "data": r.json()}
            if r.status_code == 403:
                r_fallback = await client.get(f"https://internetdb.shodan.io/{q}")
                if r_fallback.status_code == 200:
                    return {"source": "Shodan (InternetDB Fallback)", "data": r_fallback.json()}
        except:
            pass
    return None

class SearchRequest(BaseModel):
    query: str
    api_key: Optional[str] = None

async def get_ip(request: Request):
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    client_ip = request.client.host if request.client else "127.0.0.1"
    return client_ip

@app.api_route('/search', methods=['GET', 'POST'])
async def search(request: Request):
    try:
        ip = await get_ip(request)
        api_key = request.headers.get('X-API-Key')
        
        if request.method == 'GET':
            query = request.query_params.get('query')
            if not query:
                for param in ['pass', 'email', 'inn', 'text', 'фио', 'fio', 'phone', 'vkid', 'ip', 'snils', 'passport', 'ogrn', 'company']:
                    val = request.query_params.get(param)
                    if val:
                        query = val
                        break
            if not query:
                return {"error": "Missing search term"}, 400
        else:
            data = await request.json()
            if not data:
                return {"error": "Invalid JSON"}, 400
            query = data.get('query')
            if not query:
                for param in ['pass', 'email', 'inn', 'text', 'фио', 'fio', 'phone', 'vkid', 'ip', 'snils', 'passport', 'ogrn', 'company']:
                    val = data.get(param)
                    if val:
                        query = val
                        break
            if not query:
                api_key = data.get('api_key')
                query = data.get('query')
            if not query:
                return {"error": "Missing search term"}, 400
        
        if not await check_auth(api_key, ip):
            raise HTTPException(status_code=401, detail="Unauthorized")
        
        query = re.sub(r'[^a-zA-Z0-9\s@\.\-_+:яёА-ЯЁ]', '', str(query))
        search_type = detect_type(query)
        
        tasks = []
        if search_type in ["email", "pass"]:
            tasks.append(snusbase(query))
        if search_type in ["inn", "text", "фио", "fio", "snils", "passport", "ogrn", "company"]:
            tasks.append(ofdata(query))
        if search_type in ["phone", "email", "text", "фио", "fio", "company"]:
            tasks.append(infinity_check(query))
        if search_type == "phone":
            tasks.append(lookup_phone_via_seon(query))
        if search_type == "vkid":
            tasks.append(lookup_vk(query))
        if search_type == "ip":
            tasks.append(lookup_shodan(query))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        data = [r for r in results if r and not isinstance(r, Exception)]
        
        return {
            "query": query,
            "type": search_type,
            "found": len(data) > 0,
            "data": data if data else None
        }
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/key/create', methods=['GET', 'POST'])
async def create_key(request: Request):
    try:
        master = request.headers.get('X-Master-Key') or request.query_params.get('master_key')
        if request.method == 'POST':
            data = await request.json()
            master = data.get('master_key') if data else master
        if master != MASTER_KEY:
            return {"error": "Unauthorized"}, 401
        
        new_key = request.query_params.get('new_key')
        duration_param = request.query_params.get('duration')
        if request.method == 'POST':
            data = await request.json()
            if data:
                new_key = data.get('new_key', new_key)
                duration_param = data.get('duration', duration_param)
        
        global ALLOWED_KEYS
        if not new_key:
            while True:
                new_key = generate_random_key(24)
                if new_key not in ALLOWED_KEYS:
                    break
        else:
            if new_key in ALLOWED_KEYS:
                return {"error": "Already exists"}, 400
        
        expires_at_str = None
        if duration_param:
            time_delta = parse_duration(duration_param)
            if time_delta:
                expire_datetime = datetime.now() + time_delta
                expires_at_str = expire_datetime.strftime("%Y-%m-%d %H:%M:%S")
            else:
                return {"error": "Invalid duration format"}, 400
        
        ALLOWED_KEYS[new_key] = {"expires_at": expires_at_str}
        save_keys()
        
        log_msg = f"[CREATE LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Ключ: '{new_key}' | Истекает: {expires_at_str if expires_at_str else 'Permanent'}"
        print(log_msg)
        
        return {
            "success": True,
            "key": new_key,
            "expires_at": expires_at_str if expires_at_str else "Permanent"
        }
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/key/delete', methods=['GET', 'POST'])
async def delete_key(request: Request):
    try:
        master = request.headers.get('X-Master-Key') or request.query_params.get('master_key')
        if request.method == 'POST':
            data = await request.json()
            master = data.get('master_key') if data else master
        if master != MASTER_KEY:
            return {"error": "Unauthorized"}, 401
        
        target_key = request.query_params.get('target_key')
        if request.method == 'POST':
            data = await request.json()
            if data:
                target_key = data.get('target_key', target_key)
        if not target_key:
            return {"error": "Missing parameter"}, 400
        
        global ALLOWED_KEYS
        if target_key not in ALLOWED_KEYS:
            return {"error": "Not found"}, 404
        
        del ALLOWED_KEYS[target_key]
        save_keys()
        
        log_msg = f"[DELETE LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Удален ключ: '{target_key}'"
        print(log_msg)
        
        return {"success": True, "message": "Removed"}
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/key/list', methods=['GET'])
async def list_keys(request: Request):
    try:
        master = request.headers.get('X-Master-Key') or request.query_params.get('master_key')
        if master != MASTER_KEY:
            return {"error": "Unauthorized"}, 401
        return {"allowed_api_keys": ALLOWED_KEYS}
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/', methods=['GET'])
async def home():
    return {"name": "EasyApi", "author": "@y3Huk_iphone"}

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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port, workers=1)
