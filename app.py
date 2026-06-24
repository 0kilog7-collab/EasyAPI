from fastapi import FastAPI, HTTPException, Depends
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
    if re.match(r'^\+?\d{10,15}$', re.sub(r'[^\d+]', '', q)):
        return "phone"
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', q):
        return "email"
    if re.match(r'^\d{10}$|^\d{12}$', re.sub(r'[^\d]', '', q)):
        return "inn"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', q):
        return "ip"
    return "text"

async def snusbase(query: str):
    async with httpx.AsyncClient(timeout=8) as client:
        payload = {
            "terms": [query],
            "types": ["email"],
            "wildcard": False
        }
        for key in SNUSBASE_KEYS:
            try:
                r = await client.post(SNUSBASE_URL, json=payload, headers={"Auth": key})
                if r.status_code == 200:
                    return r.json()
            except:
                continue
    return None

async def ofdata(query: str):
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            r = await client.get(f"{OFDATA_BASE}/search?key={OFDATA_KEY}&query={query}")
            if r.status_code == 200:
                return r.json()
        except:
            pass
    return None

async def infinity_check(query: str):
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            r = await client.get(f"{INFINITY_URL}?fio={query}&token={INFINITY_KEY}")
            if r.status_code == 200:
                return r.json()
        except:
            pass
    return None

async def lookup_vk(query: str):
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            r = await client.get(f"https://api.vk.com/method/users.get?user_ids={query}&access_token={VK_TOKEN}&v=5.199")
            if r.status_code == 200:
                return r.json()
        except:
            pass
    return None

async def lookup_shodan(query: str):
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            r = await client.get(f"{SHODAN_BASE_URL}/shodan/host/{query}?key={SHODAN_KEY}")
            if r.status_code == 200:
                return r.json()
        except:
            pass
    return None

class SearchRequest(BaseModel):
    query: str
    api_key: str

@app.post("/search")
async def search(req: SearchRequest, x_forwarded_for: Optional[str] = None):
    client_ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else "127.0.0.1"
    
    if not await check_auth(req.api_key, client_ip):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    query = re.sub(r'[^a-zA-Z0-9\s@\.\-_+:яёА-ЯЁ]', '', req.query)
    search_type = detect_type(query)
    
    tasks = []
    if search_type in ["email", "pass"]:
        tasks.append(snusbase(query))
    if search_type in ["inn", "text", "фио", "fio", "snils", "passport", "ogrn", "company"]:
        tasks.append(ofdata(query))
    if search_type in ["phone", "email", "text", "фио", "fio", "company"]:
        tasks.append(infinity_check(query))
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

@app.get("/")
async def home():
    return {"name": "EasyApi", "author": "@y3Huk_iphone"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port, workers=1)
