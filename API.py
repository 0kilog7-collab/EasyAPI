"""
Универсальный API-шлюз для пробива
Запуск: uvicorn router_api:app --host 0.0.0.0 --port 8080
"""

import asyncio
import json
import re
import time
import hashlib
from typing import Optional, Any, Dict, List
from datetime import datetime
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
import httpx
import aiohttp
from pydantic import BaseModel

app = FastAPI(title="Router API Gateway", version="1.0")

# ====== ВСЕ КЛЮЧИ И ТОКЕНЫ ======
CONFIG = {
    # Snusbase
    "SNUSBASE_KEYS": ["sb5029dec66mht55m78fx8bsw6tm8a", "sbmeovhou6ecsn9fd9wcwnwwvsvwnc"],
    "SNUSBASE_URL": "https://api.snusbase.com/data/search",
    
    # Ofdata
    "OFDATA_KEY": "DiC9ALodH5T12BfR",
    "OFDATA_BASE": "https://api.ofdata.ru/v2",
    
    # Infinity
    "INFINITY_KEY": "N7xQ4Lp2ZWk8F5VcD1mR9H6TyU3E0BJa",
    "INFINITY_URL": "https://infinity-search.fun/find.php",
    
    # SEON
    "SEON_KEY": "758f5f54-befb-4125-bd17-931689af6633",
    "SEON_URL": "https://api.seon.io/SeonRestService/phone-api/v2",
    
    # Shodan
    "SHODAN_KEY": "i7SlTEgdEoz3aNPKn6tH7aHFKwqmPrPF",
    "SHODAN_KEY_2": "pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM",
    
    # FadeAPI
    "FADE_KEY": "jupit-54cb687d48b31e8234d6ab7f4f",
    "FADE_URL": "https://graph.maybebot.icu/japi/v2/search",
    
    # DeepScan
    "DEEPSCAN_KEY": "deepscan_5277564584:ckycv9yS",
    "DEEPSCAN_URL": "https://deepscan.cc/api/v1/search",
    
    # Cryven
    "CRYVEN_KEY": "%40Oliver_FloresSS%3ARRCqVLUb",
    "CRYVEN_BASE": "https://cryven.info",
    
    # DepSearch
    "DEPSEARCH_TOKEN": "WDTHx2vqZGE38gchBe7oAewzB9ZPNpxU",
    "DEPSEARCH_BACKUP_TOKEN": "XV1rGjJyryowCyGMKqfJ72ozJtF0bhoF",
    
    # SMSC
    "SMSC_LOGIN": "kirahacker333",
    "SMSC_PSW": "Zangar5050!",
    
    # NumLookup
    "NUMLOOKUP_KEY": "num_live_sL8EgCimFaiqCAxcd8peRCkInxUWX2Zg1h1ceMIf",
    
    # IPGeo
    "IPGEO_API_KEY": "73d99145d2e948779263360bfeb67ecc",
    
    # AbuseIPDB
    "ABUSEIPDB_KEY": "70bcb231c3ae0194917804f23f6f96843bffec2bf2304f09f24b327c3f340d2d769689af42c8790d",
    
    # Hunter
    "HUNTER_API_KEY": "c750a854258bf1a9c264f6166ca7e34f0a3c783d",
    
    # LeakCheck
    "LEAKCHECK_KEY": "4344cd645b6e6cc2559c1a92017d9bfa12e4e4b1",
    
    # VK
    "VK_TOKEN": "0af157510af157510af15751aa0a89e69600af10af157516a0bc15996e74fe2b440998c",
    
    # Локальная база
    "API_BASE": "http://94.26.90.84:8000",
    "API_TOKEN": "5KDOIVqn9uvDD17LsThnnwZjMAZsAUEiFtDPhcyc",
}

# ====== МОДЕЛИ ДЛЯ ЗАПРОСОВ ======
class SearchRequest(BaseModel):
    query: str
    type: str  # phone, email, ip, vk, nick, inn, passport, snils, fio, car, address, password

# ====== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ======
def clean_phone(phone: str) -> str:
    phone = re.sub(r'[\s\-\(\)\+]', '', phone)
    if phone.startswith('8') and len(phone) == 11:
        phone = '7' + phone[1:]
    if len(phone) == 10 and phone.startswith('9'):
        phone = '7' + phone
    return phone

def clean_ip(ip: str) -> Optional[str]:
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if pattern.match(ip):
        return ip
    return None

def clean_email(email: str) -> Optional[str]:
    pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    if pattern.match(email):
        return email.lower()
    return None

async def http_get(url: str, headers: dict = None, timeout: float = 10.0) -> Optional[Any]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            r = await client.get(url, headers=headers)
            if r.status_code == 200:
                try:
                    return r.json()
                except:
                    return r.text
        except:
            return None
    return None

async def http_post(url: str, headers: dict = None, json_data: dict = None, timeout: float = 10.0) -> Optional[Any]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            r = await client.post(url, headers=headers, json=json_data)
            if r.status_code == 200:
                try:
                    return r.json()
                except:
                    return r.text
        except:
            return None
    return None

# ====== ПРОВЕРКИ ПО РАЗНЫМ API ======
async def check_cryven(query: str) -> Optional[Any]:
    url = f"{CONFIG['CRYVEN_BASE']}/api/search?search={query}&key={CONFIG['CRYVEN_KEY']}"
    return await http_get(url, timeout=20.0)

async def check_depsearch(query: str) -> Optional[Any]:
    for token in [CONFIG['DEPSEARCH_TOKEN'], CONFIG['DEPSEARCH_BACKUP_TOKEN']]:
        for url in [
            f"https://api.depsearch.sbs/quest={query}&token={token}",
            f"https://api.depsearch.sbs/?quest={query}&token={token}",
        ]:
            result = await http_get(url, headers={"Accept": "application/json"}, timeout=12.0)
            if result:
                return result
    return None

async def check_snusbase(query: str, search_type: str = "email") -> Optional[Any]:
    for key in CONFIG['SNUSBASE_KEYS']:
        headers = {"Content-Type": "application/json", "Auth": key}
        payload = {"terms": [query], "types": [search_type], "wildcard": False}
        result = await http_post(CONFIG['SNUSBASE_URL'], headers=headers, json_data=payload, timeout=10.0)
        if result:
            return result
    return None

async def check_ofdata(query: str, search_type: str) -> Optional[Any]:
    type_map = {
        "inn": ("person", "inn"), "phone": ("search", "phone"), "email": ("search", "email"),
        "passport": ("person", "passport"), "snils": ("person", "snils"), "fio": ("search", "fio"),
        "ogrn": ("company", "ogrn"), "company": ("company", "query")
    }
    endpoint, param = type_map.get(search_type, ("search", "query"))
    url = f"{CONFIG['OFDATA_BASE']}/{endpoint}?key={CONFIG['OFDATA_KEY']}&{param}={query}"
    return await http_get(url, timeout=10.0)

async def check_infinity(query: str, search_type: str) -> Optional[Any]:
    param_map = {"phone": "phone", "email": "email", "fio": "fio", "фио": "fio"}
    param = param_map.get(search_type, "fio")
    url = f"{CONFIG['INFINITY_URL']}?{param}={query}&token={CONFIG['INFINITY_KEY']}"
    return await http_get(url, timeout=10.0)

async def check_seon(phone: str) -> Optional[Any]:
    clean = re.sub(r'[^\d]', '', phone)
    headers = {"X-API-KEY": CONFIG['SEON_KEY'], "Content-Type": "application/json"}
    return await http_post(CONFIG['SEON_URL'], headers=headers, json_data={"phone": clean}, timeout=10.0)

async def check_fadeapi(query: str, search_type: str) -> Optional[Any]:
    headers = {"access_token": CONFIG['FADE_KEY'], "Content-Type": "application/json"}
    payload = {"search_type": search_type, "query": query}
    return await http_post(CONFIG['FADE_URL'], headers=headers, json_data=payload, timeout=15.0)

async def check_deepscan(query: str, search_type: str) -> Optional[Any]:
    headers = {"Content-Type": "application/json"}
    payload = {"api_key": CONFIG['DEEPSCAN_KEY'], "query": query, "type": search_type}
    return await http_post(CONFIG['DEEPSCAN_URL'], headers=headers, json_data=payload, timeout=15.0)

async def check_leakcheck(query: str) -> Optional[Any]:
    url = f"https://leakcheck.net/api/public?key={CONFIG['LEAKCHECK_KEY']}&check={query}"
    return await http_get(url, timeout=10.0)

async def check_smsc(phone: str) -> Optional[Any]:
    url = f"https://smsc.ru/sys/info.php?get_operator=1&login={CONFIG['SMSC_LOGIN']}&psw={CONFIG['SMSC_PSW']}&phone={phone}"
    return await http_get(url, timeout=8.0)

async def check_numlookup(phone: str) -> Optional[Any]:
    url = f"https://api.numlookupapi.com/v1/validate/{phone}?apikey={CONFIG['NUMLOOKUP_KEY']}"
    return await http_get(url, timeout=8.0)

async def check_vk_official(user_id: str) -> Optional[Any]:
    url = f"https://api.vk.com/method/users.get?user_ids={user_id}&access_token={CONFIG['VK_TOKEN']}&v=5.199&fields=first_name,last_name,bdate,city,country,contacts,online"
    result = await http_get(url, timeout=8.0)
    if result and 'response' in result:
        return result['response']
    return None

async def check_local_db(query: str, endpoint: str) -> Optional[Any]:
    url = f"{CONFIG['API_BASE']}/{endpoint}?token={CONFIG['API_TOKEN']}&q={query}"
    return await http_get(url, timeout=15.0)

# ====== ОСНОВНОЙ ПОИСК ======
async def search_all(query: str, search_type: str) -> Dict[str, Any]:
    results = {}
    
    # Очистка данных
    if search_type == "phone":
        query = clean_phone(query)
    elif search_type == "email":
        query = clean_email(query)
    elif search_type == "ip":
        query = clean_ip(query)
    
    # Параллельный запуск всех проверок
    tasks = {}
    
    # Базовые проверки для всех типов
    tasks["cryven"] = check_cryven(query)
    tasks["depsearch"] = check_depsearch(query)
    tasks["local_db"] = check_local_db(query, search_type)
    tasks["fadeapi"] = check_fadeapi(query, search_type)
    tasks["deepscan"] = check_deepscan(query, search_type)
    tasks["snusbase"] = check_snusbase(query, "email")
    
    # Дополнительные проверки в зависимости от типа
    if search_type in ["phone", "email", "fio"]:
        tasks["infinity"] = check_infinity(query, search_type)
        tasks["leakcheck"] = check_leakcheck(query)
        tasks["ofdata"] = check_ofdata(query, search_type)
    
    if search_type == "phone":
        tasks["seon"] = check_seon(query)
        tasks["smsc"] = check_smsc(query)
        tasks["numlookup"] = check_numlookup(query)
    
    if search_type == "vk":
        tasks["vk_official"] = check_vk_official(query)
    
    if search_type == "ip":
        tasks["shodan"] = await http_get(f"https://api.shodan.io/shodan/host/{query}?key={CONFIG['SHODAN_KEY']}", timeout=10.0)
        tasks["shodan_v2"] = await http_get(f"https://api.shodan.io/shodan/host/{query}?key={CONFIG['SHODAN_KEY_2']}", timeout=10.0)
        tasks["ipinfo"] = await http_get(f"https://ipinfo.io/{query}/json", timeout=8.0)
        tasks["ipwhois"] = await http_get(f"https://ipwhois.app/json/{query}", timeout=8.0)
        tasks["abuseipdb"] = await http_get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={query}&maxAgeInDays=90",
            headers={"Key": CONFIG['ABUSEIPDB_KEY'], "Accept": "application/json"},
            timeout=8.0
        )
    
    # Запускаем все задачи параллельно
    for name, coro in tasks.items():
        try:
            results[name] = await coro
        except Exception as e:
            results[name] = {"error": str(e)}
    
    return results

# ====== API ENDPOINTS ======
@app.get("/")
async def root():
    return {
        "service": "Router API Gateway",
        "version": "1.0",
        "endpoints": {
            "/search": "POST - универсальный поиск",
            "/search/phone": "GET - поиск по номеру",
            "/search/email": "GET - поиск по email",
            "/search/ip": "GET - поиск по IP",
            "/search/vk": "GET - поиск по VK ID",
            "/search/nick": "GET - поиск по никнейму",
            "/search/inn": "GET - поиск по ИНН",
            "/search/passport": "GET - поиск по паспорту",
            "/search/snils": "GET - поиск по СНИЛС",
            "/search/fio": "GET - поиск по ФИО",
            "/search/car": "GET - поиск по авто",
            "/search/address": "GET - поиск по адресу",
            "/search/password": "GET - поиск по паролю",
        }
    }

@app.post("/search")
async def search(request: SearchRequest):
    """Универсальный поиск"""
    if not request.query:
        raise HTTPException(status_code=400, detail="Query is required")
    
    results = await search_all(request.query, request.type)
    return JSONResponse(content={
        "query": request.query,
        "type": request.type,
        "timestamp": datetime.now().isoformat(),
        "results": results
    })

@app.get("/search/phone")
async def search_phone(query: str = Query(..., description="Номер телефона")):
    results = await search_all(query, "phone")
    return JSONResponse(content={"query": query, "type": "phone", "results": results})

@app.get("/search/email")
async def search_email(query: str = Query(..., description="Email")):
    results = await search_all(query, "email")
    return JSONResponse(content={"query": query, "type": "email", "results": results})

@app.get("/search/ip")
async def search_ip(query: str = Query(..., description="IP адрес")):
    results = await search_all(query, "ip")
    return JSONResponse(content={"query": query, "type": "ip", "results": results})

@app.get("/search/vk")
async def search_vk(query: str = Query(..., description="VK ID")):
    results = await search_all(query, "vk")
    return JSONResponse(content={"query": query, "type": "vk", "results": results})

@app.get("/search/nick")
async def search_nick(query: str = Query(..., description="Никнейм")):
    results = await search_all(query, "nick")
    return JSONResponse(content={"query": query, "type": "nick", "results": results})

@app.get("/search/inn")
async def search_inn(query: str = Query(..., description="ИНН")):
    results = await search_all(query, "inn")
    return JSONResponse(content={"query": query, "type": "inn", "results": results})

@app.get("/search/passport")
async def search_passport(query: str = Query(..., description="Паспорт")):
    results = await search_all(query, "passport")
    return JSONResponse(content={"query": query, "type": "passport", "results": results})

@app.get("/search/snils")
async def search_snils(query: str = Query(..., description="СНИЛС")):
    results = await search_all(query, "snils")
    return JSONResponse(content={"query": query, "type": "snils", "results": results})

@app.get("/search/fio")
async def search_fio(query: str = Query(..., description="ФИО")):
    results = await search_all(query, "fio")
    return JSONResponse(content={"query": query, "type": "fio", "results": results})

@app.get("/search/car")
async def search_car(query: str = Query(..., description="Номер авто")):
    results = await search_all(query, "car")
    return JSONResponse(content={"query": query, "type": "car", "results": results})

@app.get("/search/address")
async def search_address(query: str = Query(..., description="Адрес")):
    results = await search_all(query, "address")
    return JSONResponse(content={"query": query, "type": "address", "results": results})

@app.get("/search/password")
async def search_password(query: str = Query(..., description="Пароль")):
    results = await search_all(query, "password")
    return JSONResponse(content={"query": query, "type": "password", "results": results})

# ====== ЗАПУСК ======
if __name__ == "__main__":
    import uvicorn
    print("Router API Gateway запускается...")
    uvicorn.run(app, host="0.0.0.0", port=8080)
