from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import requests
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import uvicorn

app = FastAPI()

# ====== КЛЮЧИ ======
SNUSBASE_KEYS = ["sb5029dec66mht55m78fx8bsw6tm8a", "sbmeovhou6ecsn9fd9wcwnwwvsvwnc"]
OFDATA_KEY = "DiC9ALodH5T12BfR"
INFINITY_KEY = "N7xQ4Lp2ZWk8F5VcD1mR9H6TyU3E0BJa"
SEON_KEY = "758f5f54-befb-4125-bd17-931689af6633"
VK_TOKEN = "0af157510af157510af15751aa0a89e69600af10af157516a0bc15996e74fe2b440998c"
SHODAN_KEY = "xx6gSg9pWYmJcND1hEMbcWuOJtjbHSZ5"
DEPSEARCH_TOKEN = "WDTHx2vqZGE38gchBe7oAewzB9ZPNpxU"
DEPSEARCH_BACKUP_TOKEN = "XV1rGjJyryowCyGMKqfJ72ozJtF0bhoF"
FADE_KEY = "jupit-54cb687d48b31e8234d6ab7f4f"

# ====== URL ======
SNUSBASE_URL = "https://api.snusbase.com/data/search"
OFDATA_BASE = "https://api.ofdata.ru/v2"
INFINITY_URL = "https://infinity-search.fun/find.php"
SEON_URL = "https://api.seon.io/SeonRestService/phone-api/v2"
SHODAN_BASE_URL = "https://api.shodan.io"
FADE_URL = "https://graph.maybebot.icu/japi/v2/search"
HTMLWEB_GEO_URL = "https://htmlweb.ru/geo/api.php"

SUPPORTED_PARAMS = ['pass', 'email', 'inn', 'text', 'фио', 'fio', 'phone', 'vkid', 'ip', 'snils', 'passport', 'ogrn', 'company']

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
    if re.match(r'^[А-ЯЁA-Z][а-яёa-zА-ЯЁA-Z0-9\s\-\.\,]+$', q) and len(q) > 3:
        return "company"
    return "text"

# ====== ПРОВЕРКИ ======

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
        "inn": ("person", "inn"),
        "phone": ("search", "phone"),
        "email": ("search", "email"),
        "passport": ("person", "passport"),
        "snils": ("person", "snils"),
        "fio": ("search", "fio"),
        "фио": ("search", "fio"),
        "ogrn": ("company", "ogrn"),
        "company": ("company", "query"),
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
                "key": OFDATA_KEY,
                "first_name": parts[0],
                "last_name": parts[1],
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

    if collected_data:
        return {"source": "Ofdata", "data": collected_data}
    return {"source": "Ofdata", "error": status_code}

def infinity_check(query, search_type):
    try:
        session = requests.Session()
        from requests.adapters import HTTPAdapter
        from urllib3.util import Retry
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
            "user_ids": str(query).strip(),
            "access_token": VK_TOKEN,
            "v": "5.199",
            "fields": "first_name,last_name,bdate,city,country,contacts,online"
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

def check_htmlweb_geo(phone):
    try:
        clean = re.sub(r'[^\d]', '', str(phone).strip())
        telcod = clean[:7] if len(clean) >= 7 else clean
        url = f"{HTMLWEB_GEO_URL}?json&telcod={telcod}"
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            try:
                data = r.json()
                if data:
                    return {"source": "HTMLweb", "data": data}
            except:
                return {"source": "HTMLweb", "data": r.text}
        return {"source": "HTMLweb", "error": r.status_code}
    except Exception as e:
        return {"source": "HTMLweb", "error": str(e)}

def check_depsearch(query):
    try:
        for token in [DEPSEARCH_TOKEN, DEPSEARCH_BACKUP_TOKEN]:
            for url in [
                f"https://api.depsearch.sbs/quest={query}&token={token}",
                f"https://api.depsearch.sbs/?quest={query}&token={token}",
            ]:
                try:
                    r = requests.get(
                        url,
                        headers={"Accept": "application/json", "Referer": "https://api.depsearch.sbs/"},
                        timeout=12
                    )
                    if r.status_code == 200 and r.text and len(r.text.strip()) > 3:
                        t = r.text.strip()
                        if t.lower() not in ('null', '[]', '{}', 'false'):
                            try:
                                return {"source": "DepSearch", "data": r.json()}
                            except:
                                return {"source": "DepSearch", "data": r.text}
                except:
                    continue
        return {"source": "DepSearch", "error": "All tokens exhausted"}
    except:
        return {"source": "DepSearch", "error": 504}

def check_fadeapi(query, search_type):
    try:
        headers = {"access_token": FADE_KEY, "Content-Type": "application/json"}
        payload = {"search_type": search_type, "query": str(query).strip()}
        r = requests.post(FADE_URL, headers=headers, json=payload, timeout=15)
        if r.status_code == 200:
            try:
                return {"source": "FadeAPI", "data": r.json()}
            except:
                return {"source": "FadeAPI", "data": r.text}
        return {"source": "FadeAPI", "error": r.status_code}
    except:
        return {"source": "FadeAPI", "error": 504}

# ====== ОСНОВНОЙ ЭНДПОИНТ ======
@app.api_route("/search", methods=["GET", "POST"])
async def search(request: Request):
    try:
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
            return JSONResponse({"error": "Missing search term"}, 400)
        
        if not search_type:
            search_type = detect_type(query)
        
        result = {
            "query": query,
            "type": search_type,
            "timestamp": datetime.now().isoformat(),
            "results": {}
        }
        
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {}
            
            if search_type in ["email", "pass"]:
                futures[executor.submit(snusbase, query, search_type)] = "snusbase"
                
            if search_type in ["inn", "text", "фио", "fio", "snils", "passport", "ogrn", "company"]:
                futures[executor.submit(ofdata, query, search_type)] = "ofdata"
                
            if search_type in ["phone", "email", "text", "фио", "fio", "company"]:
                futures[executor.submit(infinity_check, query, search_type)] = "infinity"

            if search_type == "phone":
                futures[executor.submit(lookup_phone_via_seon, query)] = "seon"
                futures[executor.submit(check_htmlweb_geo, query)] = "htmlweb"

            if search_type == "vkid":
                futures[executor.submit(lookup_vk, query)] = "vk"

            if search_type == "ip":
                futures[executor.submit(lookup_shodan, query)] = "shodan"
            
            futures[executor.submit(check_depsearch, query)] = "depsearch"
            futures[executor.submit(check_fadeapi, query, search_type)] = "fadeapi"
            
            for future in as_completed(futures):
                key = futures[future]
                try:
                    res = future.result(timeout=15)
                    if res:
                        result["results"][key] = res
                except Exception as e:
                    result["results"][key] = {"error": str(e)}
        
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse({"error": "Internal server error", "details": str(e)}, 500)

@app.get("/")
async def home():
    return JSONResponse({
        "name": "EasyApi",
        "author": "@y3Huk_iphone"
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port, workers=1)
