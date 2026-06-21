from flask import Flask, request, jsonify
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

# Ключ авторизации доступа к шлюзу
GATEWAY_API_KEY = "hdhxhs827dhsb"

DEPSEARCH_TOKEN = "WDTHx2vqZGE38gchBe7oAewzB9ZPNpxU"
SNUSBASE_KEY = "sb5029dec66mht55m78fx8bsw6tm8a"

DEPSEARCH_BASE = "https://api.depsearch.sbs"
SNUSBASE_URL = "https://api.snusbase.com/data/search"

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
    
    # 1. TikTok
    if q_lower.startswith('tt:') or 'tiktok.com' in q_lower:
        return "tiktok"
    # 2. Адрес
    if q_lower.startswith(('г.', 'addr:', 'адрес:')):
        return "address"
    # 3. ВКонтакте
    if 'vk.com/' in q_lower or q_lower.startswith('vkid'):
        return "vk"
    # 4. Никнейм
    if q_lower.startswith('nick:'):
        return "nick"
    # 5. Пароль
    if q_lower.startswith('pass:'):
        return "pass"
    # 6. СНИЛС
    if q_lower.startswith('snils') or (re.match(r'^\d{11}$', re.sub(r'[^\d]', '', q)) and len(re.sub(r'[^\d]', '', q)) == 11):
        return "snils"
    # 7. ИНН
    if q_lower.startswith('inn') or (re.match(r'^\d{10}$|^\d{12}$', re.sub(r'[^\d]', '', q)) and len(re.sub(r'[^\d]', '', q)) in [10, 12]):
        return "inn"
    # 8. Email
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', q):
        return "email"
    # 9. IP-адрес
    if q_lower.startswith('ip:') or re.match(r'^(\d{1,3}\.){3}\d{1,3}$', q):
        return "ip"
    # 10. Телефон
    if re.match(r'^[78][\d]{10}$', re.sub(r'[^\d]', '', q)):
        return "phone"
    # 11. Авто (ГРЗ / VIN)
    # VIN: 17 символов; ГРЗ: Стандартный паттерн РФ (Буква 3Цифры 2Буквы Регион)
    if re.match(r'^[A-HJ-NPR-Z0-9]{17}$', q, re.IGNORECASE) or re.match(r'^[A-ZА-Я]\d{3}[A-ZА-Я]{2}\d{2,3}$', q, re.IGNORECASE):
        return "auto"
    
    # 12. ФИО / Текст (дефолт)
    return "text"

def depsearch(query, search_type):
    q = str(query).strip()
    
    # Форматирование под синтаксис роутера DepSearch согласно документации
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
        # Передаем чистую строку цифр, пробелы/скобки удаляются, роутер DepSearch съедает автоматически
        quest = re.sub(r'[^\d]', '', q)
        
    else:
        # Для address, nick, pass, auto, email, text — передаем как есть (роутер парсит сам)
        quest = q

    # Прямая сборка URL эндпоинта по спецификации: Base URL + /quest=ЗНАЧЕНИЕ&token=ТОКЕН&lang=ru
    url = f"{DEPSEARCH_BASE}/quest={requests.utils.quote(quest)}&token={DEPSEARCH_TOKEN}&lang=ru"
    
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return {"source": "DepSearch", "data": r.json()}
        return {"source": "DepSearch", "error": r.status_code}
    except Exception as e:
        return {"source": "DepSearch", "error": "timeout_or_connection_error"}

def snusbase(query):
    try:
        headers = {"Content-Type": "application/json", "Auth": SNUSBASE_KEY}
        payload = {
            "terms": [query],
            "types": ["email"],
            "wildcard": False
        }
        r = requests.post(SNUSBASE_URL, headers=headers, json=payload, timeout=15)
        if r.status_code == 200:
            return {"source": "Snusbase", "data": r.json()}
        return {"source": "Snusbase", "error": r.status_code}
    except:
        return {"source": "Snusbase", "error": "timeout"}

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
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(depsearch, query, search_type): "ds"}
        if search_type == "email":
            futures[executor.submit(snusbase, query)] = "sn"
            
        for future in as_completed(futures):
            res = future.result()
            if res and ("data" in res or "error" in res):
                result["sources"].append(res)
    
    result["found"] = len([s for s in result["sources"] if "data" in s]) > 0
    return jsonify(result)

@app.route('/')
def home():
    return jsonify({
        "name": "Clearance API Gateway",
        "version": "1.3",
        "author": "@y3Huk_iphone",
        "sources": ["DepSearch", "Snusbase"],
        "endpoint": f"/search?query=79277231370&api_key={GATEWAY_API_KEY}"
    })

@app.route('/status')
def status():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "status": "online",
        "sources": ["DepSearch", "Snusbase"],
        "limits": {
            "depsearch": "70 requests/min",
            "snusbase": "2048 requests/12h"
        }
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
