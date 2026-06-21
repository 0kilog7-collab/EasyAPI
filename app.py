from flask import Flask, request, jsonify
import requests
import re
import os
import json
import secrets
import string
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

# Включение автоформатирования и поддержка кириллицы в JSON
app.config['JSON_AS_ASCII'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
try:
    app.json.ensure_ascii = False
    app.json.compact = False
except AttributeError:
    pass

# ТВОЙ КАСТОМНЫЙ ГЛАВНЫЙ КЛЮЧ
MASTER_KEY = "hsjdjfhrnjdjd72jrhfbsbxjdndn772hdjd92hrjdjx72nrkfusk8qkrklmrwoco52jrmfn95eufjr"

# ГАРАНТИРОВАННЫЙ ПУТЬ: Директория, где физически находится этот файл App.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Пути к файлам в папке сервера
KEYS_FILE = os.path.join(BASE_DIR, "api_keys.json")
LOG_FILE = os.path.join(BASE_DIR, "keys_log.txt")

# Действующие токены внешних сервисов из твоей конфигурации
DEPSEARCH_TOKEN = "WDTHx2vqZGE38gchBe7oAewzB9ZPNpxU"
SNUSBASE_KEY = "sb5029dec66mht55m78fx8bsw6tm8a"
OFDATA_KEY = "DiC9ALodH5T12BfR"

DEPSEARCH_BASE = "https://api.depsearch.sbs"
SNUSBASE_URL = "https://api.snusbase.com/data/search"
OFDATA_BASE = "https://api.ofdata.ru/v2"

# Функция для текстового логирования операций с ключами в файл keys_log.txt
def write_to_log(message):
    print(message)  # Вывод в консоль сервера
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{message}\n")
    except Exception as e:
        print(f"[ERROR LOGGING] Не удалось записать лог в файл: {e}")

# Функция для генерации случайного безопасного API-ключа
def generate_random_key(length=24):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Вспомогательная функция для парсинга времени (10days, 2hours, 30mins)
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

# Автоматическая инициализация и миграция базы API-ключей в формат словаря
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

# Загружаем ключи в оперативную память
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
                # Логируем автоматическую блокировку просроченного ключа в файл
                log_msg = f"[EXPIRED LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Ключ '{auth_key}' заблокирован. Срок действия истек ({expires_at_str})."
                write_to_log(log_msg)
                return False
        return True
    return False

# Полный перечень поддерживаемых явных параметров поиска
SUPPORTED_PARAMS = ['phone', 'email', 'tiktok', 'address', 'vk', 'nick', 'pass', 'snils', 'inn', 'ip', 'auto', 'text']

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
    if q_lower.startswith('snils') or (re.match(r'^\d{11}$', re.sub(r'[^\d]', '', q)) and len(re.sub(r'[^\d]', '', q)) == 11):
        return "snils"
    if q_lower.startswith('inn') or (re.match(r'^\d{10}$|^\d{12}$', re.sub(r'[^\d]', '', q)) and len(re.sub(r'[^\d]', '', q)) in [10, 12]):
        return "inn"
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', q):
        return "email"
    if q_lower.startswith('ip:') or re.match(r'^(\d{1,3}\.){3}\d{1,3}$', q):
        return "ip"
    if re.match(r'^[78][\d]{10}$', re.sub(r'[^\d]', '', q)):
        return "phone"
    if re.match(r'^[A-HJ-NPR-Z0-9]{17}$', q, re.IGNORECASE) or re.match(r'^[A-ZА-Я]\d{3}[A-ZА-Я]{2}\d{2,3}$', q, re.IGNORECASE):
        return "auto"
    
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

    url = f"{DEPSEARCH_BASE}/quest={requests.utils.quote(quest)}&token={DEPSEARCH_TOKEN}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            return {"source": "DepSearch", "data": r.json()}
        return {"source": "DepSearch", "error": r.status_code}
    except:
        return {"source": "DepSearch", "error": "timeout"}

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
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
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
    elif search_type == "text":
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

# --- ЭНДПОИНТЫ УПРАВЛЕНИЯ КЛЮЧАМИ ДОСТУПА ---

@app.route('/key/create', methods=['POST', 'GET'])
def create_key():
    master = request.headers.get("X-Master-Key") or request.args.get("master_key")
    if not master and request.is_json:
        master = request.get_json(silent=True).get("master_key")
        
    if master != MASTER_KEY:
        return jsonify({"error": "Unauthorized. Invalid or missing Master Key."}), 401
        
    new_key = request.args.get("new_key")
    duration_param = request.args.get("duration")
    
    if not new_key and request.is_json:
        json_data = request.get_json(silent=True) or {}
        new_key = json_data.get("new_key")
        duration_param = json_data.get("duration")
        
    global ALLOWED_KEYS

    # Если имя ключа не указано — генерируем случайный
    if not new_key:
        while True:
            new_key = generate_random_key(24)
            if new_key not in ALLOWED_KEYS:
                break
    else:
        if new_key in ALLOWED_KEYS:
            return jsonify({"error": "This API key already exists."}), 400
        
    # Расчет даты окончания действия ключа
    expires_at_str = None
    if duration_param:
        time_delta = parse_duration(duration_param)
        if time_delta:
            expire_datetime = datetime.now() + time_delta
            expires_at_str = expire_datetime.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return jsonify({"error": "Invalid duration format. Use '10days', '5hours', '30mins' etc."}), 400
            
    # Сохранение ключа
    ALLOWED_KEYS[new_key] = {"expires_at": expires_at_str}
    save_keys_to_file()
    
    # Запись в файл логов keys_log.txt рядом со скриптом
    log_msg = f"[CREATE LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Создан API-ключ: '{new_key}' | Истекает: {expires_at_str if expires_at_str else 'Никогда'}"
    write_to_log(log_msg)
    
    return jsonify({
        "success": True, 
        "message": "API key successfully generated and logged into file.",
        "key": new_key,
        "expires_at": expires_at_str if expires_at_str else "Permanent"
    })

@app.route('/key/delete', methods=['POST', 'GET'])
def delete_key():
    master = request.headers.get("X-Master-Key") or request.args.get("master_key")
    if not master and request.is_json:
        master = request.get_json(silent=True).get("master_key")
        
    if master != MASTER_KEY:
        return jsonify({"error": "Unauthorized. Invalid or missing Master Key."}), 401
        
    target_key = request.args.get("target_key")
    if not target_key and request.is_json:
        target_key = request.get_json(silent=True).get("target_key")
        
    if not target_key:
        return jsonify({"error": "Missing 'target_key' parameter."}), 400
        
    global ALLOWED_KEYS
    if target_key not in ALLOWED_KEYS:
        return jsonify({"error": "API key not found."}), 404
        
    del ALLOWED_KEYS[target_key]
    save_keys_to_file()
    
    # Запись удаления ключа в файл логов
    log_msg = f"[DELETE LOG] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Удален API-ключ: '{target_key}'"
    write_to_log(log_msg)
    
    return jsonify({"success": True, "message": f"API key '{target_key}' successfully removed and logged."})

@app.route('/key/list', methods=['GET'])
def list_keys():
    master = request.headers.get("X-Master-Key") or request.args.get("master_key")
    if master != MASTER_KEY:
        return jsonify({"error": "Unauthorized. Invalid or missing Master Key."}), 401
    return jsonify({"allowed_api_keys": ALLOWED_KEYS})

# --- ОСНОВНОЙ ПОИСК ---

@app.route('/search', methods=['POST', 'GET'])
def search():
    if not check_auth():
        return jsonify({"error": "Unauthorized. Invalid, missing or expired API key."}), 401

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
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(depsearch, query, search_type): "ds"}
        
        if search_type in ["email", "pass"]:
            futures[executor.submit(snusbase, query, search_type)] = "sn"
            
        if search_type in ["inn", "text"]:
            futures[executor.submit(ofdata, query, search_type)] = "of"
            
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
        "sources": ["DepSearch", "Snusbase", "Ofdata"]
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
