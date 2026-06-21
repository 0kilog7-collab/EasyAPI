#!/usr/bin/env python3

from flask import Flask, request, jsonify
import requests
import re

app = Flask(__name__)

GATEWAY_API_KEY = "hdhxhs827dhsb"

OFDATA_KEY = "DiC9ALodH5T12BfR"
SNUSBASE_KEY = "sb5029dec66mht55m78fx8bsw6tm8a"

SNUSBASE_URL = "https://api.snusbase.com/data/search"

def check_auth():
    auth_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if not auth_key and request.is_json:
        data = request.get_json(silent=True)
        if data:
            auth_key = data.get("api_key")
    return auth_key == GATEWAY_API_KEY

def handle_ofdata_request(url):
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 401:
            return {"status": "error", "reason": "OFdata API key is invalid (401)"}, 401
        elif r.status_code == 429:
            return {"status": "error", "reason": "OFdata rate limit exceeded (429)"}, 429
        elif r.status_code != 200:
            return {"status": "error", "reason": f"OFdata returned status {r.status_code}"}, r.status_code
            
        res_json = r.json()
        if res_json.get('meta', {}).get('status') == 'ok':
            records = res_json.get('data', {}).get('Записи', res_json.get('data', {}))
            if records:
                return {"status": "success", "data": records}, 200
            return {"status": "error", "reason": "No records found in OFdata"}, 404
        return {"status": "error", "reason": f"OFdata meta error: {res_json.get('meta', {}).get('message')}"}, 400
    except Exception as e:
        return {"status": "error", "reason": f"OFdata connection error: {str(e)}"}, 500

def handle_snusbase_request(query):
    try:
        headers = {"Content-Type": "application/json", "Auth": SNUSBASE_KEY}
        payload = {
            "terms": [str(query).strip()],
            "types": ["email"],
            "wildcard": False
        }
        r = requests.post(SNUSBASE_URL, headers=headers, json=payload, timeout=10)
        
        if r.status_code == 401:
            return {"status": "error", "reason": "Snusbase API key is invalid (401)"}, 401
        elif r.status_code == 429:
            return {"status": "error", "reason": "Snusbase rate limit exceeded (429)"}, 429
        elif r.status_code != 200:
            return {"status": "error", "reason": f"Snusbase returned status {r.status_code}"}, r.status_code
            
        return {"status": "success", "data": r.json()}, 200
    except Exception as e:
        return {"status": "error", "reason": f"Snusbase connection error: {str(e)}"}, 500

def get_query_param():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        return data.get('query') or data.get('search')
    return request.args.get('query') or request.args.get('search')

@app.route('/search/ofdata/inn', methods=['GET', 'POST'])
def search_ofdata_inn():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401
    query = get_query_param()
    if not query: return jsonify({"error": "Missing parameter 'query'"}), 400
    
    digits = re.sub(r'[^\d]', '', str(query))
    url = f"https://api.ofdata.ru/v2/person?key={OFDATA_KEY}&inn={digits}"
    res, status_code = handle_ofdata_request(url)
    return jsonify(res), status_code

@app.route('/search/ofdata/ogrn', methods=['GET', 'POST'])
def search_ofdata_ogrn():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401
    query = get_query_param()
    if not query: return jsonify({"error": "Missing parameter 'query'"}), 400
    
    digits = re.sub(r'[^\d]', '', str(query))
    url = f"https://api.ofdata.ru/v2/inspections?key={OFDATA_KEY}&ogrn={digits}"
    res, status_code = handle_ofdata_request(url)
    return jsonify(res), status_code

@app.route('/search/ofdata/company', methods=['GET', 'POST'])
def search_ofdata_company():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401
    query = get_query_param()
    if not query: return jsonify({"error": "Missing parameter 'query'"}), 400
    
    url = f"https://api.ofdata.ru/v2/search?key={OFDATA_KEY}&by=name&obj=org&query={requests.utils.quote(str(query))}"
    res, status_code = handle_ofdata_request(url)
    return jsonify(res), status_code

@app.route('/search/ofdata/founder', methods=['GET', 'POST'])
def search_ofdata_founder():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401
    query = get_query_param()
    if not query: return jsonify({"error": "Missing parameter 'query'"}), 400
    
    url = f"https://api.ofdata.ru/v2/search?key={OFDATA_KEY}&by=founder-name&obj=org&query={requests.utils.quote(str(query))}"
    res, status_code = handle_ofdata_request(url)
    return jsonify(res), status_code

@app.route('/search/snusbase', methods=['GET', 'POST'])
def search_snusbase():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401
    query = get_query_param()
    if not query: return jsonify({"error": "Missing parameter 'query'"}), 400
    res, status_code = handle_snusbase_request(query)
    return jsonify(res), status_code

@app.route('/')
def home():
    return jsonify({
        "name": "EasyAPI",
        "version": "3.2",
        "endpoints": {
            "ofdata_inn": "/search/ofdata/inn",
            "ofdata_ogrn": "/search/ofdata/ogrn",
            "ofdata_company": "/search/ofdata/company",
            "ofdata_founder": "/search/ofdata/founder",
            "snusbase": "/search/snusbase"
        }
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
