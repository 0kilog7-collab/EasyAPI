#!/usr/bin/env python3

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import httpx

CONFIG = {
    "HOST": "0.0.0.0",
    "PORT": 8000,
    "MASTER_API_KEY": "hsjdjfhrnjdjd72jrhfbsbxjdndn772hdjd92hrjdjx72nrkfusk8qkrklmrwoco52jrmfn95eufjr",
    "EXTERNAL_APIS": {
        "snusbase": {
            "api_key": "sb5029dec66mht55m78fx8bsw6tm8a",
            "backup_key": "sbmeovhou6ecsn9fd9wcwnwwvsvwnc",
            "base_url": "https://api.snusbase.com",
            "timeout": 30
        },
        "depsearch": {
            "api_key": "w8wxpMncT84SyYSDobV6zSFdZGqcnAoJ",
            "base_url": "https://api.depsearch.sbs",
            "timeout": 30
        },
        "seon": {
            "api_key": "758f5f54-befb-4125-bd17-931689af6633",
            "base_url": "https://api.seon.io",
            "timeout": 30
        },
        "htmlweb": {
            "api_key": "",
            "base_url": "https://htmlweb.ru",
            "timeout": 30
        },
        "shodan": {
            "api_key": "xx6gSg9pWYmJcND1hEMbcWuOJtjbHSZ5",
            "base_url": "https://api.shodan.io",
            "timeout": 30
        },
        "vk": {
            "api_key": "0af157510af157510af15751aa0a89e69600af10af157516a0bc15996e74fe2b440998c",
            "base_url": "https://api.vk.com",
            "timeout": 30
        },
        "ofdata": {
            "api_key": "DiC9ALodH5T12BfR",
            "base_url": "https://api.ofdata.ru",
            "timeout": 30
        },
        "cryven": {
            "api_key": "%40Oliver_FloresSS%3ARRCqVLUb",
            "base_url": "https://cryven.info",
            "timeout": 30
        },
        "bigbase": {
            "api_key": "hEtcNRmBOGUxGwHX9NfOccaIXbyqCmRF",
            "base_url": "https://bigbase.top/api",
            "timeout": 30
        }
    },
    "DEFAULT_RATE_LIMIT": 1000,
    "DEFAULT_RATE_LIMIT_PERIOD": 3600,
    "LOG_LEVEL": "INFO",
    "LOG_FILE": "search_aggregator.log"
}

logging.basicConfig(level=getattr(logging, CONFIG["LOG_LEVEL"]))
logger = logging.getLogger(__name__)

class SearchType(Enum):
    PHONE = "phone"
    EMAIL = "email"
    IP = "ip"
    VK = "vk"
    INN = "inn"
    PASSPORT = "passport"
    SNILS = "snils"
    FIO = "fio"
    OGRN = "ogrn"
    COMPANY = "company"
    ADDRESS = "address"
    CAR = "car"

class APIKeyStatus(Enum):
    ACTIVE = "active"
    DISABLED = "disabled"

@dataclass
class APIKeyInfo:
    key: str
    status: APIKeyStatus
    created_at: str
    rate_limit: int
    rate_limit_period: int
    request_count: int
    last_used: Optional[str] = None

class APIKeyManager:
    def __init__(self):
        self.keys: Dict[str, APIKeyInfo] = {}
        self.master_key = CONFIG["MASTER_API_KEY"]
        master_info = APIKeyInfo(
            key=self.master_key,
            status=APIKeyStatus.ACTIVE,
            created_at=datetime.utcnow().isoformat(),
            rate_limit=-1,
            rate_limit_period=0,
            request_count=0
        )
        self.keys[self.master_key] = master_info
        logger.info("Master API key initialized")
    
    def is_master_key(self, key: str) -> bool:
        return key == self.master_key
    
    def is_valid_key(self, key: str) -> bool:
        if key not in self.keys:
            return False
        return self.keys[key].status == APIKeyStatus.ACTIVE
    
    def create_key(self, rate_limit: int = 1000, rate_limit_period: int = 3600) -> str:
        new_key = f"sk_{uuid.uuid4().hex}"
        self.keys[new_key] = APIKeyInfo(
            key=new_key,
            status=APIKeyStatus.ACTIVE,
            created_at=datetime.utcnow().isoformat(),
            rate_limit=rate_limit,
            rate_limit_period=rate_limit_period,
            request_count=0
        )
        return new_key
    
    def delete_key(self, key: str) -> bool:
        if key == self.master_key:
            return False
        if key in self.keys:
            del self.keys[key]
            return True
        return False
    
    def get_all_keys(self):
        return [k.to_dict() for k in self.keys.values()]

api_key_manager = APIKeyManager()

class HTTPClient:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
    
    async def get(self, url, headers=None, params=None, timeout=30):
        try:
            r = await self.client.get(url, headers=headers, params=params, timeout=timeout)
            return r.json()
        except Exception as e:
            return {"error": str(e)}
    
    async def post(self, url, headers=None, json_data=None, timeout=30):
        try:
            r = await self.client.post(url, headers=headers, json=json_data, timeout=timeout)
            return r.json()
        except Exception as e:
            return {"error": str(e)}

http_client = HTTPClient()

class SearchService:
    def __init__(self, name: str, config: dict):
        self.name = name
        self.config = config
        self.api_key = config.get("api_key", "")
        self.base_url = config.get("base_url", "")
        self.timeout = config.get("timeout", 30)

class SnusbaseService(SearchService):
    async def search_phone(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/data/search"
        for key in [self.api_key, self.config.get("backup_key")]:
            try:
                headers = {"Content-Type": "application/json", "Auth": key}
                payload = {"terms": [query], "types": ["email"], "wildcard": False}
                result = await http_client.post(url, headers=headers, json_data=payload, timeout=self.timeout)
                if "error" not in result:
                    return result
            except:
                continue
        return {"error": "All Snusbase keys failed"}
    
    async def search_email(self, query: str) -> Dict[str, Any]:
        return await self.search_phone(query)

class DepSearchService(SearchService):
    async def search(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&lang=ru&token={self.api_key}"
        return await http_client.get(url, headers={"Accept": "application/json"}, timeout=self.timeout)
    
    async def search_phone(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_email(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_ip(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_vk(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_inn(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_passport(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_snils(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_fio(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_ogrn(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_company(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_address(self, query: str) -> Dict[str, Any]:
        return await self.search(query)
    
    async def search_car(self, query: str) -> Dict[str, Any]:
        return await self.search(query)

class SEONService(SearchService):
    async def search_phone(self, query: str):
        url = f"{self.base_url}/v1/phone"
        headers = {"X-API-KEY": self.api_key}
        return await http_client.post(url, headers=headers, json={"phone": query})

class HTMLWebService(SearchService):
    async def search_phone(self, query: str):
        url = f"{self.base_url}/geo/api.php"
        return await http_client.get(url, params={"json": 1, "telcod": query[:7]})

class ShodanService(SearchService):
    async def search_ip(self, query: str):
        url = f"{self.base_url}/shodan/host/{query}"
        return await http_client.get(url, params={"key": self.api_key})

class VKService(SearchService):
    async def search_vk(self, query: str):
        url = f"{self.base_url}/method/users.get"
        return await http_client.get(url, params={"user_ids": query, "access_token": self.api_key, "v": "5.131"})

class OFDataService(SearchService):
    async def search_inn(self, query: str):
        url = f"{self.base_url}/v2/person"
        return await http_client.get(url, params={"key": self.api_key, "inn": query})
    
    async def search_ogrn(self, query: str):
        url = f"{self.base_url}/v2/company"
        return await http_client.get(url, params={"key": self.api_key, "ogrn": query})
    
    async def search_company(self, query: str):
        url = f"{self.base_url}/v2/company"
        return await http_client.get(url, params={"key": self.api_key, "query": query})

class CryvenService(SearchService):
    async def search(self, query: str):
        url = f"{self.base_url}/api/search"
        return await http_client.get(url, params={"search": query, "key": self.api_key})

class BigBaseService(SearchService):
    async def search(self, query: str):
        url = f"{self.base_url}/search"
        headers = {"Authorization": self.api_key}
        return await http_client.post(url, headers=headers, json={"search": query, "page": 1})

search_services = {
    "snusbase": SnusbaseService("snusbase", CONFIG["EXTERNAL_APIS"]["snusbase"]),
    "depsearch": DepSearchService("depsearch", CONFIG["EXTERNAL_APIS"]["depsearch"]),
    "seon": SEONService("seon", CONFIG["EXTERNAL_APIS"]["seon"]),
    "htmlweb": HTMLWebService("htmlweb", CONFIG["EXTERNAL_APIS"]["htmlweb"]),
    "shodan": ShodanService("shodan", CONFIG["EXTERNAL_APIS"]["shodan"]),
    "vk": VKService("vk", CONFIG["EXTERNAL_APIS"]["vk"]),
    "ofdata": OFDataService("ofdata", CONFIG["EXTERNAL_APIS"]["ofdata"]),
    "cryven": CryvenService("cryven", CONFIG["EXTERNAL_APIS"]["cryven"]),
    "bigbase": BigBaseService("bigbase", CONFIG["EXTERNAL_APIS"]["bigbase"])
}

SEARCH_TYPE_MAPPING = {
    SearchType.PHONE: ["snusbase", "depsearch", "seon", "htmlweb", "cryven", "bigbase"],
    SearchType.EMAIL: ["snusbase", "depsearch", "cryven", "bigbase"],
    SearchType.IP: ["depsearch", "shodan", "cryven", "bigbase"],
    SearchType.VK: ["depsearch", "vk", "cryven", "bigbase"],
    SearchType.INN: ["depsearch", "ofdata", "cryven", "bigbase"],
    SearchType.PASSPORT: ["depsearch", "cryven", "bigbase"],
    SearchType.SNILS: ["depsearch", "cryven", "bigbase"],
    SearchType.FIO: ["depsearch", "cryven", "bigbase"],
    SearchType.OGRN: ["depsearch", "ofdata", "cryven", "bigbase"],
    SearchType.COMPANY: ["depsearch", "ofdata", "cryven", "bigbase"],
    SearchType.ADDRESS: ["depsearch", "cryven", "bigbase"],
    SearchType.CAR: ["depsearch", "cryven", "bigbase"]
}

class SearchAggregator:
    async def search(self, search_type: SearchType, query: str) -> dict:
        sources = {}
        results = []
        service_names = SEARCH_TYPE_MAPPING.get(search_type, [])
        
        for name in service_names:
            service = search_services.get(name)
            if not service:
                continue
            try:
                if name == "snusbase":
                    res = await service.search_phone(query)
                elif name == "depsearch":
                    res = await service.search(query)
                elif hasattr(service, "search"):
                    res = await service.search(query)
                elif search_type == SearchType.PHONE and hasattr(service, "search_phone"):
                    res = await service.search_phone(query)
                elif search_type == SearchType.IP and hasattr(service, "search_ip"):
                    res = await service.search_ip(query)
                elif search_type == SearchType.VK and hasattr(service, "search_vk"):
                    res = await service.search_vk(query)
                elif search_type == SearchType.INN and hasattr(service, "search_inn"):
                    res = await service.search_inn(query)
                elif search_type == SearchType.OGRN and hasattr(service, "search_ogrn"):
                    res = await service.search_ogrn(query)
                elif search_type == SearchType.COMPANY and hasattr(service, "search_company"):
                    res = await service.search_company(query)
                else:
                    continue
                sources[name] = {"success": "error" not in res, "data": res}
                if "error" not in res:
                    results.append(res)
            except Exception as e:
                sources[name] = {"success": False, "error": str(e)}
        
        return {
            "success": len(results) > 0,
            "query_type": search_type.value,
            "query_value": query,
            "results": results,
            "sources": sources,
            "timestamp": datetime.utcnow().isoformat()
        }

search_aggregator = SearchAggregator()
app = FastAPI(title="Search API Aggregator", version="1.0")

@app.get("/search")
async def search(
    phone: Optional[str] = None,
    email: Optional[str] = None,
    ip: Optional[str] = None,
    vk: Optional[str] = None,
    inn: Optional[str] = None,
    passport: Optional[str] = None,
    snils: Optional[str] = None,
    fio: Optional[str] = None,
    ogrn: Optional[str] = None,
    company: Optional[str] = None,
    address: Optional[str] = None,
    car: Optional[str] = None,
    api: str = Query(...)
):
    if not api_key_manager.is_valid_key(api):
        raise HTTPException(401, "Invalid API key")
    
    params = {k: v for k, v in locals().items() if k not in ["api", "request"] and v}
    if not params:
        raise HTTPException(400, "No search parameter provided")
    if len(params) > 1:
        raise HTTPException(400, "Only one parameter allowed")
    
    key = list(params.keys())[0]
    value = list(params.values())[0]
    search_type = SearchType(key)
    
    result = await search_aggregator.search(search_type, value)
    return JSONResponse(result)

@app.post("/master/keys")
async def create_key(x_api_key: str = Header(...)):
    if not api_key_manager.is_master_key(x_api_key):
        raise HTTPException(403, "Master key required")
    new_key = api_key_manager.create_key()
    return {"key": new_key}

@app.delete("/master/keys/{key}")
async def delete_key(key: str, x_api_key: str = Header(...)):
    if not api_key_manager.is_master_key(x_api_key):
        raise HTTPException(403, "Master key required")
    if api_key_manager.delete_key(key):
        return {"message": "Deleted"}
    raise HTTPException(404, "Key not found")

@app.get("/health")
async def health():
    return {"status": "ok", "services": list(search_services.keys())}

@app.get("/")
async def root():
    return {
        "name": "Search API Aggregator",
        "version": "1.0",
        "endpoints": {
            "/search": "GET - поиск",
            "/master/keys": "POST - создать ключ",
            "/master/keys/{key}": "DELETE - удалить ключ",
            "/health": "GET - статус"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
