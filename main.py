#!/usr/bin/env python3

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import httpx

CONFIG = {
    "HOST": "0.0.0.0",
    "PORT": 8000,
    "MASTER_API_KEY": "hsjdjfhrnjdjd72jrhfbsbxjdndn772hdjd92hrjdjx72nrkfusk8qkrklmrwoco52jrmfn95eufjr",
    "EXTERNAL_APIS": {
        "snusbase": {
            "api_key": "sb5029dec66mht55m78fx8bsw6tm8a",
            "base_url": "https://api.snusbase.com",
            "timeout": 30
        },
        "infinity": {
            "api_key": "N7xQ4Lp2ZWk8F5VcD1mR9H6TyU3E0BJa",
            "base_url": "https://infinity-search.fun",
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
        "depsearch": {
            "api_key": "WDTHx2vqZGE38gchBe7oAewzB9ZPNpxU",
            "base_url": "https://api.depsearch.sbs",
            "timeout": 30
        },
        "fadeapi": {
            "api_key": "jupit-54cb687d48b31e8234d6ab7f4f",
            "base_url": "https://graph.maybebot.icu",
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
        }
    },
    "DEFAULT_RATE_LIMIT": 1000,
    "DEFAULT_RATE_LIMIT_PERIOD": 3600,
    "LOG_LEVEL": "INFO",
    "LOG_FILE": "search_aggregator.log"
}

def setup_logging():
    logging.basicConfig(
        level=getattr(logging, CONFIG["LOG_LEVEL"]),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(CONFIG["LOG_FILE"]),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

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
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "status": self.status.value,
            "created_at": self.created_at,
            "rate_limit": self.rate_limit,
            "rate_limit_period": self.rate_limit_period,
            "request_count": self.request_count,
            "last_used": self.last_used
        }

class UnifiedResponse(BaseModel):
    success: bool
    query_type: str
    query_value: str
    results: List[Dict[str, Any]]
    sources: Dict[str, Any]
    timestamp: str
    error: Optional[str] = None

class CreateKeyRequest(BaseModel):
    rate_limit: Optional[int] = Field(default=CONFIG["DEFAULT_RATE_LIMIT"])
    rate_limit_period: Optional[int] = Field(default=CONFIG["DEFAULT_RATE_LIMIT_PERIOD"])

class UpdateKeyRequest(BaseModel):
    rate_limit: Optional[int] = None
    rate_limit_period: Optional[int] = None

class APIKeyManager:
    def __init__(self):
        self.keys: Dict[str, APIKeyInfo] = {}
        self.master_key = CONFIG["MASTER_API_KEY"]
        self._initialize_master_key()
    
    def _initialize_master_key(self):
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
    
    def create_key(self, rate_limit: int = CONFIG["DEFAULT_RATE_LIMIT"],
                   rate_limit_period: int = CONFIG["DEFAULT_RATE_LIMIT_PERIOD"]) -> str:
        new_key = f"sk_{uuid.uuid4().hex}"
        key_info = APIKeyInfo(
            key=new_key,
            status=APIKeyStatus.ACTIVE,
            created_at=datetime.utcnow().isoformat(),
            rate_limit=rate_limit,
            rate_limit_period=rate_limit_period,
            request_count=0
        )
        self.keys[new_key] = key_info
        logger.info(f"Created new API key: {new_key}")
        return new_key
    
    def delete_key(self, key: str) -> bool:
        if key == self.master_key:
            logger.warning("Attempted to delete master key")
            return False
        if key in self.keys:
            del self.keys[key]
            logger.info(f"Deleted API key: {key}")
            return True
        return False
    
    def disable_key(self, key: str) -> bool:
        if key == self.master_key:
            logger.warning("Attempted to disable master key")
            return False
        if key in self.keys:
            self.keys[key].status = APIKeyStatus.DISABLED
            logger.info(f"Disabled API key: {key}")
            return True
        return False
    
    def enable_key(self, key: str) -> bool:
        if key in self.keys:
            self.keys[key].status = APIKeyStatus.ACTIVE
            logger.info(f"Enabled API key: {key}")
            return True
        return False
    
    def get_all_keys(self) -> List[Dict[str, Any]]:
        return [key_info.to_dict() for key_info in self.keys.values()]
    
    def get_key_stats(self, key: str) -> Optional[Dict[str, Any]]:
        if key in self.keys:
            return self.keys[key].to_dict()
        return None
    
    def check_rate_limit(self, key: str) -> bool:
        if key not in self.keys:
            return False
        
        key_info = self.keys[key]
        
        if key_info.rate_limit == -1:
            return True
        
        if key_info.request_count >= key_info.rate_limit:
            logger.warning(f"Rate limit exceeded for key: {key}")
            return False
        
        return True
    
    def record_request(self, key: str):
        if key in self.keys:
            self.keys[key].request_count += 1
            self.keys[key].last_used = datetime.utcnow().isoformat()

api_key_manager = APIKeyManager()

class HTTPClient:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
    
    async def close(self):
        await self.client.aclose()
    
    async def get(self, url: str, headers: Optional[Dict[str, str]] = None,
                  params: Optional[Dict[str, Any]] = None,
                  timeout: int = 30) -> Dict[str, Any]:
        try:
            response = await self.client.get(
                url,
                headers=headers,
                params=params,
                timeout=timeout
            )
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException:
            logger.error(f"Timeout error for URL: {url}")
            return {"error": "timeout", "message": "Request timed out"}
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error for URL {url}: {e.response.status_code}")
            return {"error": "http_error", "status_code": e.response.status_code, "message": str(e)}
        except httpx.RequestError as e:
            logger.error(f"Request error for URL {url}: {str(e)}")
            return {"error": "request_error", "message": str(e)}
        except json.JSONDecodeError:
            logger.error(f"JSON decode error for URL: {url}")
            return {"error": "json_error", "message": "Invalid JSON response"}
        except Exception as e:
            logger.error(f"Unexpected error for URL {url}: {str(e)}")
            return {"error": "unexpected_error", "message": str(e)}
    
    async def post(self, url: str, headers: Optional[Dict[str, str]] = None,
                   json_data: Optional[Dict[str, Any]] = None,
                   timeout: int = 30) -> Dict[str, Any]:
        try:
            response = await self.client.post(
                url,
                headers=headers,
                json=json_data,
                timeout=timeout
            )
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException:
            logger.error(f"Timeout error for URL: {url}")
            return {"error": "timeout", "message": "Request timed out"}
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error for URL {url}: {e.response.status_code}")
            return {"error": "http_error", "status_code": e.response.status_code, "message": str(e)}
        except httpx.RequestError as e:
            logger.error(f"Request error for URL {url}: {str(e)}")
            return {"error": "request_error", "message": str(e)}
        except json.JSONDecodeError:
            logger.error(f"JSON decode error for URL: {url}")
            return {"error": "json_error", "message": "Invalid JSON response"}
        except Exception as e:
            logger.error(f"Unexpected error for URL {url}: {str(e)}")
            return {"error": "unexpected_error", "message": str(e)}

http_client = HTTPClient()

class SearchService:
    def __init__(self, service_name: str, config: Dict[str, Any]):
        self.service_name = service_name
        self.api_key = config.get("api_key", "")
        self.base_url = config.get("base_url", "")
        self.timeout = config.get("timeout", 30)
    
    async def search_phone(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "Phone search not supported"}
    
    async def search_email(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "Email search not supported"}
    
    async def search_ip(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "IP search not supported"}
    
    async def search_vk(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "VK search not supported"}
    
    async def search_inn(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "INN search not supported"}
    
    async def search_passport(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "Passport search not supported"}
    
    async def search_snils(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "SNILS search not supported"}
    
    async def search_fio(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "FIO search not supported"}
    
    async def search_ogrn(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "OGRN search not supported"}
    
    async def search_company(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "Company search not supported"}
    
    async def search_address(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "Address search not supported"}
    
    async def search_car(self, query: str) -> Dict[str, Any]:
        return {"error": "not_supported", "message": "Car search not supported"}

class SnusbaseService(SearchService):
    async def search_phone(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/search/phone"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        params = {"query": query}
        return await http_client.get(url, headers=headers, params=params, timeout=self.timeout)
    
    async def search_email(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/search/email"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        params = {"query": query}
        return await http_client.get(url, headers=headers, params=params, timeout=self.timeout)

class InfinityService(SearchService):
    async def search_phone(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/phone"
        headers = {"X-API-Key": self.api_key}
        params = {"phone": query}
        return await http_client.get(url, headers=headers, params=params, timeout=self.timeout)
    
    async def search_email(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/email"
        headers = {"X-API-Key": self.api_key}
        params = {"email": query}
        return await http_client.get(url, headers=headers, params=params, timeout=self.timeout)
    
    async def search_inn(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/inn"
        headers = {"X-API-Key": self.api_key}
        params = {"inn": query}
        return await http_client.get(url, headers=headers, params=params, timeout=self.timeout)
    
    async def search_fio(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/fio"
        headers = {"X-API-Key": self.api_key}
        params = {"fio": query}
        return await http_client.get(url, headers=headers, params=params, timeout=self.timeout)
    
    async def search_ogrn(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/ogrn"
        headers = {"X-API-Key": self.api_key}
        params = {"ogrn": query}
        return await http_client.get(url, headers=headers, params=params, timeout=self.timeout)
    
    async def search_company(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/company"
        headers = {"X-API-Key": self.api_key}
        params = {"company": query}
        return await http_client.get(url, headers=headers, params=params, timeout=self.timeout)
    
    async def search_address(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/address"
        headers = {"X-API-Key": self.api_key}
        params = {"address": query}
        return await http_client.get(url, headers=headers, params=params, timeout=self.timeout)
    
    async def search_car(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/car"
        headers = {"X-API-Key": self.api_key}
        params = {"car": query}
        return await http_client.get(url, headers=headers, params=params, timeout=self.timeout)

class SeonService(SearchService):
    async def search_phone(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/phone"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        json_data = {"phone": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)

class HTMLWebService(SearchService):
    async def search_phone(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/geo/api.php"
        params = {"json": "1", "telcod": query[:7]}
        return await http_client.get(url, params=params, timeout=self.timeout)

class DepSearchService(SearchService):
    async def search_phone(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_email(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_ip(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_vk(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_inn(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_passport(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_snils(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_fio(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_ogrn(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_company(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_address(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)
    
    async def search_car(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/quest={query}&token={self.api_key}"
        headers = {"Accept": "application/json"}
        return await http_client.get(url, headers=headers, timeout=self.timeout)

class FadeAPIService(SearchService):
    async def search_phone(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "phone", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_email(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "email", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_ip(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "ip", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_vk(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "vk", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_inn(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "inn", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_passport(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "passport", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_snils(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "snils", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_fio(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "fio", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_ogrn(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "ogrn", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_company(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "company", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_address(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "address", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)
    
    async def search_car(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/japi/v2/search"
        headers = {"access_token": self.api_key, "Content-Type": "application/json"}
        json_data = {"search_type": "car", "query": query}
        return await http_client.post(url, headers=headers, json_data=json_data, timeout=self.timeout)

class ShodanService(SearchService):
    async def search_ip(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/shodan/host/{query}"
        params = {"key": self.api_key}
        return await http_client.get(url, params=params, timeout=self.timeout)

class VKService(SearchService):
    async def search_vk(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/method/users.get"
        params = {
            "user_ids": query,
            "access_token": self.api_key,
            "v": "5.131"
        }
        return await http_client.get(url, params=params, timeout=self.timeout)

class OFDataService(SearchService):
    async def search_inn(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v2/person"
        params = {"key": self.api_key, "inn": query}
        return await http_client.get(url, params=params, timeout=self.timeout)
    
    async def search_fio(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v2/search"
        params = {"key": self.api_key, "fio": query}
        return await http_client.get(url, params=params, timeout=self.timeout)
    
    async def search_ogrn(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v2/company"
        params = {"key": self.api_key, "ogrn": query}
        return await http_client.get(url, params=params, timeout=self.timeout)
    
    async def search_company(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v2/company"
        params = {"key": self.api_key, "query": query}
        return await http_client.get(url, params=params, timeout=self.timeout)
    
    async def search_address(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v2/search"
        params = {"key": self.api_key, "address": query}
        return await http_client.get(url, params=params, timeout=self.timeout)

search_services: Dict[str, SearchService] = {}

def initialize_services():
    external_apis = CONFIG["EXTERNAL_APIS"]
    
    service_classes = {
        "snusbase": SnusbaseService,
        "infinity": InfinityService,
        "seon": SeonService,
        "htmlweb": HTMLWebService,
        "depsearch": DepSearchService,
        "fadeapi": FadeAPIService,
        "shodan": ShodanService,
        "vk": VKService,
        "ofdata": OFDataService
    }
    
    for service_name, service_config in external_apis.items():
        if service_name in service_classes:
            search_services[service_name] = service_classes[service_name](service_name, service_config)
            logger.info(f"Initialized search service: {service_name}")

initialize_services()

SEARCH_TYPE_MAPPING = {
    SearchType.PHONE: ["snusbase", "infinity", "seon", "htmlweb", "depsearch", "fadeapi"],
    SearchType.EMAIL: ["snusbase", "infinity", "depsearch", "fadeapi"],
    SearchType.IP: ["shodan", "depsearch", "fadeapi"],
    SearchType.VK: ["vk", "depsearch", "fadeapi"],
    SearchType.INN: ["ofdata", "infinity", "depsearch", "fadeapi"],
    SearchType.PASSPORT: ["ofdata", "infinity", "depsearch", "fadeapi"],
    SearchType.SNILS: ["ofdata", "infinity", "depsearch", "fadeapi"],
    SearchType.FIO: ["ofdata", "infinity", "depsearch", "fadeapi"],
    SearchType.OGRN: ["ofdata", "infinity", "depsearch", "fadeapi"],
    SearchType.COMPANY: ["ofdata", "infinity", "depsearch", "fadeapi"],
    SearchType.ADDRESS: ["ofdata", "infinity", "depsearch", "fadeapi"],
    SearchType.CAR: ["ofdata", "infinity", "depsearch", "fadeapi"]
}

class SearchAggregator:
    async def search(self, search_type: SearchType, query: str) -> UnifiedResponse:
        results = []
        sources = {}
        
        service_names = SEARCH_TYPE_MAPPING.get(search_type, [])
        
        tasks = []
        for service_name in service_names:
            if service_name in search_services:
                task = self._search_service(service_name, search_type, query)
                tasks.append(task)
        
        if tasks:
            service_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for service_name, result in zip(service_names, service_results):
                if isinstance(result, Exception):
                    logger.error(f"Error in service {service_name}: {str(result)}")
                    sources[service_name] = {
                        "success": False,
                        "error": str(result)
                    }
                else:
                    sources[service_name] = {
                        "success": "error" not in result,
                        "data": result
                    }
                    if "error" not in result and isinstance(result, dict):
                        results.append(result)
        
        return UnifiedResponse(
            success=len(results) > 0,
            query_type=search_type.value,
            query_value=query,
            results=results,
            sources=sources,
            timestamp=datetime.utcnow().isoformat()
        )
    
    async def _search_service(self, service_name: str, search_type: SearchType, query: str) -> Dict[str, Any]:
        service = search_services.get(service_name)
        if not service:
            return {"error": "service_not_found", "message": f"Service {service_name} not found"}
        
        method_map = {
            SearchType.PHONE: service.search_phone,
            SearchType.EMAIL: service.search_email,
            SearchType.IP: service.search_ip,
            SearchType.VK: service.search_vk,
            SearchType.INN: service.search_inn,
            SearchType.PASSPORT: service.search_passport,
            SearchType.SNILS: service.search_snils,
            SearchType.FIO: service.search_fio,
            SearchType.OGRN: service.search_ogrn,
            SearchType.COMPANY: service.search_company,
            SearchType.ADDRESS: service.search_address,
            SearchType.CAR: service.search_car
        }
        
        method = method_map.get(search_type)
        if method:
            return await method(query)
        else:
            return {"error": "not_supported", "message": f"Search type {search_type.value} not supported by {service_name}"}

search_aggregator = SearchAggregator()

app = FastAPI(
    title="Search API Aggregator",
    description="Unified API for searching across multiple open-source search services",
    version="1.0.0"
)

@app.on_event("startup")
async def startup_event():
    logger.info("Starting Search API Aggregator...")
    logger.info(f"Master API Key: {CONFIG['MASTER_API_KEY'][:10]}...")
    logger.info(f"Configured services: {list(search_services.keys())}")

@app.on_event("shutdown")
async def shutdown_event():
    await http_client.close()
    logger.info("HTTP client closed")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    logger.info(f"Request: {request.method} {request.url}")
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    logger.info(f"Response: {response.status_code} - {process_time:.3f}s")
    
    return response

@app.get("/search", response_model=UnifiedResponse)
async def search(
    request: Request,
    phone: Optional[str] = Query(None, description="Phone number"),
    email: Optional[str] = Query(None, description="Email address"),
    ip: Optional[str] = Query(None, description="IP address"),
    vk: Optional[str] = Query(None, description="VK ID"),
    inn: Optional[str] = Query(None, description="INN"),
    passport: Optional[str] = Query(None, description="Passport number"),
    snils: Optional[str] = Query(None, description="SNILS"),
    fio: Optional[str] = Query(None, description="Full name"),
    ogrn: Optional[str] = Query(None, description="OGRN"),
    company: Optional[str] = Query(None, description="Company name"),
    address: Optional[str] = Query(None, description="Address"),
    car: Optional[str] = Query(None, description="Car license plate"),
    api: str = Query(..., description="API key")
):
    if not api_key_manager.is_valid_key(api):
        logger.warning(f"Invalid API key used: {api[:10]}...")
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    
    if not api_key_manager.check_rate_limit(api):
        logger.warning(f"Rate limit exceeded for key: {api[:10]}...")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    search_params = {
        "phone": phone,
        "email": email,
        "ip": ip,
        "vk": vk,
        "inn": inn,
        "passport": passport,
        "snils": snils,
        "fio": fio,
        "ogrn": ogrn,
        "company": company,
        "address": address,
        "car": car
    }
    
    provided_params = {k: v for k, v in search_params.items() if v is not None}
    
    if len(provided_params) == 0:
        raise HTTPException(status_code=400, detail="At least one search parameter must be provided")
    
    if len(provided_params) > 1:
        raise HTTPException(status_code=400, detail="Only one search parameter can be used per request")
    
    param_name, query_value = next(iter(provided_params.items()))
    search_type = SearchType(param_name)
    
    api_key_manager.record_request(api)
    
    logger.info(f"Search request: {search_type.value}={query_value} from key {api[:10]}...")
    
    result = await search_aggregator.search(search_type, query_value)
    
    return result

def verify_master_key(api_key: str) -> bool:
    return api_key_manager.is_master_key(api_key)

@app.post("/master/keys")
async def create_key(
    request: CreateKeyRequest,
    x_api_key: str = Header(..., description="Master API key")
):
    if not verify_master_key(x_api_key):
        raise HTTPException(status_code=403, detail="Master API key required")
    
    new_key = api_key_manager.create_key(
        rate_limit=request.rate_limit,
        rate_limit_period=request.rate_limit_period
    )
    
    logger.info(f"New API key created by master: {new_key}")
    
    return {"key": new_key, "message": "API key created successfully"}

@app.delete("/master/keys/{key}")
async def delete_key(
    key: str,
    x_api_key: str = Header(..., description="Master API key")
):
    if not verify_master_key(x_api_key):
        raise HTTPException(status_code=403, detail="Master API key required")
    
    if api_key_manager.delete_key(key):
        logger.info(f"API key deleted by master: {key}")
        return {"message": "API key deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="API key not found or cannot be deleted")

@app.put("/master/keys/{key}/disable")
async def disable_key(
    key: str,
    x_api_key: str = Header(..., description="Master API key")
):
    if not verify_master_key(x_api_key):
        raise HTTPException(status_code=403, detail="Master API key required")
    
    if api_key_manager.disable_key(key):
        logger.info(f"API key disabled by master: {key}")
        return {"message": "API key disabled successfully"}
    else:
        raise HTTPException(status_code=404, detail="API key not found")

@app.put("/master/keys/{key}/enable")
async def enable_key(
    key: str,
    x_api_key: str = Header(..., description="Master API key")
):
    if not verify_master_key(x_api_key):
        raise HTTPException(status_code=403, detail="Master API key required")
    
    if api_key_manager.enable_key(key):
        logger.info(f"API key enabled by master: {key}")
        return {"message": "API key enabled successfully"}
    else:
        raise HTTPException(status_code=404, detail="API key not found")

@app.get("/master/keys")
async def list_keys(
    x_api_key: str = Header(..., description="Master API key")
):
    if not verify_master_key(x_api_key):
        raise HTTPException(status_code=403, detail="Master API key required")
    
    keys = api_key_manager.get_all_keys()
    
    return {"keys": keys}

@app.get("/master/keys/{key}/stats")
async def get_key_stats(
    key: str,
    x_api_key: str = Header(..., description="Master API key")
):
    if not verify_master_key(x_api_key):
        raise HTTPException(status_code=403, detail="Master API key required")
    
    stats = api_key_manager.get_key_stats(key)
    
    if stats:
        return stats
    else:
        raise HTTPException(status_code=404, detail="API key not found")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": list(search_services.keys())
    }

def main():
    uvicorn.run(
        app,
        host=CONFIG["HOST"],
        port=CONFIG["PORT"],
        log_level=CONFIG["LOG_LEVEL"].lower()
    )

if __name__ == "__main__":
    main()


