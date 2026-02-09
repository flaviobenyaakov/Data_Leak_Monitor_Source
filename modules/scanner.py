import requests
import time
import os

class DataLeakScanner:
    def __init__(self, hibp_api_key=None, intelx_api_key=None, dehashed_api_key=None, dehashed_email=None):
        self.hibp_api_key = hibp_api_key
        self.intelx_api_key = intelx_api_key
        self.dehashed_api_key = dehashed_api_key
        self.dehashed_email = dehashed_email
        self.user_agent = "DataLeakMonitor/1.0 (LGPD Compliance System)"

    def scan_hibp(self, account):
        """Varre o Have I Been Pwned para uma conta específica."""
        if not self.hibp_api_key:
            return {"error": "HIBP API Key not provided"}
        
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
        headers = {
            "hibp-api-key": self.hibp_api_key,
            "user-agent": self.user_agent
        }
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return [] # Nenhuma brecha encontrada
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def scan_intelx(self, term):
        """Varre o IntelX para um termo (email, CPF, etc)."""
        if not self.intelx_api_key:
            return {"error": "IntelX API Key not provided"}
        
        # 1. Iniciar busca
        search_url = "https://2.intelx.io/intelligent/search"
        headers = {"x-key": self.intelx_api_key}
        data = {
            "term": term,
            "maxresults": 10,
            "media": 0,
            "timeout": 20
        }
        
        try:
            search_resp = requests.post(search_url, headers=headers, json=data)
            if search_resp.status_code != 200:
                return {"error": f"Search failed: {search_resp.status_code}"}
            
            search_id = search_resp.json().get("id")
            
            # 2. Obter resultados (polling simples para exemplo)
            time.sleep(2)
            result_url = f"https://2.intelx.io/intelligent/search/result?id={search_id}"
            result_resp = requests.get(result_url, headers=headers)
            
            if result_resp.status_code == 200:
                return result_resp.json().get("records", [])
            else:
                return {"error": f"Result fetch failed: {result_resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def scan_dehashed(self, query):
        """Varre o DeHashed para uma consulta."""
        if not self.dehashed_api_key or not self.dehashed_email:
            return {"error": "DeHashed credentials not provided"}
        
        url = f"https://api.dehashed.com/light/search?query={query}"
        auth = (self.dehashed_email, self.dehashed_api_key)
        headers = {"Accept": "application/json"}
        
        try:
            response = requests.get(url, auth=auth, headers=headers)
            if response.status_code == 200:
                return response.json().get("entries", [])
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def full_scan(self, target_data):
        """Realiza uma varredura completa em todas as fontes configuradas."""
        results = {
            "target": target_data,
            "hibp": self.scan_hibp(target_data) if "@" in target_data else "N/A",
            "intelx": self.scan_intelx(target_data),
            "dehashed": self.scan_dehashed(f'email:"{target_data}"') if "@" in target_data else self.scan_dehashed(f'username:"{target_data}"')
        }
        return results
