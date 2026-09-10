import os
import requests
from typing import List, Dict, Any

class GitHubClient:
    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")
        if not self.token:
            raise ValueError("La variable de entorno GITHUB_TOKEN no está configurada.")
        
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json"
        }

    def get_organization_repos(self, org_name: str) -> List[Dict[str, Any]]:
        repos = []
        page = 1
        per_page = 100

        while True:
            url = f"https://api.github.com/orgs/{org_name}/repos?per_page={per_page}&page={page}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code != 200:
                raise Exception(f"Error al consultar API de GitHub ({response.status_code}): {response.json().get('message')}")
            
            data = response.json()
            if not data:
                break
                
            repos.extend(data)
            page += 1

        return repos