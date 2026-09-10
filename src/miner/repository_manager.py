import os
import shutil
import git

class RepositoryManager:
    def __init__(self, base_dir: str = "temp/cloned_repos"):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

    def clone_repository(self, clone_url: str, repo_name: str) -> str:
        repo_path = os.path.join(self.base_dir, repo_name)
        
        # Si la carpeta ya existe por un fallo previo, se elimina primero
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path, ignore_errors=True)

        git.Repo.clone_from(clone_url, repo_path)
        return repo_path

    def remove_repository(self, repo_path: str):
        if os.path.exists(repo_path):
            # Se usa ignore_errors para evitar bloqueos por permisos de archivos de Git en Windows
            shutil.rmtree(repo_path, ignore_errors=True)