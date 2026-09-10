import subprocess
import os

class CodeQLRunner:
    def __init__(self, db_base_dir: str = "temp/codeql_db", sarif_base_dir: str = "temp/sarif_results"):
        self.db_base_dir = db_base_dir
        self.sarif_base_dir = sarif_base_dir
        os.makedirs(self.db_base_dir, exist_ok=True)
        os.makedirs(self.sarif_base_dir, exist_ok=True)

    def create_database(self, repo_path: str, repo_name: str, language: str) -> str:
        db_path = os.path.join(self.db_base_dir, f"{repo_name}_db")
        
        cmd = [
            "codeql", "database", "create", db_path,
            f"--language={language}",
            f"--source-root={repo_path}",
            "--overwrite"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Error al crear la base de datos CodeQL: {result.stderr}")

        return db_path

    def analyze_database(self, db_path: str, repo_name: str, language: str) -> str:
        sarif_path = os.path.join(self.sarif_base_dir, f"{repo_name}.sarif")
        
        # Especificamos el paquete oficial directamente
        query_suite = f"codeql/{language}-queries"

        cmd = [
            "codeql", "database", "analyze", db_path,
            query_suite,
            "--format=sarifv2.1.0",
            f"--output={sarif_path}",
            "--download"  # Descarga automáticamente las consultas si faltan
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Error al analizar la base de datos con CodeQL: {result.stderr}")

        return sarif_path