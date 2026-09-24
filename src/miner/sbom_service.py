import json
import subprocess
from pathlib import Path
from typing import Optional, Tuple


class SbomRunner:

    @staticmethod
    def get_syft_version() -> str:
        """Obtiene la versión instalada de Syft."""
        try:
            res = subprocess.run(
                ["syft", "--version"],
                capture_output=True,
                text=True,
                check=True,
            )
            return res.stdout.strip()
        except Exception:
            return "Unknown"

    @staticmethod
    def get_commit_hash(repo_path: Path) -> str:
        """Obtiene el hash del commit HEAD del repositorio local."""
        try:
            res = subprocess.run(
                ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            return res.stdout.strip()
        except Exception:
            return "unknown"

    @staticmethod
    def generate_sbom(
        repo_path: Path, output_dir: Path
    ) -> Tuple[str, int, Optional[str], Optional[str]]:
        """Ejecuta Syft para generar el CycloneDX JSON de un repositorio.

        Retorna: (status, components_count, sbom_file_path, error_reason)
        """
        repo_name = repo_path.name
        sbom_file = output_dir / f"{repo_name}_sbom.json"

        # Ejecución de Syft sobre la carpeta local exportando a CycloneDX JSON
        cmd = ["syft", f"dir:{repo_path}", "-o", f"cyclonedx-json={sbom_file}"]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)

            if proc.returncode != 0:
                err_msg = (
                    proc.stderr.strip()
                    or f"Syft finalizó con código {proc.returncode}"
                )
                return "failed", 0, None, err_msg

            if not sbom_file.exists():
                return (
                    "failed",
                    0,
                    None,
                    "No se encontró el archivo SBOM generado.",
                )

            # Contar componentes leyendo el JSON de CycloneDX
            with open(sbom_file, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)
                components = sbom_data.get("components", [])
                comp_count = len(components)

            # Distinguir entre éxito con componentes y sin componentes
            status = "success" if comp_count > 0 else "no_components"
            return status, comp_count, str(sbom_file.resolve()), None

        except Exception as e:
            return "failed", 0, None, str(e)