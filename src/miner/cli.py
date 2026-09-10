import os
import typer
from miner.models import OrganizationReport, Summary, RepositoryReport
from miner.github_client import GitHubClient
from miner.repository_manager import RepositoryManager
from miner.codeql_runner import CodeQLRunner
from miner.sarif_parser import SarifParser

app = typer.Typer(help="Miner de vulnerabilidades para organizaciones de GitHub")

@app.callback()
def main():
    """Herramienta de análisis estático con CodeQL."""
    pass

@app.command("scan")
def scan(
    organization: str = typer.Option(..., "--organization", "-o", help="Nombre de la organización de GitHub"),
    output: str = typer.Option("results.json", "--output", "-out", help="Archivo JSON de salida")
):
    typer.echo(f"Iniciando análisis para la organización: {organization}")
    
    # 1. Obtención de repositorios vía GitHub API
    try:
        client = GitHubClient()
        repos_data = client.get_organization_repos(organization)
    except Exception as e:
        typer.echo(f"Error crítico al comunicarse con GitHub: {e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Se encontraron {len(repos_data)} repositorios.")
    
    repo_manager = RepositoryManager()
    codeql_runner = CodeQLRunner()
    
    repo_reports = []
    summary = Summary(repositories=len(repos_data))

    # 2. Procesamiento individual por cada repositorio
    for repo in repos_data:
        repo_name = repo["name"]
        repo_url = repo["html_url"]
        clone_url = repo["clone_url"]
        primary_lang = (repo.get("language") or "").lower()

        typer.echo(f"\n[+] Procesando repositorio: {repo_name}...")

        # Mapeo de lenguajes
        CODEQL_LANGUAGES = {
            "python": "python",
            "javascript": "javascript",
            "typescript": "javascript",
            "java": "java",
            "c++": "cpp",
            "c": "cpp",
            "c#": "csharp",
            "go": "go",
            "ruby": "ruby",
            "swift": "swift"
        }

        if not primary_lang or primary_lang not in CODEQL_LANGUAGES:
            typer.echo(f"    [-] Lenguaje '{primary_lang}' no soportado o no detectado. Omitiendo.")
            repo_reports.append(RepositoryReport(
                name=repo_name,
                url=repo_url,
                status="unsupported",
                languages=[primary_lang] if primary_lang else [],
                error_reason="Lenguaje no soportado por CodeQL"
            ))
            summary.unsupported += 1
            continue

        codeql_lang = CODEQL_LANGUAGES[primary_lang]
        repo_path = None

        try:
            typer.echo(f"    -> Clonando {repo_name}...")
            repo_path = repo_manager.clone_repository(clone_url, repo_name)

            typer.echo(f"    -> Creando base de datos CodeQL ({codeql_lang})...")
            db_path = codeql_runner.create_database(repo_path, repo_name, codeql_lang)

            typer.echo("    -> Ejecutando análisis de seguridad...")
            sarif_path = codeql_runner.analyze_database(db_path, repo_name, codeql_lang)

            findings = SarifParser.parse(sarif_path)
            typer.echo(f"    [✓] Análisis completado. Hallazgos encontrados: {len(findings)}")

            repo_reports.append(RepositoryReport(
                name=repo_name,
                url=repo_url,
                status="analyzed",
                languages=[codeql_lang],
                findings=findings
            ))
            summary.analyzed += 1
            summary.findings += len(findings)

        except RuntimeError as err:
            typer.echo(f"    [!] Error durante el proceso: {err}", err=True)
            repo_reports.append(RepositoryReport(
                name=repo_name,
                url=repo_url,
                status="failed",
                languages=[codeql_lang],
                error_reason=str(err)
            ))
            summary.failed += 1

        except Exception as e:
            typer.echo(f"    [!] Error inesperado: {e}", err=True)
            repo_reports.append(RepositoryReport(
                name=repo_name,
                url=repo_url,
                status="failed",
                languages=[codeql_lang],
                error_reason=f"Error inesperado: {e}"
            ))
            summary.failed += 1

        finally:
            if repo_path:
                repo_manager.remove_repository(repo_path)

    # Consolidación y ordenamiento estable
    report = OrganizationReport(
        organization=organization,
        summary=summary,
        repositories=repo_reports
    )
    report.sort_results()

    # Guardar archivo JSON
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))

    typer.echo(f"\nProceso finalizado. El reporte consolidado fue guardado en: {output}")

if __name__ == "__main__":
    app()