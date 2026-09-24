import os
import sys

# Agregar la carpeta 'src' al path de Python para resolver importaciones
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from pathlib import Path
import typer
from miner.codeql_runner import CodeQLRunner
from miner.github_client import GitHubClient

# Imports actualizados con las clases y servicios de SBOM
from miner.models import (
    OrganizationReport,
    OrganizationSbomReport,
    RepositoryReport,
    RepositorySbomReport,
    SbomSummary,
    Summary,
)
from miner.repository_manager import RepositoryManager
from miner.sarif_parser import SarifParser
from miner.sbom_service import SbomRunner

app = typer.Typer(
    help="Miner de vulnerabilidades y SBOMs para organizaciones de GitHub"
)


@app.callback()
def main():
    """Herramienta de análisis estático con CodeQL y generación de SBOM con Syft."""
    pass


# ----------------------------------------------------
# COMANDO 1: CodeQL (Conservado de la Tarea 3)
# ----------------------------------------------------
@app.command("scan")
def scan(
    organization: str = typer.Option(
        ..., "--organization", "-o", help="Nombre de la organización de GitHub"
    ),
    output: str = typer.Option(
        "results.json", "--output", "-out", help="Archivo JSON de salida"
    ),
):
    typer.echo(f"Iniciando análisis para la organización: {organization}")

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

    for repo in repos_data:
        repo_name = repo["name"]
        repo_url = repo["html_url"]
        clone_url = repo["clone_url"]
        primary_lang = (repo.get("language") or "").lower()

        typer.echo(f"\n[+] Procesando repositorio: {repo_name}...")

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
            "swift": "swift",
        }

        if not primary_lang or primary_lang not in CODEQL_LANGUAGES:
            typer.echo(
                f"    [-] Lenguaje '{primary_lang}' no soportado o no detectado. Omitiendo."
            )
            repo_reports.append(
                RepositoryReport(
                    name=repo_name,
                    url=repo_url,
                    status="unsupported",
                    languages=[primary_lang] if primary_lang else [],
                    error_reason="Lenguaje no soportado por CodeQL",
                )
            )
            summary.unsupported += 1
            continue

        codeql_lang = CODEQL_LANGUAGES[primary_lang]
        repo_path = None

        try:
            typer.echo(f"    -> Clonando {repo_name}...")
            repo_path = repo_manager.clone_repository(clone_url, repo_name)

            typer.echo(
                f"    -> Creando base de datos CodeQL ({codeql_lang})..."
            )
            db_path = codeql_runner.create_database(
                repo_path, repo_name, codeql_lang
            )

            typer.echo("    -> Ejecutando análisis de seguridad...")
            sarif_path = codeql_runner.analyze_database(
                db_path, repo_name, codeql_lang
            )

            findings = SarifParser.parse(sarif_path)
            typer.echo(
                f"    [✓] Análisis completado. Hallazgos encontrados: {len(findings)}"
            )

            repo_reports.append(
                RepositoryReport(
                    name=repo_name,
                    url=repo_url,
                    status="analyzed",
                    languages=[codeql_lang],
                    findings=findings,
                )
            )
            summary.analyzed += 1
            summary.findings += len(findings)

        except RuntimeError as err:
            typer.echo(
                f"    [!] Error durante el proceso: {err}", err=True
            )
            repo_reports.append(
                RepositoryReport(
                    name=repo_name,
                    url=repo_url,
                    status="failed",
                    languages=[codeql_lang],
                    error_reason=str(err),
                )
            )
            summary.failed += 1

        except Exception as e:
            typer.echo(f"    [!] Error inesperado: {e}", err=True)
            repo_reports.append(
                RepositoryReport(
                    name=repo_name,
                    url=repo_url,
                    status="failed",
                    languages=[codeql_lang],
                    error_reason=f"Error inesperado: {e}",
                )
            )
            summary.failed += 1

        finally:
            if repo_path:
                repo_manager.remove_repository(repo_path)

    report = OrganizationReport(
        organization=organization, summary=summary, repositories=repo_reports
    )
    report.sort_results()

    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))

    typer.echo(
        f"\nProceso finalizado. El reporte consolidado fue guardado en: {output}"
    )


# ----------------------------------------------------
# COMANDO 2: Generación de SBOM con Syft (Tarea 4)
# ----------------------------------------------------
@app.command("generate-sbom")
def generate_sbom(
    repos_dir: str = typer.Option(
        ...,
        "--repos-dir",
        "-r",
        help="Directorio que contiene los repositorios clonados",
    ),
    organization: str = typer.Option(
        ..., "--organization", "-o", help="Nombre de la organización"
    ),
    output_dir: str = typer.Option(
        "./sbom_results",
        "--output-dir",
        "-out",
        help="Directorio de salida para los SBOMs y el resumen",
    ),
):
    """Genera inventarios SBOM en formato CycloneDX JSON usando Syft sobre repositorios clonados."""
    base_repo_path = Path(repos_dir)
    if not base_repo_path.exists() or not base_repo_path.is_dir():
        typer.echo(
            f"Error: El directorio de repositorios '{repos_dir}' no existe o no es válido.",
            err=True,
        )
        raise typer.Exit(code=1)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    syft_ver = SbomRunner.get_syft_version()
    typer.echo(
        f"Iniciando generación de SBOM para la organización: {organization}"
    )
    typer.echo(f"Versión de Syft detectada: {syft_ver}\n")

    sbom_reports = []

    # Iterar sobre cada carpeta dentro del directorio de repositorios
    repo_dirs = [d for d in base_repo_path.iterdir() if d.is_dir()]

    for repo_path in repo_dirs:
        repo_name = repo_path.name
        typer.echo(f"[+] Generando SBOM para: {repo_name}...")

        commit_hash = SbomRunner.get_commit_hash(repo_path)
        status, comp_count, sbom_file, err = SbomRunner.generate_sbom(
            repo_path, out_path
        )

        if status in ["success", "no_components"]:
            typer.echo(
                f"    [✓] Finalizado. Estado: {status} | Componentes identificados: {comp_count}"
            )
        else:
            typer.echo(
                f"    [!] Error al procesar repositorio: {err}", err=True
            )

        sbom_reports.append(
            RepositorySbomReport(
                name=repo_name,
                full_name=f"{organization}/{repo_name}",
                commit_hash=commit_hash,
                syft_version=syft_ver,
                status=status,
                components_count=comp_count,
                sbom_path=sbom_file,
                error_reason=err,
            )
        )

    # Construir métricas del resumen
    analyzed_count = sum(
        1 for r in sbom_reports if r.status in ["success", "no_components"]
    )
    failed_count = sum(1 for r in sbom_reports if r.status == "failed")
    total_components = sum(r.components_count for r in sbom_reports)

    summary = SbomSummary(
        total_repositories=len(sbom_reports),
        analyzed=analyzed_count,
        failed=failed_count,
        total_components_identified=total_components,
    )

    org_report = OrganizationSbomReport(
        organization=organization, summary=summary, repositories=sbom_reports
    )
    org_report.sort_results()

    summary_file_path = out_path / "sbom_summary_results.json"
    with open(summary_file_path, "w", encoding="utf-8") as f:
        f.write(org_report.model_dump_json(indent=2))

    typer.echo(
        f"\nProceso finalizado. El JSON consolidado fue guardado en: {summary_file_path}"
    )
    # Agregar al final de generate_sbom() en src/miner/cli.py

    typer.echo("\n" + "=" * 60)
    typer.echo(f"  RESUMEN DE GENERACIÓN DE SBOM - {organization}")
    typer.echo("=" * 60)
    for repo_rep in sbom_reports:
        symbol = "✓" if repo_rep.status in ["success", "no_components"] else "✗"
        typer.echo(
            f"  [{symbol}] {repo_rep.name:<25} | Estado: {repo_rep.status:<12} | Componentes: {repo_rep.components_count}"
        )
    typer.echo("-" * 60)
    typer.echo(
        f"  TOTALES: Repos: {summary.total_repositories} | Exitosos: {summary.analyzed} | Componentes: {summary.total_components_identified}"
    )
    typer.echo("=" * 60)
    typer.echo(f"\nReporte consolidado guardado en: {summary_file_path}\n")


if __name__ == "__main__":
    app()