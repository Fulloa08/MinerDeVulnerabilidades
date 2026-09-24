
# Miner de vulnerabilidades en repositorios de GitHub

Herramienta CLI en Python para automatizar el análisis estático de seguridad (**CodeQL**) y la generación de inventarios de software (**SBOM** con **Syft**) en repositorios de organizaciones de GitHub.

---

## Requisitos Previos

* **Python 3.10+**
* **Git**
* **CodeQL CLI** (para escaneo SAST)
* **Syft CLI** (para generación de SBOM)

---

## Instalación

```powershell
# 1. Proyecto local
git clone git@github.com:Fulloa08/MinerDeVulnerabilidades.git
cd "Miner de vulnerabilidades para organizaciones de GitHub"
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .

# 2. Instalar Syft (Windows)
winget install Anchore.syft

```

---

## Variables de Entorno

```powershell
$env:GITHUB_TOKEN="tuTokenDeGitHubAqui"

```

---

## Uso de la CLI

### 1. Escaneo de Vulnerabilidades (CodeQL)

```powershell
miner scan --organization expressjs --output results.json

```

### 2. Generación Automatizada de SBOM (Syft)

Genera el inventario en formato **CycloneDX JSON (v1.7)** de forma independiente a CodeQL.

```powershell
miner generate-sbom --repos-dir ./temp/cloned_repos --organization bottlepy --output-dir ./mis_sboms

```

---

## Estructura del Proyecto

```text
├── src/miner/
│   ├── cli.py                # Interfaz CLI (Typer)
│   ├── github_client.py      # Cliente REST API de GitHub
│   ├── repository_manager.py # Gestión de repositorios con GitPython
│   ├── codeql_runner.py      # Ejecución de CodeQL
│   ├── sbom_service.py        # Ejecución de Syft y metadata Git
│   ├── sarif_parser.py       # Parser SARIF a Pydantic
│   └── models.py             # Modelos de datos
├── tests/                    # Pruebas unitarias
├── pyproject.toml / requirements.txt
└── README.md

```

---

## Archivos de Salida (SBOM)

1. **Consolidado General (`sbom_summary_results.json`):** Resumen global con commit, fecha UTC, versión de Syft, estado, total de componentes y ruta individual por repositorio.
2. **SBOMs Independientes (`[nombre_repo]_sbom.json`):** Inventario CycloneDX con dependencias, versiones, PURL, CPEs y licencias.

---

## Ejemplo y Contraste de Componentes

1. **Ejecutar generación:**
```powershell
miner generate-sbom --repos-dir ./temp/cloned_repos --organization bottlepy --output-dir ./mis_sboms

```


2. **Verificación de componentes:**
* **SBOM (`WebGoat_sbom.json`):** Reporta `com.google.guava:guava` v33.7.1-jre.


* **Manifest (`pom.xml`):** Se contrasta contra la declaración `<dependency>` en el archivo real del proyecto.


* **Workflows (`.github/workflows/build.yml`):** Detecta acciones de CI/CD como `actions/checkout@v7`.





---

## Pruebas Unitarias

```bash
pytest

```

```

```
```

```

```
