
# Miner de vulnerabilidades en repositorios de GitHub

Herramienta CLI en Python para automatizar el análisis estático de seguridad (SAST) mediante **CodeQL** en repositorios pertenecientes a organizaciones de GitHub. Extrae proyectos vía GitHub REST API, los clona localmente, ejecuta el motor de CodeQL y consolida los resultados en un reporte JSON estructurado.

---

## Requisitos Previos

* **Python 3.10+**
* **Git** (configurado en el PATH)
* **CodeQL CLI** (instalado y agregado al PATH del sistema)

---

## Instalación

1. Clonar el repositorio y entrar al directorio:
git clone <URL_DE_TU_REPOSITORIO>
cd "Miner de vulnerabilidades para organizaciones de GitHub"
2. Crear y activar el entorno virtual:
python -m venv .venv
..venv\Scripts\activate
3. Instalar dependencias e instalar el paquete local en modo editable:
pip install -r requirements.txt
pip install -e .

---

## Variables de Entorno

Requiere un Personal Access Token (PAT) de GitHub para autenticar peticiones a la API REST.

Asignar la variable en PowerShell:
$env:GITHUB_TOKEN="ghp_tuTokenDeGitHubAqui"

---

## Uso de la CLI

Puedes utilizar el comando registrado `miner` o invocar el módulo desde Python:

### Usando el ejecutable registrado

miner scan --organization expressjs --output results.json

### Usando sintaxis de módulo de Python

python -m miner.cli scan --organization expressjs --output results.json

---

## Estructura del Proyecto
```
├── src/
│   └── miner/
│       ├── **init**.py
│       ├── cli.py                 # Interfaz de línea de comandos (Typer)
│       ├── github_client.py       # Cliente REST API de GitHub con paginación
│       ├── repository_manager.py  # Clonación y limpieza con GitPython
│       ├── codeql_runner.py       # Ejecución de CodeQL CLI
│       ├── sarif_parser.py        # Parser SARIF a Pydantic
│       └── models.py              # Modelos de datos y ordenamiento
├── tests/                         # Pruebas unitarias con Pytest
├── pyproject.toml                 # Configuración del paquete
├── requirements.txt               # Dependencias del proyecto
├── .env.example                   # Ejemplo de configuración de entorno
└── README.md                      # Documentación
```
---

## Formato de Salida (`results.json`)
```
{
"organization": "expressjs",
"summary": {
"repositories": 50,
"analyzed": 35,
"failed": 0,
"unsupported": 15,
"findings": 4
},
"repositories": [
{
"name": "express",
"url": "[https://github.com/expressjs/express](https://github.com/expressjs/express)",
"status": "analyzed",
"languages": ["javascript"],
"findings": [
{
"rule_id": "js/unvalidated-dynamic-method-call",
"severity": "warning",
"message": "Unvalidated dynamic method call.",
"file": "lib/response.js",
"start_line": 102
}
]
}
]
}
```
---

## Pruebas Unitarias

Ejecutar pruebas automatizadas con:

pytest
```

