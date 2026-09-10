# Miner de vulnerabilidades para organizaciones de GitHub
#1. identificar el repositorio y obtener informacion para clonar 
# - cliente_typer.py recibe la url del repositorio
#2. clonar el respositorio localmente
# - github_cliente.py obtiene la información del repo y lo clona
#determinar si contiene código que pueda ser analizado mediante CodeQL;
#3. crear la base de datos CodeQL correspondiente;
# - codeql_runner.py crea la base de datos
#4. ejecutar las consultas de seguridad de CodeQL;
# - codeql_runner.py ejecuta las consultas de CodeQL
#5. recuperar los resultados producidos por CodeQL;
# - sarif_parser.py procesa los resultados en formato SARIF
#6. transformar esos resultados a la estructura de datos definida por el miner
# - models.py ordena los resultados para exportar a JSON