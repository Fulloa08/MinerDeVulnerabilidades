import json
from miner.sarif_parser import SarifParser

def test_sarif_parser_parsing(tmp_path):
    # 1. Crear un archivo SARIF de prueba en un directorio temporal
    mock_sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "Possible SQL Injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/db.py"},
                                    "region": {"startLine": 42}
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    
    sarif_file = tmp_path / "sample.sarif"
    sarif_file.write_text(json.dumps(mock_sarif), encoding="utf-8")

    # 2. Parsear el archivo con la clase SarifParser
    findings = SarifParser.parse(str(sarif_file))

    # 3. Aserciones
    assert len(findings) == 1
    assert findings[0].rule_id == "py/sql-injection"
    assert findings[0].severity == "error"
    assert findings[0].file == "src/db.py"
    assert findings[0].start_line == 42