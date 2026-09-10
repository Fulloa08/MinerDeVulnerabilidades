import json
from typing import List
from miner.models import Finding

class SarifParser:
    @staticmethod
    def parse(sarif_path: str) -> List[Finding]:
        findings = []
        try:
            with open(sarif_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for run in data.get("runs", []):
                for result in run.get("results", []):
                    rule_id = result.get("ruleId", "unknown")
                    message = result.get("message", {}).get("text", "Sin descripción")
                    severity = result.get("level", "warning")

                    # Extraer ubicación
                    file_path = "desconocido"
                    start_line = 0
                    locations = result.get("locations", [])
                    if locations:
                        phys_loc = locations[0].get("physicalLocation", {})
                        file_path = phys_loc.get("artifactLocation", {}).get("uri", "desconocido")
                        start_line = phys_loc.get("region", {}).get("startLine", 0)

                    findings.append(Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        file=file_path,
                        start_line=start_line
                    ))
        except Exception as e:
            print(f"Error parseando SARIF: {e}")
        
        return findings