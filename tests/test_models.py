from miner.models import OrganizationReport, Summary, RepositoryReport, Finding

def test_organization_report_sorting():
    # 1. Crear hallazgos desordenados por archivo y línea
    f1 = Finding(rule_id="rule2", severity="warning", message="msg2", file="b_file.py", start_line=10)
    f2 = Finding(rule_id="rule1", severity="error", message="msg1", file="a_file.py", start_line=50)
    f3 = Finding(rule_id="rule3", severity="error", message="msg3", file="a_file.py", start_line=20)

    # 2. Crear repositorios desordenados alfabéticamente
    repo_b = RepositoryReport(name="repo-b", url="http://b.com", status="analyzed", findings=[f1])
    repo_a = RepositoryReport(name="repo-a", url="http://a.com", status="analyzed", findings=[f2, f3])

    report = OrganizationReport(
        organization="test-org",
        summary=Summary(repositories=2, analyzed=2),
        repositories=[repo_b, repo_a]
    )

    # 3. Aplicar ordenamiento
    report.sort_results()

    # 4. Aserciones
    assert report.repositories[0].name == "repo-a"
    assert report.repositories[1].name == "repo-b"
    
    # Verificar orden interno de hallazgos (a_file.py línea 20 va antes que línea 50)
    sorted_findings = report.repositories[0].findings
    assert sorted_findings[0].start_line == 20
    assert sorted_findings[1].start_line == 50