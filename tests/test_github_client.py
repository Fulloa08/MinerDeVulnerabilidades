import pytest
from unittest.mock import patch, MagicMock
from miner.github_client import GitHubClient

@patch.dict("os.environ", {"GITHUB_TOKEN": "token_falso"})
@patch("requests.get")
def test_get_organization_repos_pagination(mock_get):
    # Simular dos páginas de respuesta de la API
    page1_response = MagicMock()
    page1_response.status_code = 200
    page1_response.json.return_value = [{"name": "repo1", "html_url": "http://repo1"}]

    page2_response = MagicMock()
    page2_response.status_code = 200
    page2_response.json.return_value = []  # Lista vacía indica fin de paginación

    mock_get.side_effect = [page1_response, page2_response]

    client = GitHubClient()
    repos = client.get_organization_repos("dummy-org")

    assert len(repos) == 1
    assert repos[0]["name"] == "repo1"
    assert mock_get.call_count == 2