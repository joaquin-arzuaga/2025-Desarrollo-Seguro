# tests/test_invoices_sql_injection.py
import urllib.parse
import pytest
import requests


from test_security import setup_create_user

API_BASE = "http://localhost:5000"


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1 OR 1=1",
]

@pytest.fixture
def auth_token(setup_create_user):
    """
    Reutiliza la fixture setup_create_user (de test_security).
    Luego hace login y devuelve el token para autorizar las requests en los tests.
    """
    username, password = setup_create_user[0], setup_create_user[1]
    r = requests.post(f"{API_BASE}/auth/login", json={"username": username, "password": password})
    r.raise_for_status()
    return r.json()["token"]

def _headers(token):
    """Helper para construir el header Authorization igual que en el estilo del repo."""
    return {"Authorization": f"Bearer {token}"}

@pytest.mark.parametrize("raw", SQLI_PAYLOADS)
def test_invoices_id_path_sqli(auth_token, raw):
    """
    Intenta GET /invoices/{id} con payloads de inyección SQL.
    El test pasa si la API NO devuelve 200 ni 500 para una carga maliciosa.
    """
    encoded = urllib.parse.quote(raw, safe="")
    url = f"{API_BASE}/invoices/{encoded}"
    resp = requests.get(url, headers=_headers(auth_token))

    assert resp.status_code not in (200, 500), (
        f"Respuesta insegura: {resp.status_code} para payload {raw!r} en path"
    )

@pytest.mark.parametrize("param_name", ["id", "invoiceId", "q", "search", "filter"])
@pytest.mark.parametrize("raw", SQLI_PAYLOADS)
def test_invoices_query_sqli(auth_token, param_name, raw):
    """
    Intenta GET /invoices?{param} con un payload para detectar concatenaciones inseguras
    en la construcción de consultas (ej: andWhereRaw con strings concatenados).
    """
    params = {param_name: raw}
    resp = requests.get(f"{API_BASE}/invoices", params=params, headers=_headers(auth_token))

    assert resp.status_code not in (200, 500), (
        f"Endpoint /invoices aceptó payload sospechoso con {param_name}={raw!r} (status {resp.status_code})"
    )
