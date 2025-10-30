import pytest
import random
import requests
import quopri
import re
from requests.utils import unquote

# crear token
MAILHOG_API = "http://localhost:8025/api/v2/messages"

def get_last_email_body():
    resp = requests.get(MAILHOG_API)
    resp.raise_for_status()
    data = resp.json()

    if not data["items"]:
        return None  # no emails received yet

    last_email = data["items"][0]
    body = last_email["Content"]["Body"]
    decoded = quopri.decodestring(body).decode("utf-8", errors="replace")
    return unquote(decoded)

def extract_links(decoded_html):
    return re.findall(r'<a\s+href=["\']([^"\']+)["\']', decoded_html, re.IGNORECASE)[0]

def extract_query_params(url):
    # regex: busca ?token= o &token= seguido de cualquier cosa hasta &, # o fin de string
    patron = re.compile(r"(?:[?&])token=([^&#]+)")
    m = patron.search(url)
    return m.group(1) if m else None

@pytest.fixture(scope="module")
def create_and_login_user():
    # random username
    i = random.randint(1000, 999999)
    username = f'user{i}'
    email = f'{username}@test.com'
    password = 'password'

    salida = requests.post("http://localhost:5000/users",
                        data={
                            "username": username,
                            "password": password,
                            "email": email,
                            "first_name": "Name",
                            "last_name": f'{username}son'
                        })
    # user created
    assert salida.status_code == 201

    mail = get_last_email_body()
    link = extract_links(mail)
    token = extract_query_params(link)

    # activate user
    resp = requests.post("http://localhost:5000/auth/set-password", json={"token": token, "newPassword": password})

    # login y obtencion de token auth
    resp2 = requests.post("http://localhost:5000/auth/login", json={"username": username, "password": password})

    auth_token = resp2.json().get("token")

    return {"username": username, "password": password, "token": auth_token}

def get_invoices_count(auth_token, status_param=None, operator=None):
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
    params = {}
    if status_param is not None:
        params["status"] = status_param
    if operator is not None:
        params["operator"] = operator
    resp = requests.get("http://localhost:5000/invoices", headers=headers, params=params)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        raise AssertionError("Respuesta /invoices no es una lista JSON")
    return len(data), data

# payloads
PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "\" OR \"\" = \"",
    "' OR 'a'='a",
    "' OR '1'='1' -- ",
    "' OR '1'='1' /*",
    "' OR ''='"
]

@pytest.mark.parametrize("payload", PAYLOADS)
def test_sql_injection_attempt_parametrized(create_and_login_user, payload):
    """
    Test parametrizado que compara el numero de filas devueltas por:
    1) un estado improbable (baseline)
    2) el mismo parametro status usando distintos payloads de SQLi

    Si count_payload > count_baseline -> posible SQLi.
    """
    token = create_and_login_user["token"]

    # respuesta con un parametro que no existe
    rare_status = "status_does_not_exist_12345"
    # obtiene el numero de "elemetnos" que contiene la respuesta (0)
    count_baseline, baseline_data = get_invoices_count(token, status_param=rare_status)

    # respuesta con payload
    payload_encoded = payload
    # obtiene el numero de elementos que contiene la respuesta con el payload 
    count_payload, payload_data = get_invoices_count(token, status_param=payload_encoded)

    # si la app es vulnerable entonces count_payload > count_baseline
    assert count_payload == count_baseline, (
        "Posible SQL Injection detectado con payload: {!r}. "
        "La consulta con payload devolvió un número distinto de filas que la baseline. "
        f"baseline={count_baseline}, payload={count_payload}"
    )
