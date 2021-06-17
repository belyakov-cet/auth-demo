from collections import defaultdict
from typing import Optional
import hmac
import hashlib
import base64

from fastapi import FastAPI, Form, Cookie
from fastapi.datastructures import Default
from fastapi.responses import Response


SECRET_KEY = "7e400e33e9526d40d9942385b170fc9401ef939cbe8ac8082e01282049958282"
PASSWORD_SALT = "33566441ee1d1399fef29977688546b23dbeb1ade69ebec4f369168753fdde98"

app = FastAPI()


def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(signed_data: str) -> Optional[str]:
    """Возвращает декодированный username из подписанных данных"""
    username_base64, sign = signed_data.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username



users = {
    "bel@mail.ru": {
        "name": "Алексей",
        "password": "5c1e787c4f51f999e134f3338f5875ec28ec307f35e00c8a12a40d35c9704bf5",
        "cash": 100
    },
    "korn@mail.ru": {
        "name": "Евгений",
        "password": "cff8214ed3b4d35431e36c63faee30d48e790a36a7fe0557f649a983a8861fe6",
        "cash": 300
    }    
}


def verify_user(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password = users[username]["password"].lower()
    return password_hash == stored_password


@app.get("/")
def index_page(username : Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()

    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username")
        return response
    
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username")
        return response
    return Response(f'Hi, {users[valid_username]["name"]}', media_type='text/html')        



@app.post('/login')
def process_login_page(username : str = Form(...), password : str = Form(...)):
    user = users.get(username)
    if not user or not verify_user(username, password):
        return Response("Пользователь не найден", media_type="text/html")
    
    response =  Response(f'Привет, {user["name"]}. У тебя: {user["cash"]}', media_type="text/html")
    username_signed = f"{base64.b64encode(username.encode()).decode()}.{sign_data(username)}"
    response.set_cookie(key="username", value=username_signed)
    return response
    