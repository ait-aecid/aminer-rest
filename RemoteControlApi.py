"""
This module contains methods to access the AMinerRemoteControl by the REST-
API. The implementation follows the RFC-2616 standard.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

from fastapi import Depends, FastAPI, status, Request, Form
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Any, List, Optional
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from datetime import timedelta, timezone, datetime
from jose import JWTError, jwt
from database import UserDB, get_db, init_db
from cerberus import Validator
import shlex
import json
import sys
import socket
import logging
import traceback
import os
import re
import configparser
import secrets
import pyotp
import time

app = FastAPI()

# TODO: should be removed in production
client = TestClient(app)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
config = configparser.ConfigParser()
config.read("config.ini")
ALGORITHM = config.get("auth", "ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = config.getint("auth", "ACCESS_TOKEN_EXPIRE_MINUTES")
REFRESH_TOKEN_EXPIRE_DAYS = config.getint("auth", "REFRESH_TOKEN_EXPIRE_DAYS")
SECRET_KEY = config.get("auth", "SECRET_KEY")
AMINER_OUTPUT_LOG = config.get("auth", "AMINER_OUTPUT_LOG")
AMINER_INPUT_LOG = config.get("auth", "AMINER_INPUT_LOG")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ERR_RESOURCE_NOT_FOUND = b'"Resource \\"%s\\" could not be found."'
ERR_WRONG_TYPE = b"FAILURE: the parameters \"component_name\" and \"attribute\" must be of type str."
ERR_CONFIG_PROPERTY_NOT_EXISTING = "Creating a new config property is currently not allowed."
ERR_HEADER_NOT_IMPLEMENTED = "The Header '%s' is not implemented and must not be used."
CONFIG_PROPERTY_PATH = "/config_property/{config_property}"
ATTRIBUTE_PATH = "/attribute/{component_name}/{attribute_path}"
SAVE_CONFIG_PATH = "/save_config"
DESTINATION_FILE = "/tmp/live-config"  # nosec B108
ANALYSIS_COMPONENT_PATH = "/component/"
ADD_COMPONENT_PATH = ANALYSIS_COMPONENT_PATH + "{atom_handler}"
REMOTE_CONTROL_SOCKET = "/var/run/aminer-remote.socket"
sys.path = sys.path[1:] + ["/usr/lib/logdata-anomaly-miner"]
from aminer.AnalysisChild import AnalysisChildRemoteControlHandler, LIVE_CONFIG_TEMPFILE  # noqa: E402

if os.path.isfile(LIVE_CONFIG_TEMPFILE):
    os.remove(LIVE_CONFIG_TEMPFILE)


class Property(BaseModel):
    value: Any


class AnalysisComponent(BaseModel):
    class_name: str
    parameters: List[str]
    component_name: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    is_admin: Optional[bool] = False


class UserInDB(User):
    hashed_password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db: Session, username: str) -> Optional[UserDB]:
    return db.query(UserDB).filter(UserDB.username == username).first()


def authenticate_user(db: Session, username: str, password: str) -> Optional[UserDB]:
    user = get_user(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if user.disabled:
        return None
    return user


def verify_totp(user: UserDB, totp_code: str):
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(totp_code)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user_db = get_user(db, username)
    if user_db is None:
        raise credentials_exception
    if user_db.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return user_db


def guess_config_type(content: str) -> str:
    """
    Fast heuristic to detect if content is Python or YAML.

    Returns: ".py", ".yml", or "".
    """
    # Read only first ~20 lines for speed
    lines = content.splitlines()[:20]
    head = "\n".join(lines)

    # Python syntax hints
    python_patterns = [
        r'^\s*def\s+\w+\(',
        r'^\s*class\s+\w+',
        r'^\s*import\s+\w+',
        r'^\s*from\s+[\w\.]+\s+import',
        r'^\s*if\s+__name__\s*==\s*[\'"]__main__[\'"]'
    ]

    # YAML syntax hints
    yaml_patterns = [
        r'^\w[\w\-]*:\s',
        r'^-\s+\w',
        r'^\s*\w[\w\-]*:\n',
    ]

    if any(re.search(p, head, re.MULTILINE) for p in python_patterns):
        return ".py"
    elif any(re.search(p, head, re.MULTILINE) for p in yaml_patterns):
        return ".yml"
    else:
        return ""


def jsonschema_to_cerberus(json_schema: dict) -> dict:
    """
    Convert a simplified JSON Schema to a Cerberus-compatible schema.
    Supports 'type', 'properties', 'required', and 'enum'.
    """
    cerberus_schema = {}
    type_map = {"string": "string", "integer": "integer", "number": "float", "boolean": "boolean", "object": "dict", "array": "list"}
    if "properties" not in json_schema:
        raise ValueError("Expected 'properties' in JSON Schema")
    required_fields = set(json_schema.get("required", []))
    for field, props in json_schema["properties"].items():
        field_rules = {}
        if "type" in props:
            field_rules["type"] = type_map.get(props["type"], "string")
        if "enum" in props:
            field_rules["allowed"] = props["enum"]
        if field in required_fields:
            field_rules["required"] = True
        if "minLength" in props:
            field_rules["minlength"] = props["minLength"]
        if "maxLength" in props:
            field_rules["maxlength"] = props["maxLength"]
        if "minimum" in props:
            field_rules["min"] = props["minimum"]
        if "maximum" in props:
            field_rules["max"] = props["maximum"]
        cerberus_schema[field] = field_rules
    return cerberus_schema


@app.on_event("startup")
def on_startup():
    init_db()


input_schema = jsonschema_to_cerberus({
   "$id": "raw_log",
   "title": "Raw Log",
   "description": "",
   "$schema": "https://json-schema.org/draft/2020-12/schema",
   "type": "object",
   "properties": {
      "log_id": {"type": "string"},
      "timestamp": {"type": "string"},
      "source": {"type": "string"},
      "severity": {"type": "string"},
      "message": {"type": "string"},
      "hostname": {"type": "string"},
      "additional_data": {"type": "string"}
   },
   "required": [
      "log_id",
      "timestamp",
      "source",
      "severity",
      "message"
   ]
})

dtf = "%Y-%m-%d %H:%M:%S"


@app.post("/aminer-input")
async def write_aminer_input(data: dict):
    v = Validator(input_schema)
    if not v.validate(data):
        raise HTTPException(status_code=400, detail=v.errors)
    try:
        response = {"title": "AMiner Report", "publisher": "aminer", "format": "json", "identifier": data["log_id"], "language": "en"}
        init_size = os.path.getsize(AMINER_OUTPUT_LOG)
        command = 'get_processed_log_count(analysis_context)'.encode()
        cntr = int(execute_remote_control_socket(command, True).decode().replace("Remote execution response: '", "")
                   .replace("'", ""))
        os.makedirs(os.path.dirname(AMINER_INPUT_LOG), exist_ok=True)
        with open(AMINER_INPUT_LOG, "a") as f:
            log_line = f"{datetime.fromtimestamp(float(data["timestamp"]), tz=timezone.utc).strftime(dtf)} {data["source"]}" \
                       f"[{data["log_id"]}] {data["severity"]}: {data["message"]}"
            f.write(log_line + "\n")
        total_time = 0.
        while int(execute_remote_control_socket(command, True).decode().replace("Remote execution response: '", "")
                  .replace("'", "")) == cntr and total_time < 30:
            total_time += 0.1
            time.sleep(0.1)
        if int(execute_remote_control_socket(command, True).decode().replace("Remote execution response: '", "")
                .replace("'", "")) != cntr and os.path.getsize(AMINER_OUTPUT_LOG) != init_size:
            with open(AMINER_OUTPUT_LOG, "r") as f:
                f.seek(init_size)
                new_data = f.read()
            anomaly = json.loads(new_data)
            response["creator"] = anomaly["AnalysisComponent"]["AnalysisComponentName"]
            if response["creator"] is None:
                response["creator"] = anomaly["AnalysisComponent"]["AnalysisComponentType"]
            response["subject"] = anomaly["AnalysisComponent"]["AnalysisComponentType"]
            response["description"] = anomaly["AnalysisComponent"]["Message"]
            response["date"] = datetime.fromtimestamp(anomaly["LogData"]["DetectionTimestamp"], tz=timezone.utc).strftime(dtf)
            response["type"] = "anomaly"
            return response
        else:
            response["creator"] = "aminer"
            response["subject"] = "No anomaly"
            response["description"] = f"No anomaly for the log with the id {data["log_id"]} reported."
            response["date"] = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp(), tz=timezone.utc).strftime(dtf)
            response["type"] = "info"
            return response
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/create-admin")
def create_admin(db: Session = Depends(get_db)):
    # Only allow creation if no admin exists
    if db.query(UserDB).filter(UserDB.is_admin).first():
        raise HTTPException(status_code=403, detail="Admin user already exists.")

    # Generate strong random password
    password = secrets.token_urlsafe(24)  # ~32 characters
    hashed_password = pwd_context.hash(password)

    # Generate TOTP secret
    totp_secret = pyotp.random_base32()

    admin_user = UserDB(
        username="admin",
        hashed_password=hashed_password,
        full_name="Administrator",
        email=None,
        disabled=False,
        is_admin=True,
        totp_secret=totp_secret,
        must_reset_password=True  # force first-login reset
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)

    # Provide instructions for 2FA
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name="admin", issuer_name="aminer-rest")

    return {
        "message": "Admin user created successfully. Store the password securely - it is only returned once!",
        "username": admin_user.username,
        "password": password,  # returned only once
        "totp_uri": totp_uri,  # can be scanned by Google Authenticator / Authy
        # "totp_secret": totp_secret  # optional if user wants manual entry -> probably not secure
    }


@app.post("/create-user")
def create_user(username: str = Form(...), password: str = Form(...), email: Optional[str] = Form(None),
                full_name: Optional[str] = Form(None), current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    # Only allow admins to create new users
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Only admin users can create new users")
    # Prevent creating duplicate usernames
    if db.query(UserDB).filter(UserDB.username == username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = pwd_context.hash(password)
    new_user = UserDB(
        username=username,
        hashed_password=hashed_password,
        full_name=full_name,
        email=email,
        disabled=False,
        is_admin=False,  # <-- always regular user
        totp_secret=None,  # no TOTP for regular users
        must_reset_password=True  # force password reset on first login
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": f"User {username} created successfully", "username": username, "must_reset_password": True}


@app.post("/reset-password")
def reset_password(new_password: str = Form(...), current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    # Update password
    current_user.hashed_password = pwd_context.hash(new_password)
    current_user.must_reset_password = False
    db.add(current_user)
    db.commit()
    return {"message": "Password has been reset successfully."}


@app.post("/token", response_model=Token)
async def login_for_access_token(
        username: str = Form(...), password: str = Form(...), totp_code: Optional[str] = Form(None), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    if user.disabled:
        raise HTTPException(status_code=400, detail="User is disabled")
    # If admin, verify TOTP
    if user.is_admin:
        if not totp_code:
            raise HTTPException(status_code=400, detail="TOTP code required for admin login")
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            raise HTTPException(status_code=400, detail="Invalid TOTP code")
    if user.must_reset_password:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Password reset required. Please reset your password before logging in.")
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_refresh_token(data={"sub": user.username}, expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer"}


@app.post("/refresh", response_model=Token)
def refresh_access_token(refresh_token: str, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not refresh token", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        if username is None or token_type != "refresh":  # nosec B105
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user is None or user.disabled:
        raise credentials_exception
    # issue new access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    # optionally issue a new refresh token too
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    new_refresh_token = create_refresh_token(data={"sub": user.username}, expires_delta=refresh_token_expires)
    return {"access_token": access_token, "refresh_token": new_refresh_token, "token_type": "Bearer"}

# Client flow
#
# Login
#
# curl -X POST "http://127.0.0.1:8000/token" \
#   -d "username=johndoe&password=password" \
#   -H "Content-Type: application/x-www-form-urlencoded"
#
#
# → Get access_token + refresh_token.
#
# Use access token
# Send Authorization: Bearer ... with requests until it expires.
#
# When expired, refresh
#
# curl -X POST "http://127.0.0.1:8000/refresh" \
#   -d "refresh_token=eyJhbGciOiJI..." \
#   -H "Content-Type: application/x-www-form-urlencoded"
#
#
# → Get new access_token (and possibly a new refresh_token).


@app.get("/")
def get_current_config(_: UserDB = Depends(get_current_user)):
    res = execute_remote_control_socket(b"print_current_config()", True)
    return res


@app.get(CONFIG_PROPERTY_PATH)
def get_config_property(config_property: str, _: UserDB = Depends(get_current_user)):
    command = b'print_config_property(analysis_context,"%s")' % shlex.quote(config_property).encode()
    res = execute_remote_control_socket(command, True)
    val = res.split(b"'")[1]
    if val == ERR_RESOURCE_NOT_FOUND % config_property.encode("utf-8"):
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"ErrorMessage": val.decode().replace('\\', '').strip('"')})
    val = val.split(b":", 1)[1].strip(b" ").strip(b"\n")
    if val.startswith(b"[") and val.endswith(b"]"):
        val = json.loads(val)
    else:
        if val.isdigit():
            val = int(val)
        elif b"." in val:
            try:
                val = float(val)
            except ValueError:
                pass
    return {config_property: val}


@app.put(CONFIG_PROPERTY_PATH)
def put_config_property(config_property: str, item: Property, request: Request, token: str = Depends(oauth2_scheme),
                        _: UserDB = Depends(get_current_user)):
    # first check if the property exists - return the status code.
    check_content_headers(request)

    response = client.get("%s%s" % (CONFIG_PROPERTY_PATH.split("{")[0], config_property), headers={"Authorization": "%s %s" % (
        "Bearer", token)})
    if response.status_code == 200:
        if isinstance(item.value, bytes):
            item.value = item.value.decode()
        if isinstance(item.value, str):
            item.value = '"%s"' % shlex.quote(item.value)
        command = f'change_config_property(analysis_context,"{shlex.quote(config_property)}",{item.value})'.encode()
        res = execute_remote_control_socket(command, True)
        val = res.split(b":", 1)[1].strip(b" ").strip(b'\n').strip(b"'")
        if val.startswith(b"FAILURE:"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b"FAILURE: ")[1].decode().rstrip("'"))
        return JSONResponse(status_code=status.HTTP_200_OK, content={
            "message": f"Successfully changed config property {config_property} to {item.value}."})
    if response.status_code == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=ERR_CONFIG_PROPERTY_NOT_EXISTING)
    return HTTPException(status_code=response.status_code, detail="An error occurred. Response message:\n%s" % response.content)


@app.get(ATTRIBUTE_PATH)
def get_attribute_of_registered_component(component_name: str, attribute_path: str, _: UserDB = Depends(get_current_user)):
    command = f'print_attribute_of_registered_analysis_component(analysis_context,"{shlex.quote(component_name)}",' \
              f'"{shlex.quote(attribute_path)}")'.encode()
    res = execute_remote_control_socket(command, True)
    val = res.split(b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'")
    if isinstance(val, bytes) and val.startswith(b"FAILURE:"):
        if val == ERR_WRONG_TYPE:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b"FAILURE: ")[1].decode())
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=val.split(b"FAILURE: ")[1].decode())
    return json.loads(b"{%s}" % val)


@app.put(ATTRIBUTE_PATH)
def put_attribute_of_registered_component(component_name: str, attribute_path: str, item: Property, request: Request,
                                          token: str = Depends(oauth2_scheme), _: UserDB = Depends(get_current_user)):
    check_content_headers(request)
    response = client.get("%s%s/%s" % (ATTRIBUTE_PATH.split("{")[0], component_name, attribute_path), headers={"Authorization": "%s %s" % (
        "Bearer", token)})
    if response.status_code == 200:
        if isinstance(item.value, bytes):
            item.value = item.value.decode()
        if isinstance(item.value, str):
            item.value = '"%s"' % shlex.quote(item.value)
        command = f"change_attribute_of_registered_analysis_component(analysis_context,\"{shlex.quote(component_name)}\"," \
                  f"\"{shlex.quote(attribute_path)}\",{item.value})".encode()
        res = execute_remote_control_socket(command, True)
        val = res.split(b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'")
        if val.startswith(b"FAILURE:"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b"FAILURE: ")[1].decode())
        return JSONResponse(status_code=status.HTTP_200_OK, content={
            "message": f"Successfully changed attribute {attribute_path} of registered analysis component {component_name} to "
                       f"{item.value}"})
    if response.status_code == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=response.content.split(b'"')[3].decode())
    return HTTPException(status_code=response.status_code, detail="An error occurred. Response message:\n%s" % response.content)


@app.get(SAVE_CONFIG_PATH)
def save_config(_: UserDB = Depends(get_current_user)):
    dest_file = DESTINATION_FILE + guess_config_type(
        execute_remote_control_socket(b"print_current_config()", True).split(
            b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'").decode("unicode-escape"))
    command = f'save_current_config("{shlex.quote(dest_file)}")'.encode()
    res = execute_remote_control_socket(command, True)
    val = res.split(b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'")
    if val.startswith(b"FAILURE:"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b"FAILURE: ")[1].decode())
    with open(dest_file, "r", encoding="utf-8") as f:
        content = f.read()
    return JSONResponse(
        status_code=status.HTTP_200_OK, headers={"location": dest_file}, content={"filename": dest_file, "content": content})


@app.put(ANALYSIS_COMPONENT_PATH)
def rename_registered_analysis_component(
        old_component_name: str, new_component_name: str, request: Request, _: UserDB = Depends(get_current_user)):
    check_content_headers(request)
    command = f'rename_registered_analysis_component(analysis_context,"{shlex.quote(old_component_name)}",' \
              f'"{shlex.quote(new_component_name)}")'.encode()
    res = execute_remote_control_socket(command, True)
    val = res.split(b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'")
    if val.startswith(b"FAILURE:"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=val.split(b"FAILURE: ")[1].decode())
    return JSONResponse(status_code=status.HTTP_200_OK, content={
        "message": f"Successfully renamed analysis component from {old_component_name} to {new_component_name}"})


@app.post(ADD_COMPONENT_PATH)
def add_handler_to_atom_filter_and_register_analysis_component(
        atom_handler: str, analysis_component: AnalysisComponent, _: UserDB = Depends(get_current_user)):
    parameter = ""
    for p in analysis_component.parameters:
        if parameter != "":
            parameter += ","
        if p.startswith('"') and p.endswith('"'):
            parameter += shlex.quote(p)
        elif p.startswith('[') and p.endswith(']'):
            parameter += '[%s]' % shlex.quote(p[1:-1])
        else:
            parameter += shlex.quote(p)
    command = f"add_handler_to_atom_filter_and_register_analysis_component(analysis_context,\"{shlex.quote(atom_handler)}\"," \
              f"{shlex.quote(analysis_component.class_name)}({parameter}),\"{shlex.quote(analysis_component.component_name)}\")".encode()
    res = execute_remote_control_socket(command, True)
    val = res.split(b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'")
    if val.startswith(b"FAILURE:"):
        val = val.split(b"FAILURE: ")[1]
        if val == b"atom_handler '%s' does not exist!" % atom_handler.encode("utf-8"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=val.decode())
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.decode())
    return JSONResponse(status_code=status.HTTP_200_OK, content={
        "message": f"Successfully added new {analysis_component.class_name} with the name {analysis_component.component_name} to the "
                   f"atom filter {atom_handler}"})


def check_content_headers(request):
    for header in request.headers:
        if header.startswith("content-") and header not in ("content-type", "content-length"):
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=ERR_HEADER_NOT_IMPLEMENTED % header)


def execute_remote_control_socket(remote_control_code, string_response_flag, remote_control_data=None):
    result = b""
    remote_control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        remote_control_socket.connect(REMOTE_CONTROL_SOCKET)
    except socket.error as connectException:
        msg = "Failed to connect to socket %s, AMiner might not be running or remote control is disabled in configuration: %s" % (
            REMOTE_CONTROL_SOCKET, str(connectException))
        logging.log(logging.ERROR, msg)
        print(msg)
        sys.exit(1)
    control_handler = AnalysisChildRemoteControlHandler(remote_control_socket, None)
    control_handler.put_execute_request(remote_control_code, remote_control_data)
    # Send data until we are ready for receiving.
    while not control_handler.may_receive():
        control_handler.do_send()
    while not control_handler.may_get():
        control_handler.do_receive()
    request_data = control_handler.do_get()
    request_type = request_data[4:8]
    if request_type == b"RRRR":
        try:
            remote_data = json.loads(request_data[8:])
            if remote_data[0] is not None:
                result += ("Remote execution exception:\n%s" % remote_data[0]).encode()
                logging.log(logging.ERROR, "Remote execution exception:\n%s", remote_data[0])
            if string_response_flag:
                result += ("Remote execution response: '%s'" % str(remote_data[1])).encode()
            else:
                result += ("Remote execution response: '%s'" % repr(remote_data[1])).encode()
        except Exception:
            print("Failed to process response %s" % repr(request_data))
            logging.log(logging.ERROR, "Failed to process response %s", repr(request_data))
            traceback.print_exc()
    else:
        raise Exception("Invalid request type %s" % repr(request_type))
    remote_control_socket.close()
    return result
