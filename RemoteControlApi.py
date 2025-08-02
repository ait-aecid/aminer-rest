"""This module contains methods to access the AMinerRemoteControl by the REST-API.
The implementation follows the RFC-2616 standard.

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

from fastapi import Depends, FastAPI, status, Request
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Any, List, Optional
from passlib.context import CryptContext
from datetime import timedelta
from jose import JWTError, jwt
import datetime
import shlex
import json
import sys
import socket
import logging
import traceback
import os

app = FastAPI()
client = TestClient(app)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# generated with openssl rand -hex 32
SECRET_KEY = "49e36802e75fdc8d5915073c3b0ed97580be2b701a456e857c6df7a8706a33f9"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ERR_RESOURCE_NOT_FOUND = b'"Resource \\"%s\\" could not be found."'
ERR_WRONG_TYPE = b"FAILURE: the parameters \"component_name\" and \"attribute\" must be of type str."
ERR_CONFIG_PROPERTY_NOT_EXISTING = "Creating a new config property is currently not allowed."
ERR_HEADER_NOT_IMPLEMENTED = "The Header '%s' is not implemented and must not be used."
CONFIG_PROPERTY_PATH = "/config_property/{config_property}"
ATTRIBUTE_PATH = "/attribute/{component_name}/{attribute_path}"
SAVE_CONFIG_PATH = "/save_config"
DESTINATION_FILE = "/tmp/live-config.py"
ANALYSIS_COMPONENT_PATH = "/component/"
ADD_COMPONENT_PATH = ANALYSIS_COMPONENT_PATH + "{atom_handler}"
REMOTE_CONTROL_SOCKET = "/var/run/aminer-remote.socket"
sys.path = sys.path[1:] + ["/usr/lib/logdata-anomaly-miner"]
from aminer.AnalysisChild import AnalysisChildRemoteControlHandler, LIVE_CONFIG_TEMPFILE

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
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


# this is just a fake users db and needs to be replaced by an actual user database.
# the user johndoe is used in the unittests. For production use disabled must be True.
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        # hashed "password"
        "hashed_password": "$2b$12$Rqcr7TEUCUcuH3aPKE8upu3rZmNpaGeKkkQC7a.eSRL.jskItD62W",
        "disabled": False,
    }
}


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.UTC) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.UTC) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "Bearer"}


@app.get("/")
def get_current_config(token: str = Depends(oauth2_scheme)):
    get_current_user(token)
    res = execute_remote_control_socket(b"print_current_config()", True)
    return res


@app.get(CONFIG_PROPERTY_PATH)
def get_config_property(config_property: str, token: str = Depends(oauth2_scheme)):
    get_current_user(token)
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
            except Exception:
                pass
    return {config_property: val}


@app.put(CONFIG_PROPERTY_PATH)
def put_config_property(config_property: str, item: Property, request: Request, token: str = Depends(oauth2_scheme)):
    # first check if the property exists - return the status code.
    get_current_user(token)
    check_content_headers(request)
    response = client.get("%s%s" % (CONFIG_PROPERTY_PATH.split("{")[0], config_property), headers={"Authorization": "%s %s" % (
        "Bearer", token)})
    if response.status_code == 200:
        if isinstance(item.value, (bytes, str)):
            item.value = '"%s"' % shlex.quote(item.value)
        command = 'change_config_property(analysis_context,"%s",%s)' % (shlex.quote(config_property), item.value)
        command = command.encode()
        res = execute_remote_control_socket(command, True)
        val = res.split(b":", 1)[1].strip(b" ").strip(b'\n').strip(b"'")
        if val.startswith(b"FAILURE:"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b"FAILURE: ")[1].decode().rstrip("'"))
        return JSONResponse(status_code=status.HTTP_200_OK, content={
            "message": f"Successfully changed config property {config_property} to {item.value}"})
    if response.status_code == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=ERR_CONFIG_PROPERTY_NOT_EXISTING)
    return HTTPException(status_code=response.status_code, detail="An error occurred. Response message:\n%s" % response.content)


@app.get(ATTRIBUTE_PATH)
def get_attribute_of_registered_component(component_name: str, attribute_path: str, token: str = Depends(oauth2_scheme)):
    get_current_user(token)
    command = 'print_attribute_of_registered_analysis_component(analysis_context,"%s","%s")' % (
        shlex.quote(component_name), shlex.quote(attribute_path))
    command = command.encode()
    res = execute_remote_control_socket(command, True)
    val = res.split(b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'")
    if isinstance(val, bytes) and val.startswith(b"FAILURE:"):
        if val == ERR_WRONG_TYPE:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b"FAILURE: ")[1].decode())
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=val.split(b"FAILURE: ")[1].decode())
    return json.loads(b"{%s}" % val)


@app.put(ATTRIBUTE_PATH)
def put_attribute_of_registered_component(component_name: str, attribute_path: str, item: Property, request: Request,
                                          token: str = Depends(oauth2_scheme)):
    get_current_user(token)
    check_content_headers(request)
    response = client.get("%s%s/%s" % (ATTRIBUTE_PATH.split("{")[0], component_name, attribute_path), headers={"Authorization": "%s %s" % (
        "Bearer", token)})
    if response.status_code == 200:
        if isinstance(item.value, (bytes, str)):
            item.value = '"%s"' % shlex.quote(item.value)
        command = "change_attribute_of_registered_analysis_component(analysis_context,\"%s\",\"%s\",%s)" % (
            shlex.quote(component_name), shlex.quote(attribute_path), item.value)
        command = command.encode()
        res = execute_remote_control_socket(command, True)
        val = res.split(b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'")
        if val.startswith(b"FAILURE:"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b"FAILURE: ")[1].decode())
        return JSONResponse(status_code=status.HTTP_200_OK, content={"message": f"Successfully changed attribute {attribute_path} of registered analysis component {component_name} to {item.value}"})
    if response.status_code == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=response.content.split(b'"')[3].decode())
    return HTTPException(status_code=response.status_code, detail="An error occurred. Response message:\n%s" % response.content)


@app.get(SAVE_CONFIG_PATH)
def save_config(token: str = Depends(oauth2_scheme)):
    get_current_user(token)
    command = 'save_current_config(analysis_context,"%s")' % shlex.quote(DESTINATION_FILE)
    command = command.encode()
    res = execute_remote_control_socket(command, True)
    val = res.split(b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'")
    if val.startswith(b"FAILURE:"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b"FAILURE: ")[1].decode())
    with open(DESTINATION_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    return JSONResponse(
        status_code=status.HTTP_200_OK, headers={"location": DESTINATION_FILE}, content={"filename": DESTINATION_FILE, "content": content})


@app.put(ANALYSIS_COMPONENT_PATH)
def rename_registered_analysis_component(old_component_name: str, new_component_name: str, request: Request,
                                         token: str = Depends(oauth2_scheme)):
    get_current_user(token)
    check_content_headers(request)
    command = 'rename_registered_analysis_component(analysis_context,"%s","%s")' % (
        shlex.quote(old_component_name), shlex.quote(new_component_name))
    command = command.encode()
    res = execute_remote_control_socket(command, True)
    val = res.split(b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'")
    if val.startswith(b"FAILURE:"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=val.split(b"FAILURE: ")[1].decode())
    return JSONResponse(status_code=status.HTTP_200_OK, content={
        "message": f"Successfully renamed analysis component from {old_component_name} to {new_component_name}"})


@app.post(ADD_COMPONENT_PATH)
def add_handler_to_atom_filter_and_register_analysis_component(atom_handler: str, analysis_component: AnalysisComponent,
                                                               token: str = Depends(oauth2_scheme)):
    get_current_user(token)
    parameter = ""
    for p in analysis_component.parameters:
        if parameter != "":
            parameter += ","
        if p.startswith('"') and p.endswith('"'):
            parameter += '"%s"' % shlex.quote(p)
        else:
            parameter += shlex.quote(p)
    command = "add_handler_to_atom_filter_and_register_analysis_component(analysis_context,\"%s\",%s(%s),\"%s\")" % (
        shlex.quote(atom_handler), shlex.quote(analysis_component.class_name), parameter, shlex.quote(analysis_component.component_name))
    command = command.encode()
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
