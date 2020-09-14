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

from fastapi import FastAPI, status, Request
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from pydantic import BaseModel
from typing import Any, List
import subprocess  # skipcq: BAN-B404
import shlex
import json

app = FastAPI()
client = TestClient(app)
ERR_RESOURCE_NOT_FOUND = b'"Resource \\\\"%s\\\\" could not be found."'
ERR_CONFIG_PROPERTY_NOT_EXISTING = "Creating new a new config property currently is not allowed."
ERR_HEADER_NOT_IMPLEMENTED = "The Header '%s' is not implemented and must not be used."
CONFIG_PROPERTY_PATH = "/config_property/{config_property}"


class ConfigProperty(BaseModel):
    value: Any


@app.get("/")
def get_current_config():
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(
        ['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'print_current_config(analysis_context)', '--StringResponse'],
        capture_output=True)
    return json.loads((b'{' + res.stdout.split(b':', 1)[1].strip(b' ') + b'}'))


@app.get(CONFIG_PROPERTY_PATH)
def get_config_property(config_property: str):
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'print_config_property(analysis_context,"%s")'
                          % shlex.quote(config_property)], capture_output=True)
    val = res.stdout.split(b"'")[1]
    if val == ERR_RESOURCE_NOT_FOUND % config_property.encode('utf-8'):
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={'ErrorMessage': val.decode().replace('\\', '').strip('"')})
    val = val.split(b':', 1)[1].strip(b' ')
    if val.startswith(b'[') and val.endswith(b']'):
        val = json.loads(val)
    else:
        if val.isdigit():
            val = int(val)
        elif b'.' in val:
            try:
                val = float(val)
            except:  # skipcq: FLK-E722
                pass
    return {config_property: val}


@app.put(CONFIG_PROPERTY_PATH)
def put_config_property(config_property: str, item: ConfigProperty, request: Request):
    # first check if the property exists - return the status code.
    for header in request.headers:
        if header.startswith("content-") and header not in ("content-type", "content-length"):
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=ERR_HEADER_NOT_IMPLEMENTED % header)
    response = client.get("%s%s" % (CONFIG_PROPERTY_PATH.split("{")[0], config_property))
    if response.status_code == 200:
        if isinstance(item.value, (bytes, str)):
            item.value = '"%s"' % shlex.quote(item.value)
        res = subprocess.run(
            ['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'change_config_property(analysis_context,"%s",%s)' % (
                shlex.quote(config_property), item.value), '--StringResponse'], capture_output=True)
        val = res.stdout.split(b":", 1)[1]
        if val.startswith(b' FAILURE:'):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b' FAILURE: ')[1].decode())
        return JSONResponse(status_code=status.HTTP_200_OK)
    if response.status_code == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=ERR_CONFIG_PROPERTY_NOT_EXISTING)
    return HTTPException(status_code=response.status_code, detail="An error occured. Response message:\n%s" % response.content)


@app.post(CONFIG_PROPERTY_PATH.split("{")[0])
def post_config_property(config_property: ConfigProperty):
    # first check if the property exists - return the status code.
    pass
