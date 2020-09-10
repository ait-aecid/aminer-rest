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

from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Any, List
import subprocess  # skipcq: BAN-B404
import shlex
import json

app = FastAPI()
client = TestClient(app)
ERR_RESOURCE_NOT_FOUND = b'"Resource \\\\"%s\\\\" could not be found."'
CONFIG_PROPERTY_PATH = "/config_property/{config_property}"


class ConfigProperty(BaseModel):
    value: Any


@app.get("/")
def get_current_config():
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(
        ['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'print_current_config(analysis_context)', '--StringResponse'],
        capture_output=True)
    # lines = res.stdout.split(b':', 1)[1].strip(b' ').split(b'\n')
    # for i, line in enumerate(lines[:300]):
    #     print(i+1, line)
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
def put_config_property(config_property: str, item: ConfigProperty):
    # first check if the property exists - return the status code.
    response = client.get("%s%s" % (CONFIG_PROPERTY_PATH.split("{")[0], config_property))
    if response.status_code == 200:
        return JSONResponse(status_code=status.HTTP_201_CREATED)
    elif response.status_code == 404:
        return JSONResponse(status_code=status.HTTP_200_OK)
    else:
        return JSONResponse(status_code=response.status_code)


@app.post(CONFIG_PROPERTY_PATH.split("{")[0])
def post_config_property(config_property: ConfigProperty):
    # first check if the property exists - return the status code.
    pass
