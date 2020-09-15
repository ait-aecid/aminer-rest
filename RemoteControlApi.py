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
ERR_WRONG_TYPE = b"FAILURE: the parameters 'component_name' and 'attribute' must be of type str."
ERR_CONFIG_PROPERTY_NOT_EXISTING = "Creating new a new config property currently is not allowed."
ERR_HEADER_NOT_IMPLEMENTED = "The Header '%s' is not implemented and must not be used."
CONFIG_PROPERTY_PATH = "/config_property/{config_property}"
ATTRIBUTE_PATH = "/attribute/{component_name}/{attribute_path}"
SAVE_CONFIG_PATH = "/save_config"
DESTINATION_FILE = "/tmp/config.py"
ANALYSIS_COMPONENT_PATH = "/component/"
ADD_COMPONENT_PATH = ANALYSIS_COMPONENT_PATH + "{atom_handler}"


class Property(BaseModel):
    value: Any


class AnalysisComponent(BaseModel):
    class_name: str
    parameters: List[str]
    component_name: str


@app.get("/")
def get_current_config():
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'print_current_config(analysis_context)', '--StringResponse'],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return json.loads((b'{' + res.stdout.split(b':', 1)[1].strip(b' ') + b'}'))


@app.get(CONFIG_PROPERTY_PATH)
def get_config_property(config_property: str):
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'print_config_property(analysis_context,"%s")'
                          % shlex.quote(config_property)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    val = res.stdout.split(b"'")[1]
    if val == ERR_RESOURCE_NOT_FOUND % config_property.encode('utf-8'):
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={'ErrorMessage': val.decode().replace('\\', '').strip('"')})
    val = val.split(b':', 1)[1].strip(b' ').strip(b'\n')
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
def put_config_property(config_property: str, item: Property, request: Request):
    # first check if the property exists - return the status code.
    check_content_headers(request)
    response = client.get("%s%s" % (CONFIG_PROPERTY_PATH.split("{")[0], config_property))
    if response.status_code == 200:
        if isinstance(item.value, (bytes, str)):
            item.value = '"%s"' % shlex.quote(item.value)
        # skipcq: BAN-B603, BAN-B607, PYL-W1510
        res = subprocess.run(['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'change_config_property(analysis_context,"%s",%s)' % (
                shlex.quote(config_property), item.value), '--StringResponse'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        val = res.stdout.split(b":", 1)[1].strip(b' ').strip(b'\n')
        if val.startswith(b'FAILURE:'):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b'FAILURE: ')[1].decode())
        return JSONResponse(status_code=status.HTTP_200_OK)
    if response.status_code == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=ERR_CONFIG_PROPERTY_NOT_EXISTING)
    return HTTPException(status_code=response.status_code, detail="An error occured. Response message:\n%s" % response.content)


@app.get(ATTRIBUTE_PATH)
def get_attribute_of_registered_component(component_name: str, attribute_path: str):
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(['sudo', 'python3', 'AMinerRemoteControl', '--Exec',
                          'print_attribute_of_registered_analysis_component(analysis_context,"%s","%s")' % (
                              shlex.quote(component_name), shlex.quote(attribute_path)), '--StringResponse'], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    val = res.stdout.split(b':', 1)[1].strip(b' ').strip(b'\n')
    if isinstance(val, bytes) and val.startswith(b'FAILURE:'):
        if val == ERR_WRONG_TYPE:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b'FAILURE: ')[1].decode())
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=val.split(b'FAILURE: ')[1].decode())
    return json.loads(b'{%s}' % val)


@app.put(ATTRIBUTE_PATH)
def put_attribute_of_registered_component(component_name: str, attribute_path: str, item: Property, request: Request):
    check_content_headers(request)
    response = client.get("%s%s/%s" % (ATTRIBUTE_PATH.split("{")[0], component_name, attribute_path))
    if response.status_code == 200:
        if isinstance(item.value, (bytes, str)):
            item.value = '"%s"' % shlex.quote(item.value)
        # skipcq: BAN-B603, BAN-B607, PYL-W1510
        res = subprocess.run([
            'sudo', 'python3', 'AMinerRemoteControl', '--Exec',
            'change_attribute_of_registered_analysis_component(analysis_context,"%s","%s",%s)' % (
                shlex.quote(component_name), shlex.quote(attribute_path), item.value), '--StringResponse'], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        val = res.stdout.split(b":", 1)[1].strip(b' ').strip(b'\n')
        if val.startswith(b'FAILURE:'):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b'FAILURE: ')[1].decode())
        return JSONResponse(status_code=status.HTTP_200_OK)
    if response.status_code == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=response.content.split(b'"')[3].decode())
    return HTTPException(status_code=response.status_code, detail="An error occured. Response message:\n%s" % response.content)


@app.get(SAVE_CONFIG_PATH)
def save_config():
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(['sudo', 'python3', 'AMinerRemoteControl', '--Exec',
                          'save_current_config(analysis_context,"%s")' % shlex.quote(DESTINATION_FILE), '--StringResponse'],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    val = res.stdout.split(b":", 1)[1].strip(b' ').strip(b'\n')
    if val.startswith(b'FAILURE:'):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.split(b'FAILURE: ')[1].decode())
    return JSONResponse(status_code=status.HTTP_200_OK, headers={"location": DESTINATION_FILE})


@app.put(ANALYSIS_COMPONENT_PATH)
def rename_registered_analysis_component(old_component_name: str, new_component_name: str, request: Request):
    check_content_headers(request)
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(['sudo', 'python3', 'AMinerRemoteControl', '--Exec',
                          'rename_registered_analysis_component(analysis_context,"%s","%s")' % (
                              shlex.quote(old_component_name), shlex.quote(new_component_name)), '--StringResponse'],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    val = res.stdout.split(b":", 1)[1].strip(b' ').strip(b'\n')
    if val.startswith(b'FAILURE:'):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=val.split(b'FAILURE: ')[1].decode())
    return JSONResponse(status_code=status.HTTP_200_OK)


@app.post(ADD_COMPONENT_PATH)
def add_handler_to_atom_filter_and_register_analysis_component(atom_handler: str, analysis_component: AnalysisComponent):
    parameter_str = ''
    for p in analysis_component.parameters:
        if parameter_str != '':
            parameter_str += ','
        if p.startswith('"') and p.endswith('"'):
            parameter_str += '"%s"' % shlex.quote(p)
        else:
            parameter_str += shlex.quote(p)
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(['sudo', 'python3', 'AMinerRemoteControl', '--Exec',
                          'add_handler_to_atom_filter_and_register_analysis_component(analysis_context,"%s",%s(%s),"%s")' % (
                              shlex.quote(atom_handler), shlex.quote(analysis_component.class_name), parameter_str,
                              shlex.quote(analysis_component.component_name)), '--StringResponse'], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    val = res.stdout.split(b":", 1)[1].strip(b' ').strip(b'\n')
    if val.startswith(b'FAILURE:'):
        val = val.split(b'FAILURE: ')[1]
        if val == b"atomHandler '%s' does not exist!" % atom_handler.encode('utf-8'):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=val.decode())
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=val.decode())
    return JSONResponse(status_code=status.HTTP_200_OK)


def check_content_headers(request):
    for header in request.headers:
        if header.startswith("content-") and header not in ("content-type", "content-length"):
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=ERR_HEADER_NOT_IMPLEMENTED % header)
