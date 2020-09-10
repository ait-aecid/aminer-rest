from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Any, List
import subprocess  # skipcq: BAN-B404
import shlex
import json

app = FastAPI()
ERR_RESOURCE_NOT_FOUND = b'"Resource \\\\"%s\\\\" could not be found."'


class ConfigProperty(BaseModel):
    name: str
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


@app.get("/config_property/{config_property}")
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


@app.put("/config_property/")
def put_config_property(config_property: ConfigProperty):
    # first check if the property exists - return the status code.
    print(config_property)
    return JSONResponse(status_code=status.HTTP_201_CREATED)


@app.post("/config_property/")
def post_config_property(config_property: str):
    # first check if the property exists - return the status code.
    pass
