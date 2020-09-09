from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
import subprocess  # skipcq: BAN-B404
import shlex
import json

app = FastAPI()
ERROR_MESSAGE_RESOURCE_NOT_FOUND = b'"Resource \\\\"%s\\\\" could not be found."'


@app.get("/")
def get_current_config():
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(
        ['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'print_current_config(analysis_context)', '--StringResponse'],
        capture_output=True)
    return json.loads((b'{' + res.stdout.split(b':', 1)[1].strip(b' ') + b'}'))


@app.get("/config_property/{config_property}")
def get_config_property(config_property: str):
    # skipcq: BAN-B603, BAN-B607, PYL-W1510
    res = subprocess.run(['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'print_config_property(analysis_context,"%s")'
                          % shlex.quote(config_property)], capture_output=True)
    print(res.stdout)
    val = res.stdout.split(b"'")[1]
    if val == ERROR_MESSAGE_RESOURCE_NOT_FOUND % config_property.encode('utf-8'):
        print(val)
        print(val.decode())
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