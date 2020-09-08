from fastapi import FastAPI
import subprocess  # skipcq: BAN-B404
import shlex
import json

app = FastAPI()


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
    val = res.stdout.split(b"'", 1)[1].split(b':')[1].strip(b' ')
    if val.isdigit():
        val = int(val)
    else:
        try:
            val = float(val)
        except:  # skipcq: FLK-E722
            pass
    return {config_property: val}