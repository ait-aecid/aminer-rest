from typing import Optional
from fastapi import FastAPI
import subprocess
import shlex

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/config_property/{config_property}")
def get_config_property(config_property: str):
    res = subprocess.run(['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'print_config_property(analysis_context,"%s")'
                          % shlex.quote(config_property)], capture_output=True)
    val = res.stdout.split(b"'")[1].split(b':')[1].strip(b' ')
    if val.isdigit():
        val = int(val)
    else:
        try:
            val = float(val)
        except:
            pass
    return {config_property: val}