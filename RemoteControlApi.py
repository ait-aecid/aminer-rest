from fastapi import FastAPI
import subprocess  # skipcq: BAN-B404
import shlex

app = FastAPI()


@app.get("/")
def get_current_config():
    res = subprocess.run(
        ['sudo', 'python3', 'AMinerRemoteControl', '--Exec', 'print_current_config(analysis_context)', '--StringResponse'],
        capture_output=True)
    import json
    #return json.loads(b'{' + res.stdout.strip(b' ') + b'}')
    lines = res.stdout.split(b':', 1)[1].strip(b' ').split(b'\n')
    config = {}
    currently_in = [config]
    currently_in_key = []
    list_vals = []
    for line in lines:
        isin = False
        print(line)
        if b'{' in line and len(list_vals) == 0:
            # if len(list_vals) == 0:
            #     currently_in.append({})
            # else:
            #     currently_in.append(currently_in[-1])
            currently_in.append({})
            currently_in_key.append(line.split(b'{')[0].strip().rstrip(b':'))
            isin = True
        if b':' in line or len(list_vals) > 0:
            if len(list_vals) > 0: #b':' not in line and len(list_vals) > 0:
                list_vals[-1][1].append(line)
                value = line
                # if b']' not in value:
                #     continue
            else:
                key, value = line.split(b':', 1)
                key = key.strip(b' ')
                value = value.strip(b' ').strip(b'"').strip(b"'")
            #print(b"%s: %s" % (key, value))
            if b'[' in value:
                if b'(' in value and b')' in value:
                    sep = b'('
                    vals = value.lstrip(b'[').rstrip(b']').split(sep)
                    vals = list(map(lambda x: sep + x.rstrip(b" ").rstrip(b','), vals))
                    vals = list(filter(lambda x: x != sep, vals))
                    list_vals.append((key, vals))
                else:
                    sep = b','
                    list_vals.append((key, value.lstrip(b'[').rstrip(b']').split(sep)))
                # currently_in.append(list_vals[-1][1])
                # currently_in_key.append(key)
                #print("\n", "LISTVALS_START", list_vals, "\n", len(list_vals))
                # if b']' not in value:
                #     continue
            if b']' in value:
                value = list(map(lambda x: x.strip(b"'").strip(b'"'), list_vals[-1][1]))
                #value = dict(enumerate(value))
                key = list_vals[-1][0]
                del list_vals[-1]
                #print("LISTVALS", list_vals)
                # if len(list_vals) > 0:
                #     continue
            if isinstance(value, list) or isinstance(value, dict):
                pass
            elif value == b'None':
                value = None
            elif value == b'True':
                value = True
            elif value == b'False':
                value = False
            elif value.isdigit():
                value = int(value)
            else:
                try:
                    value = float(value)
                except:  # skipcq: FLK-E722
                    pass
            currently_in[-1][key] = value
            isin = True
        if b'}' in line and len(list_vals) == 0:# or b']' in line:
            config[currently_in_key[-1]] = currently_in[-1]
            del currently_in_key[-1]
            del currently_in[-1]
            isin = True
        if not isin and line != b'':
            print("MISSING", line)
    return config


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