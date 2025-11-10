import unittest
from RemoteControlApi import ERR_RESOURCE_NOT_FOUND, ERR_CONFIG_PROPERTY_NOT_EXISTING, ERR_HEADER_NOT_IMPLEMENTED, DESTINATION_FILE, \
    ANALYSIS_COMPONENT_PATH, app, guess_config_type, get_password_hash, jsonschema_to_cerberus
from fastapi.testclient import TestClient
from database import init_db, SessionLocal, UserDB
from datetime import datetime, timezone
from cerberus import Validator
import os
import json
import asyncio
import threading
from time import time


def ensure_test_user():
    db = SessionLocal()
    if not db.query(UserDB).filter_by(username="johndoe").first():
        user = UserDB(
            username="johndoe",
            hashed_password=get_password_hash("password"),
            email="john@example.com",
            is_admin=False,
            disabled=False,
            must_reset_password=False,
        )
        db.add(user)
        db.commit()
    db.close()


# def receive_text_with_timeout(ws, timeout=1):
#     result = [None]
#     done = threading.Event()
#     def worker():
#         try:
#             result[0] = ws.receive_text()
#         except Exception:
#             pass
#         finally:
#             done.set()
#     t = threading.Thread(target=worker, daemon=True)
#     t.start()
#     done.wait(timeout)
#     if not done.is_set():
#         try:
#             ws.close()
#         except Exception:
#             pass
#         return None
#     return result[0]


class RemoteControlApiTest(unittest.TestCase):
    """This class tests the REST RemoteControlApi.

    The start of an AMiner instance and of the RemoteControlApi is not
    the task of this class and must be done beforehand.
    """
    client = TestClient(app)
    access_token = None
    token_type = "Bearer"
    authorization_headers = None
    output_schema = jsonschema_to_cerberus({
      "$id": "",
      "title": "Metadata",
      "description": "",
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "type": "object",
      "properties": {
        "title": {
          "type": "string"
        },
        "creator": {
          "type": "string"
        },
        "subject": {
          "type": "string"
        },
        "description": {
          "type": "string"
        },
        "publisher": {
          "type": "string"
        },
        "contributor": {
          "type": "string"
        },
        "date": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "format": {
          "type": "string"
        },
        "identifier": {
          "type": "string"
        },
        "source": {
          "type": "string"
        },
        "language": {
          "type": "string"
        },
        "relation": {
          "type": "string"
        },
        "coverage": {
          "type": "string"
        },
        "rights": {
          "type": "string"
        }
      },
      "required": [
        "title",
        "creator",
        "subject",
        "description",
        "date",
        "type",
        "format",
        "identifier",
        "language"
      ]
    })

    @classmethod
    def setUpClass(cls):
        init_db()
        ensure_test_user()
        response = cls.client.post("/token", data={
            "username": "johndoe", "password": "password",
            "client_secret": "49e36802e75fdc8d5915073c3b0ed97580be2b701a456e857c6df7a8706a33f9"})
        cls.access_token = json.loads(response.content)["access_token"]
        cls.authorization_headers = {"Authorization": "%s %s" % (cls.token_type, cls.access_token)}

        response = cls.client.get("/", headers=cls.authorization_headers)
        cls.dest_config_file = DESTINATION_FILE + guess_config_type(response.content.split(b":", 1)[1].strip(b" ").strip(b"\n").strip(b"'").decode("unicode-escape"))

    def test0websocket_aminer_output(self):
        """Test that WebSocket endpoint broadcasts new file lines."""
        t = time()
        dtf = "%Y-%m-%d %H:%M:%S"
        dtm = datetime.fromtimestamp(float(t), tz=timezone.utc).strftime(dtf)
        response = self.client.post("/aminer-input", json={"log_id": "1", "timestamp": str(datetime.now(timezone.utc).timestamp()), "severity": "info", "source": "remoteControlApiTest", "message": "initial line"})
        print(json.loads(response.content.decode()))
        self.assertEqual(response.status_code, 200)
        v = Validator(self.output_schema)
        data = json.loads(response.content.decode())
        self.assertTrue(v.validate(data))
        response = self.client.post("/aminer-input", json={"log_id": "2", "timestamp": str(datetime.now(timezone.utc).timestamp()), "severity": "info", "source": "remoteControlApiTest", "message": f"{dtm} ubuntu cron[50000]: Will run job `cron.daily' in 5 min."})
        data = json.loads(response.content.decode())
        self.assertTrue(v.validate(data))
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/aminer-input", json={"log_id": "3", "timestamp": str(datetime.now(timezone.utc).timestamp()), "severity": "info", "source": "remoteControlApiTest", "message": f"{dtm} ubuntu cron[50000]: Will run job `cron.daily' in 5 min."})
        data = json.loads(response.content.decode())
        self.assertTrue(v.validate(data))
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/aminer-input", json={"log_id": "4", "timestamp": str(datetime.now(timezone.utc).timestamp()), "severity": "info", "source": "remoteControlApiTest", "message": f"Any:dafsdff12%3§fasß?–_=yy"})
        data = json.loads(response.content.decode())
        self.assertTrue(v.validate(data))
        self.assertEqual(response.status_code, 200)

    def test1get_config_property(self):
        live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        property_name = "MailAlerting.MaxEventsPerMessage"
        response = self.client.get("config_property/%s" % property_name, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"{property_name}\":1000}}".encode())
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        self.assertEqual(new_live_config, live_config)

        live_config = new_live_config
        property_name = "AminerUser"
        response = self.client.get("config_property/%s" % property_name, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"{property_name}\":\"aminer\"}}".encode())
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        self.assertEqual(new_live_config, live_config)

        live_config = new_live_config
        property_name = "LogResourceList"
        response = self.client.get("config_property/%s" % property_name, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"{property_name}\":[\"file:///tmp/syslog\",\"file:///tmp/aminer-rest-input.log\"]}}".encode())
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        self.assertEqual(new_live_config, live_config)

        live_config = new_live_config
        response = self.client.get("config_property/%s" % property_name)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        self.assertEqual(new_live_config, live_config)

        live_config = new_live_config
        response = self.client.get("config_property/%s" % property_name, headers={
            "Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        self.assertEqual(new_live_config, live_config)

        live_config = new_live_config
        property_name = "NonExistentConfigProperty"
        response = self.client.get("config_property/%s" % property_name, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"ErrorMessage\":{ERR_RESOURCE_NOT_FOUND.decode() % property_name}}}".encode())
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        self.assertEqual(new_live_config, live_config)

    def test2put_config_property(self):
        live_config = self.client.get("/", headers=self.authorization_headers).content
        property_name = "Core.PersistencePeriod"
        response = self.client.put("config_property/%s" % property_name, json={"value": 700}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("config_property/%s" % property_name, headers=self.authorization_headers).content,
                         f"{{\"{property_name}\":700}}".encode())
        self.assertEqual(response.content, f"{{\"message\":\"Successfully changed config property {property_name} to {700}.\"}}".encode())
        new_live_config = self.client.get("/", headers=self.authorization_headers).content
        c = live_config.replace(b'atom_filter.add_handler(time_correlation_violation_detector)\\n\'"', b'atom_filter.add_handler(time_correlation_violation_detector)\\n\\nconfig_properties[\\"Core.PersistencePeriod\\"] = 700\'"')
        if self.dest_config_file.endswith(".yml"):
            c = live_config.replace(b'Core.PersistencePeriod: 600', b'Core.PersistencePeriod: 700')
        self.assertEqual(new_live_config, c)
        self.assertNotEqual(new_live_config, live_config)
        self.client.put("config_property/%s" % property_name, json={"value": 600}, headers=self.authorization_headers)
        new_live_config = self.client.get("/", headers=self.authorization_headers).content
        c = c.replace(b'Core.PersistencePeriod\\"] = 700', b'Core.PersistencePeriod\\"] = 600')
        if self.dest_config_file.endswith(".yml"):
            c = live_config
        self.assertEqual(new_live_config, c)

        live_config = new_live_config
        property_name = "MailAlerting.MaxEventsPerMessage"
        response = self.client.put("config_property/%s" % property_name, json={"value": 2}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("config_property/%s" % property_name, headers=self.authorization_headers).content,
                         f"{{\"{property_name}\":2}}".encode())
        self.assertEqual(response.content, f"{{\"message\":\"Successfully changed config property {property_name} to {2}.\"}}".encode())
        new_live_config = self.client.get("/", headers=self.authorization_headers).content
        self.assertNotEqual(new_live_config, live_config)
        c = live_config.replace(b"MailAlerting.MaxEventsPerMessage'] = 1000", b"MailAlerting.MaxEventsPerMessage'] = 2")
        if self.dest_config_file.endswith(".yml"):
            c = live_config.replace(b"MailAlerting.MaxEventsPerMessage: 1000", b"MailAlerting.MaxEventsPerMessage: 2")
        self.assertEqual(new_live_config, c)
        self.client.put("config_property/%s" % property_name, json={"value": 1000}, headers=self.authorization_headers)
        new_live_config = self.client.get("/", headers=self.authorization_headers).content
        c = live_config
        if self.dest_config_file.endswith(".yml"):
            c = live_config
        self.assertEqual(new_live_config, c)

        response = self.client.put("config_property/%s" % property_name, json={"value": 2})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("/", headers=self.authorization_headers).content, live_config)

        response = self.client.put("config_property/%s" % property_name, json={"value": 2}, headers={
            "Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("/", headers=self.authorization_headers).content, live_config)

        response = self.client.put("config_property/%s" % property_name, json={"value": "2"}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("config_property/%s" % property_name, headers=self.authorization_headers).content,
                         f"{{\"{property_name}\":1000}}".encode())
        self.assertEqual(response.content, f"{{\"detail\":\"the value of the property '{property_name}' must be of type {type(1000)}!\"}}".encode())
        self.assertEqual(self.client.get("/", headers=self.authorization_headers).content, live_config)

        property_name = "AminerUser"
        response = self.client.put("config_property/%s" % property_name, json={"value": "new_aminer"}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("config_property/%s" % property_name, headers=self.authorization_headers).content,
                         f"{{\"{property_name}\":\"aminer\"}}".encode())
        self.assertEqual(response.content, f"{{\"detail\":\"the property '{property_name}' can only be changed at startup in the aminer root process!\"}}".encode())
        self.assertEqual(self.client.get("/", headers=self.authorization_headers).content, live_config)

        property_name = "LogResourceList"
        response = self.client.put("config_property/%s" % property_name, json={"value": ["file:///tmp/syslog.txt"]},
                                   headers=self.authorization_headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("config_property/%s" % property_name, headers=self.authorization_headers).content,
                         f"{{\"{property_name}\":[\"file:///tmp/syslog\",\"file:///tmp/aminer-rest-input.log\"]}}".encode())
        self.assertEqual(response.content, f"{{\"detail\":\"the property '{property_name}' can only be changed at startup in the aminer root process!\"}}".encode())
        self.assertEqual(self.client.get("/", headers=self.authorization_headers).content, live_config)

        property_name = "NoneExistentConfigProperty"
        response = self.client.put("config_property/%s" % property_name, json={"value": "some string"}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"{ERR_CONFIG_PROPERTY_NOT_EXISTING}"}}'.encode())
        self.assertEqual(self.client.get("/", headers=self.authorization_headers).content, live_config)

        property_name = "LogResourceList"
        response = self.client.put("config_property/%s" % property_name, json={"value": ["file:///tmp/syslog.txt"]},
                                   headers={"content-md5": "md5 string", **self.authorization_headers})
        self.assertEqual(response.status_code, 501)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"{ERR_HEADER_NOT_IMPLEMENTED % "content-md5"}"}}'.encode())
        self.assertEqual(self.client.get("/", headers=self.authorization_headers).content, live_config)

    def test3get_attribute_of_registered_component(self):
        component_name = "NewMatchPathValueCombo"
        attribute_name = "target_path_list"
        response = self.client.get("attribute/%s/%s" % (component_name, attribute_name), headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"{component_name}.{attribute_name}\":[\"/model/IPAddresses/Username\",\"/model/IPAddresses/IP\"]}}".encode())

        response = self.client.get("attribute/%s/%s" % (component_name, attribute_name))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.get("attribute/%s/%s" % (component_name, attribute_name), headers={
            "Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        component_name = "NewMatchPathValueComboDetector"
        attribute_name = "target_path_list"
        response = self.client.get("attribute/%s/%s" % (component_name, attribute_name), headers=self.authorization_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"the component \'{component_name}\' does not exist."}}'.encode())

        component_name = "NewMatchPathValueCombo"
        attribute_name = "not_existing_attribute"
        response = self.client.get("attribute/%s/%s" % (component_name, attribute_name), headers=self.authorization_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"the component \'{component_name}\' does not have an attribute named \'{attribute_name}\'."}}'.encode())

        attribute_name = "learn_mode"
        response = self.client.get("attribute/%s/%s" % (component_name, attribute_name), headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"{component_name}.{attribute_name}\":false}}".encode())

    def test4put_attribute_of_registered_component(self):
        live_config = self.client.get("/", headers=self.authorization_headers).content
        component_name = "NewMatchPathValueCombo"
        attribute_name = "learn_mode"
        response = self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": True}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("attribute/%s/%s" % (component_name, attribute_name), headers=self.authorization_headers).content,
                         f"{{\"{component_name}.{attribute_name}\":true}}".encode())
        self.assertEqual(response.content, f"{{\"message\":\"Successfully changed attribute {attribute_name} of registered analysis component {component_name} to True\"}}".encode())
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        c = live_config.replace(b'anomaly_event_handlers.append(mail_notification_handler)\\n\'"', b'anomaly_event_handlers.append(mail_notification_handler)\\n\\nconfig_properties[\\"Core.PersistencePeriod\\"] = 600\'"').replace(b'\\nconfig_properties[\\"Core.PersistencePeriod\\"] = 600\'"', f"\n    setattr(analysis_context.get_component_by_name(\"{component_name}\"), \"{attribute_name}\", True)\nconfig_properties[\\\"Core.PersistencePeriod\\\"] = 600".encode() + b'\'"')
        if self.dest_config_file.endswith(".yml"):
            c = live_config.replace(b'- type: NewMatchPathValueComboDetector\\n          id: NewMatchPathValueCombo\\n          paths:\\n            - \\"/model/IPAddresses/Username\\"\\n            - \\"/model/IPAddresses/IP\\"\\n          learn_mode: False', b'- type: NewMatchPathValueComboDetector\\n          id: NewMatchPathValueCombo\\n          paths:\\n            - \\"/model/IPAddresses/Username\\"\\n            - \\"/model/IPAddresses/IP\\"\\n          learn_mode: True')
        self.assertEqual(new_live_config, c.decode("unicode-escape"))
        self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": False}, headers=self.authorization_headers)
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        c = live_config.replace(b'\\nconfig_properties[\\"Core.PersistencePeriod\\"] = 600\'"', f"\n    setattr(analysis_context.get_component_by_name(\"{component_name}\"), \"{attribute_name}\", False)\nconfig_properties[\\\"Core.PersistencePeriod\\\"] = 600".encode() + b'\'"')
        if self.dest_config_file.endswith(".yml"):
            c = live_config
        self.assertEqual(new_live_config, c.decode("unicode-escape"))

        response = self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": True})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": True}, headers={
            "Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": 2},
                                   headers=self.authorization_headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("attribute/%s/%s" % (component_name, attribute_name), headers=self.authorization_headers).content,
                         f"{{\"{component_name}.{attribute_name}\":false}}".encode())
        self.assertEqual(response.content, f'{{"detail":"property \'{component_name}.{attribute_name}\' must be of type {type(True)}!"}}'.encode())

        component_name = "NewMatchPathValueComboDetector"
        response = self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": True},
                                   headers=self.authorization_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"the component \'{component_name}\' does not exist."}}'.encode())

        component_name = "NewMatchPathValueCombo"
        attribute_name = "not_existing_attribute"
        response = self.client.get("attribute/%s/%s" % (component_name, attribute_name), headers=self.authorization_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"the component \'{component_name}\' does not have an attribute named \'{attribute_name}\'."}}'.encode())

        attribute_name = "learn_mode"
        response = self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": True},
                                   headers={"content-md5": "md5 string", **self.authorization_headers})
        self.assertEqual(response.status_code, 501)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"{ERR_HEADER_NOT_IMPLEMENTED % "content-md5"}"}}'.encode())

    def test5save_config(self):
        live_config = self.client.get("/", headers=self.authorization_headers).content.replace(b'"Remote execution response: \'', b"").replace(b'\'"', b"")
        component_name = "NewMatchPathValueCombo"
        attribute_name = "learn_mode"
        response = self.client.get("save_config", headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.headers["location"], self.dest_config_file)
        c = live_config
        if self.dest_config_file.endswith(".yml"):
            c = live_config
        self.assertEqual(response.content, f"{{\"filename\":\"{self.dest_config_file}\",\"content\":\"{c.decode()}\"}}".encode())

        # change values
        c = c.replace(f'setattr(analysis_context.get_component_by_name(\\"{component_name}\\"), \\"{attribute_name}\\", False)'.encode(), f'setattr(analysis_context.get_component_by_name(\\"{component_name}\\"), \\"{attribute_name}\\", True)'.encode())
        property_name = "Core.PersistencePeriod"
        self.client.put("config_property/%s" % property_name, json={"value": 700}, headers=self.authorization_headers)
        property_name = "MailAlerting.MaxEventsPerMessage"
        self.client.put("config_property/%s" % property_name, json={"value": 2}, headers=self.authorization_headers)
        self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": True}, headers=self.authorization_headers)

        response = self.client.get("save_config", headers=self.authorization_headers)
        c = c.replace(b'Core.PersistencePeriod\\"] = 600', b'Core.PersistencePeriod\\"] = 700').replace(b"MailAlerting.MaxEventsPerMessage'] = 1000", b"MailAlerting.MaxEventsPerMessage'] = 2")
        if self.dest_config_file.endswith(".yml"):
            c = c.replace(b'Core.PersistencePeriod: 600', b'Core.PersistencePeriod: 700').replace(b"MailAlerting.MaxEventsPerMessage: 1000", b"MailAlerting.MaxEventsPerMessage: 2").replace(b'- type: NewMatchPathValueComboDetector\\n          id: NewMatchPathValueCombo\\n          paths:\\n            - \\"/model/IPAddresses/Username\\"\\n            - \\"/model/IPAddresses/IP\\"\\n          learn_mode: False', b'- type: NewMatchPathValueComboDetector\\n          id: NewMatchPathValueCombo\\n          paths:\\n            - \\"/model/IPAddresses/Username\\"\\n            - \\"/model/IPAddresses/IP\\"\\n          learn_mode: True')
        self.assertEqual(response.content, f"{{\"filename\":\"{self.dest_config_file}\",\"content\":\"{c.decode()}\"}}".encode())

        # reset values
        property_name = "Core.PersistencePeriod"
        self.client.put("config_property/%s" % property_name, json={"value": 600}, headers=self.authorization_headers)
        property_name = "MailAlerting.MaxEventsPerMessage"
        self.client.put("config_property/%s" % property_name, json={"value": 1000}, headers=self.authorization_headers)
        component_name = "NewMatchPathValueCombo"
        attribute_name = "learn_mode"
        self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": False}, headers=self.authorization_headers)

        c = c.replace(b'Core.PersistencePeriod\\"] = 700', b'Core.PersistencePeriod\\"] = 600').replace(b"MailAlerting.MaxEventsPerMessage'] = 2", b"MailAlerting.MaxEventsPerMessage'] = 1000").replace(f"\\n    setattr(analysis_context.get_component_by_name(\\\"{component_name}\\\"), \\\"{attribute_name}\\\", True)".encode(), f"\\n    setattr(analysis_context.get_component_by_name(\\\"{component_name}\\\"), \\\"{attribute_name}\\\", False)".encode())
        if self.dest_config_file.endswith(".yml"):
            c = live_config
        response = self.client.get("save_config", headers=self.authorization_headers)
        self.assertEqual(response.content, f"{{\"filename\":\"{self.dest_config_file}\",\"content\":\"{c.decode()}\"}}".encode())

        response = self.client.get("save_config")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.get("save_config", headers={
            "Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")
        os.remove(self.dest_config_file)

    def test6rename_registered_analysis_component(self):
        live_config = self.client.get("/", headers=self.authorization_headers).content
        old_component_name = "NewMatchPathValueCombo"
        new_component_name = "NewMatchPathValueComboDetector"
        response = self.client.put(ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (
            old_component_name, new_component_name), headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"message\":\"Successfully renamed analysis component from {old_component_name} to {new_component_name}\"}}".encode())
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        c = live_config.replace(b'\\nconfig_properties[\\"Core.PersistencePeriod\\"] = 600\'"', f"\n    component = analysis_context.get_component_by_name(\"{old_component_name}\")\n    analysis_context.registered_components_by_name[\"{old_component_name}\"] = None\n    analysis_context.registered_components_by_name[\"{new_component_name}\"] = component\nconfig_properties[\\\"Core.PersistencePeriod\\\"] = 600".encode() + b'\'"')
        if self.dest_config_file.endswith(".yml"):
            c = live_config.replace(b'- type: NewMatchPathValueComboDetector\\n          id: NewMatchPathValueCombo\\n          paths:\\n            - \\"/model/IPAddresses/Username\\"\\n            - \\"/model/IPAddresses/IP\\"\\n          learn_mode: False', b'- type: NewMatchPathValueComboDetector\\n          id: NewMatchPathValueComboDetector\\n          paths:\\n            - \\"/model/IPAddresses/Username\\"\\n            - \\"/model/IPAddresses/IP\\"\\n          learn_mode: False')
        self.assertEqual(new_live_config, c.decode("unicode-escape"))

        # reset value
        self.client.put(ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (
            new_component_name, old_component_name), headers=self.authorization_headers)
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        c = live_config.replace(b'\\nconfig_properties[\\"Core.PersistencePeriod\\"] = 600\'"', f"\n    component = analysis_context.get_component_by_name(\"{old_component_name}\")\n    analysis_context.registered_components_by_name[\"{old_component_name}\"] = None\n    analysis_context.registered_components_by_name[\"{new_component_name}\"] = component\n    component = analysis_context.get_component_by_name(\"{new_component_name}\")\n    analysis_context.registered_components_by_name[\"{new_component_name}\"] = None\n    analysis_context.registered_components_by_name[\"{old_component_name}\"] = component\nconfig_properties[\\\"Core.PersistencePeriod\\\"] = 600".encode() + b'\'"')
        if self.dest_config_file.endswith(".yml"):
            c = live_config
        self.assertEqual(new_live_config, c.decode("unicode-escape"))

        response = self.client.put(ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (
            old_component_name, new_component_name))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.put(ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (
            old_component_name, new_component_name), headers={
            "Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        old_component_name = "NotExistingComponent"
        response = self.client.put(ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (
            old_component_name, new_component_name), headers=self.authorization_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"the component \'{old_component_name}\' does not exist."}}'.encode())

        old_component_name = "NewMatchPathValueCombo"
        response = self.client.put(
            ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (old_component_name, new_component_name),
            headers={"content-md5": "md5 string", **self.authorization_headers})
        self.assertEqual(response.status_code, 501)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"{ERR_HEADER_NOT_IMPLEMENTED % "content-md5"}"}}'.encode())

    def test7add_handler_to_atom_filter_and_register_analysis_component(self):
        """This test is problematic as there is no way to remove analysis
        components without restarting the AMiner."""
        live_config = self.client.get("/", headers=self.authorization_headers).content
        atom_handler = "AtomFilter"
        class_name = "NewMatchPathDetector"
        parameters = ["analysis_context.aminer_config", "analysis_context.atomizer_factory.event_handler_list", "learn_mode=True"]
        component_name = "NewComponent1"
        response = self.client.post(ANALYSIS_COMPONENT_PATH + atom_handler, json={
            "class_name": class_name, "parameters": parameters, "component_name": component_name}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"message\":\"Successfully added new {class_name} with the name {component_name} to the atom filter {atom_handler}\"}}".encode())
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        c = live_config.replace(b'\\nconfig_properties[\\"Core.PersistencePeriod\\"] = 600\'"', f"\n    add_handler_to_atom_filter_and_register_analysis_component(analysis_context,\\\"AtomFilter\\\",NewMatchPathDetector(analysis_context.aminer_config,analysis_context.atomizer_factory.event_handler_list,learn_mode=True),\\\"NewComponent1\\\")\nconfig_properties[\\\"Core.PersistencePeriod\\\"] = 600".encode() + b'\'"')
        if self.dest_config_file.endswith(".yml"):
            c = live_config.replace(b'Analysis:\\n        - type: TimestampsUnsortedDetector', b'Analysis:\\n        - type: NewMatchPathDetector\\n          id: NewComponent1\\n          learn_mode: True\\n        - type: TimestampsUnsortedDetector')
        self.assertEqual(new_live_config, c.decode("unicode-escape"))

        atom_handler = "AtomFilter"
        class_name = "MatchValueAverageChangeDetector"
        parameters = ["analysis_context.aminer_config", "analysis_context.atomizer_factory.event_handler_list", "\"/some/timestamp/path\"", "[\"some/target/path\"]", "1", "10", "learn_mode=True"]
        component_name = "MatchValueAverageChange-NEW"
        response = self.client.post(ANALYSIS_COMPONENT_PATH + atom_handler, json={
            "class_name": class_name, "parameters": parameters, "component_name": component_name}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"message\":\"Successfully added new {class_name} with the name {component_name} to the atom filter {atom_handler}\"}}".encode())
        new_live_config = self.client.get("/", headers=self.authorization_headers).content.decode("unicode-escape")
        c = live_config.replace(b'\\nconfig_properties[\\"Core.PersistencePeriod\\"] = 600\'"', f"\n    add_handler_to_atom_filter_and_register_analysis_component(analysis_context,\\\"AtomFilter\\\",NewMatchPathDetector(analysis_context.aminer_config,analysis_context.atomizer_factory.event_handler_list,learn_mode=True),\\\"NewComponent1\\\")\n    add_handler_to_atom_filter_and_register_analysis_component(analysis_context,\\\"AtomFilter\\\",MatchValueAverageChangeDetector(analysis_context.aminer_config,analysis_context.atomizer_factory.event_handler_list,\\\"/some/timestamp/path\\\",[\\\"some/target/path\\\"],1,10,learn_mode=True),\\\"MatchValueAverageChange-NEW\\\")\nconfig_properties[\\\"Core.PersistencePeriod\\\"] = 600".encode() + b'\'"')
        if self.dest_config_file.endswith(".yml"):
            c = live_config.replace(b'Analysis:\\n        - type: TimestampsUnsortedDetector', b'Analysis:\\n        - type: MatchValueAverageChangeDetector\\n          id: MatchValueAverageChange-NEW\\n          timestamp_path: "/some/timestamp/path"\\n          paths: ["some/target/path"]\\n          min_bin_elements: 1\\n          min_bin_time: 10\\n          learn_mode: True\\n        - type: NewMatchPathDetector\\n          id: NewComponent1\\n          learn_mode: True\\n        - type: TimestampsUnsortedDetector')
        self.assertEqual(new_live_config, c.decode("unicode-escape"))

        response = self.client.post(ANALYSIS_COMPONENT_PATH + atom_handler, json={
            "class_name": class_name, "parameters": parameters, "component_name": component_name})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.post(ANALYSIS_COMPONENT_PATH + atom_handler, json={
            "class_name": class_name, "parameters": parameters, "component_name": component_name}, headers={
            "Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        atom_handler = "UnknownAtomFilter"
        response = self.client.post(ANALYSIS_COMPONENT_PATH + atom_handler, json={
            "class_name": class_name, "parameters": parameters, "component_name": component_name}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"atom_handler \'{atom_handler}\' does not exist!"}}'.encode())

        atom_handler = "AtomFilter"
        response = self.client.post(ANALYSIS_COMPONENT_PATH + atom_handler, json={
            "class_name": class_name, "parameters": parameters, "component_name": component_name}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"component with same name already registered! ({component_name})"}}'.encode())

    def test8get_current_config(self):
        """This test case checks if the get_current_config method is working
        and if the authorization works as well."""
        response = self.client.get("/", headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.get("/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.get("/", headers={"Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")
