import unittest
from RemoteControlApi import ERR_RESOURCE_NOT_FOUND, ERR_CONFIG_PROPERTY_NOT_EXISTING, ERR_HEADER_NOT_IMPLEMENTED, DESTINATION_FILE, \
    ANALYSIS_COMPONENT_PATH, app
from fastapi.testclient import TestClient
import os
import json


class RemoteControlApiTest(unittest.TestCase):
    """This class tests the REST RemoteControlApi. The start of an AMiner instance and of the RemoteControlApi is not the task of this class
    and must be done beforehand."""
    client = TestClient(app)
    access_token = None
    token_type = "Bearer"
    authorization_headers = None

    @classmethod
    def setUpClass(cls):
        response = cls.client.post("/token", data={
            "username": "johndoe", "password": "password",
            "client_secret": "49e36802e75fdc8d5915073c3b0ed97580be2b701a456e857c6df7a8706a33f9"})
        cls.access_token = json.loads(response.content)["access_token"]
        cls.authorization_headers = {"Authorization": "%s %s" % (cls.token_type, cls.access_token)}

    def test1get_config_property(self):
        property_name = "MailAlerting.MaxEventsPerMessage"
        response = self.client.get("config_property/%s" % property_name, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"{property_name}\":1000}}".encode())

        property_name = "AminerUser"
        response = self.client.get("config_property/%s" % property_name, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"{property_name}\":\"aminer\"}}".encode())

        property_name = "LogResourceList"
        response = self.client.get("config_property/%s" % property_name, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"{property_name}\":[\"file:///tmp/syslog\"]}}".encode())

        response = self.client.get("config_property/%s" % property_name)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.get("config_property/%s" % property_name, headers={
            "Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        property_name = "NonExistentConfigProperty"
        response = self.client.get("config_property/%s" % property_name, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"ErrorMessage\":{ERR_RESOURCE_NOT_FOUND.decode() % property_name}}}".encode())

    def test2put_config_property(self):
        property_name = "MailAlerting.MaxEventsPerMessage"
        response = self.client.put("config_property/%s" % property_name, json={"value": 2}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("config_property/%s" % property_name, headers=self.authorization_headers).content,
                         f"{{\"{property_name}\":2}}".encode())
        self.assertEqual(response.content, f"{{\"message\":\"Successfully changed config property {property_name} to {2}\"}}".encode())
        self.client.put("config_property/%s" % property_name, json={"value": 1000}, headers=self.authorization_headers)

        response = self.client.put("config_property/%s" % property_name, json={"value": 2})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.put("config_property/%s" % property_name, json={"value": 2}, headers={
            "Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.put("config_property/%s" % property_name, json={"value": "2"}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("config_property/%s" % property_name, headers=self.authorization_headers).content,
                         f"{{\"{property_name}\":1000}}".encode())
        self.assertEqual(response.content, f"{{\"detail\":\"the value of the property '{property_name}' must be of type {type(1000)}!\"}}".encode()
)

        property_name = "AminerUser"
        response = self.client.put("config_property/%s" % property_name, json={"value": "new_aminer"}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("config_property/%s" % property_name, headers=self.authorization_headers).content,
                         f"{{\"{property_name}\":\"aminer\"}}".encode())
        self.assertEqual(response.content, f"{{\"detail\":\"the property '{property_name}' can only be changed at startup in the aminer root process!\"}}".encode())

        property_name = "LogResourceList"
        response = self.client.put("config_property/%s" % property_name, json={"value": ["file:///tmp/syslog.txt"]},
                                   headers=self.authorization_headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("config_property/%s" % property_name, headers=self.authorization_headers).content,
                         f"{{\"{property_name}\":[\"file:///tmp/syslog\"]}}".encode())
        self.assertEqual(response.content, f"{{\"detail\":\"the property '{property_name}' can only be changed at startup in the aminer root process!\"}}".encode())

        property_name = "NoneExistentConfigProperty"
        response = self.client.put("config_property/%s" % property_name, json={"value": "some string"}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"{ERR_CONFIG_PROPERTY_NOT_EXISTING}"}}'.encode())

        property_name = "LogResourceList"
        response = self.client.put("config_property/%s" % property_name, json={"value": ["file:///tmp/syslog.txt"]},
                                   headers={"content-md5": "md5 string", **self.authorization_headers})
        self.assertEqual(response.status_code, 501)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f'{{"detail":"{ERR_HEADER_NOT_IMPLEMENTED % "content-md5"}"}}'.encode())

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
        component_name = "NewMatchPathValueCombo"
        attribute_name = "learn_mode"
        response = self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": True},
                                   headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.client.get("attribute/%s/%s" % (component_name, attribute_name), headers=self.authorization_headers).content,
                         f"{{\"{component_name}.{attribute_name}\":true}}".encode())
        self.assertEqual(response.content, f"{{\"message\":\"Successfully changed attribute {attribute_name} of registered analysis component {component_name} to True\"}}".encode())
        self.client.put("attribute/%s/%s" % (component_name, attribute_name), json={"value": False}, headers=self.authorization_headers)

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
        response = self.client.get("save_config", headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.headers["location"], DESTINATION_FILE)
        content = ""
        self.assertEqual(response.content, f"{{\"filename\": {DESTINATION_FILE}, \"content\": \"{content}\"}}".encode())
        os.remove(DESTINATION_FILE)

        response = self.client.get("save_config")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.get("save_config", headers={
            "Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

    def test6rename_registered_analysis_component(self):
        old_component_name = "NewMatchPathValueCombo"
        new_component_name = "NewMatchPathValueComboDetector"
        response = self.client.put(ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (
            old_component_name, new_component_name), headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"message\":\"Successfully renamed analysis component from {old_component_name} to {new_component_name}\"}}".encode())
        # reset value
        self.client.put(ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (
            new_component_name, old_component_name), headers=self.authorization_headers)

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
        """This test is problematic as there is no way to remove analysis components without restarting the AMiner."""
        atom_handler = "AtomFilter"
        class_name = "NewMatchPathDetector"
        parameters = ["analysis_context.aminer_config", "analysis_context.atomizer_factory.event_handler_list", "learn_mode=True"]
        component_name = "NewComponent1"
        response = self.client.post(ANALYSIS_COMPONENT_PATH + atom_handler, json={
            "class_name": class_name, "parameters": parameters, "component_name": component_name}, headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.content, f"{{\"message\":\"Successfully added new {class_name} with the name {component_name} to the atom filter {atom_handler}\"}}".encode())

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
        """This test case checks if the get_current_config method is working and if the authorization works as well."""
        response = self.client.get("/", headers=self.authorization_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.get("/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")

        response = self.client.get("/", headers={"Authorization": "%s %s" % (self.token_type, self.access_token + "failedtoken")})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["content-type"], "application/json")
