import unittest
from RemoteControlApi import ERR_RESOURCE_NOT_FOUND, ERR_CONFIG_PROPERTY_NOT_EXISTING, ERR_HEADER_NOT_IMPLEMENTED, DESTINATION_FILE, \
    ANALYSIS_COMPONENT_PATH, app
from fastapi.testclient import TestClient
import os


class RemoteControlApiTest(unittest.TestCase):
    """This class tests the REST RemoteControlApi. The start of an AMiner instance and of the RemoteControlApi is not the task of this class
    and must be done beforehand."""
    client = TestClient(app)

    def test1get_config_property(self):
        property_name = 'MailAlerting.MaxEventsPerMessage'
        response = self.client.get('config_property/%s' % property_name)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"%s":1000}' % property_name.encode('utf-8'))

        property_name = 'AMinerUser'
        response = self.client.get('config_property/%s' % property_name)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"%s":"aminer"}' % property_name.encode('utf-8'))

        property_name = 'LogResourceList'
        response = self.client.get('config_property/%s' % property_name)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"%s":["file:///tmp/syslog"]}' % property_name.encode('utf-8'))

        property_name = 'NoneExistentConfigProperty'
        response = self.client.get('config_property/%s' % property_name)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"ErrorMessage":%s}' % ERR_RESOURCE_NOT_FOUND.replace(
            b'\\\\', b'\\') % property_name.encode('utf-8'))

    def test2put_config_property(self):
        property_name = 'MailAlerting.MaxEventsPerMessage'
        response = self.client.put('config_property/%s' % property_name, json={"value": 2})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(self.client.get('config_property/%s' % property_name).content, b'{"%s":2}' % property_name.encode('utf-8'))
        self.assertEqual(response.content, b'null')
        # reset value
        self.client.put('config_property/%s' % property_name, json={"value": 1000})

        property_name = 'MailAlerting.MaxEventsPerMessage'
        response = self.client.put('config_property/%s' % property_name, json={"value": "2"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(self.client.get('config_property/%s' % property_name).content, b'{"%s":1000}' % property_name.encode('utf-8'))
        self.assertEqual(response.content, b'{"detail":"%s"}' % b"the value of the property '%s' must be of type %s!" % (
            property_name.encode('utf-8'), str(type(1000)).encode('utf-8')))

        property_name = 'AMinerUser'
        response = self.client.put('config_property/%s' % property_name, json={"value": "new_aminer"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(self.client.get('config_property/%s' % property_name).content, b'{"%s":"aminer"}' % property_name.encode('utf-8'))
        self.assertEqual(response.content, b'{"detail":"%s"}' % b'property %s could not be changed. Please check the '
                                                                b'propertyName again.' % property_name.encode('utf-8'))

        property_name = 'LogResourceList'
        response = self.client.put('config_property/%s' % property_name, json={"value": ["file:///tmp/syslog.txt"]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(self.client.get('config_property/%s' % property_name).content, b'{"%s":["file:///tmp/syslog"]}' %
                                                                                        property_name.encode('utf-8'))
        self.assertEqual(response.content, b'{"detail":"%s"}' % b"the property '%s' can only be changed at startup in the AMiner root "
                                                                b"process!" % property_name.encode('utf-8'))

        property_name = 'NoneExistentConfigProperty'
        response = self.client.put('config_property/%s' % property_name, json={"value": "some string"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"%s"}' % ERR_CONFIG_PROPERTY_NOT_EXISTING.encode("utf-8"))

        property_name = 'LogResourceList'
        response = self.client.put('config_property/%s' % property_name, json={"value": ["file:///tmp/syslog.txt"]},
                                   headers={"content-md5": "md5 string"})
        self.assertEqual(response.status_code, 501)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"%s"}' % ERR_HEADER_NOT_IMPLEMENTED.encode("utf-8") % b"content-md5")

    def test3get_attribute_of_registered_component(self):
        component_name = 'NewMatchPathValueCombo'
        attribute_name = 'target_path_list'
        response = self.client.get('attribute/%s/%s' % (component_name, attribute_name))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"%s.%s":["/model/IPAddresses/Username","/model/IPAddresses/IP"]}' % (
            component_name.encode('utf-8'), attribute_name.encode('utf-8')))

        component_name = 'NewMatchPathValueComboDetector'
        attribute_name = 'target_path_list'
        response = self.client.get('attribute/%s/%s' % (component_name, attribute_name))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"%s"}' % b"the component '%s' does not exist." % component_name.encode('utf-8'))

        component_name = 'NewMatchPathValueCombo'
        attribute_name = 'not_existing_attribute'
        response = self.client.get('attribute/%s/%s' % (component_name, attribute_name))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"%s"}' % b"the component '%s' does not have an attribute named '%s'." % (
            component_name.encode('utf-8'), attribute_name.encode('utf-8')))

        component_name = 'NewMatchPathValueCombo'
        attribute_name = 'auto_include_flag'
        response = self.client.get('attribute/%s/%s' % (component_name, attribute_name))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"%s.%s":false}' % (component_name.encode('utf-8'), attribute_name.encode('utf-8')))

    def test4put_attribute_of_registered_component(self):
        component_name = 'NewMatchPathValueCombo'
        attribute_name = 'auto_include_flag'
        response = self.client.put('attribute/%s/%s' % (component_name, attribute_name), json={"value": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(self.client.get('attribute/%s/%s' % (component_name, attribute_name)).content, b'{"%s.%s":true}' % (
            component_name.encode('utf-8'), attribute_name.encode('utf-8')))
        self.assertEqual(response.content, b'null')
        # reset value
        self.client.put('attribute/%s/%s' % (component_name, attribute_name), json={"value": False})

        component_name = 'NewMatchPathValueCombo'
        attribute_name = 'auto_include_flag'
        response = self.client.put('attribute/%s/%s' % (component_name, attribute_name), json={"value": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(self.client.get('attribute/%s/%s' % (component_name, attribute_name)).content,
                         b'{"%s.%s":false}' % (component_name.encode('utf-8'), attribute_name.encode('utf-8')))
        self.assertEqual(response.content, b'{"detail":"%s"}' % b"property '%s.%s' must be of type %s!" % (
            component_name.encode('utf-8'), attribute_name.encode('utf-8'), str(type(True)).encode('utf-8')))

        component_name = 'NewMatchPathValueComboDetector'
        attribute_name = 'auto_include_flag'
        response = self.client.put('attribute/%s/%s' % (component_name, attribute_name), json={"value": True})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"%s"}' % b"the component '%s' does not exist." % component_name.encode('utf-8'))

        component_name = 'NewMatchPathValueCombo'
        attribute_name = 'not_existing_attribute'
        response = self.client.get('attribute/%s/%s' % (component_name, attribute_name))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"%s"}' % b"the component '%s' does not have an attribute named '%s'." % (
            component_name.encode('utf-8'), attribute_name.encode('utf-8')))

        component_name = 'NewMatchPathValueCombo'
        attribute_name = 'auto_include_flag'
        response = self.client.put('attribute/%s/%s' % (component_name, attribute_name), json={"value": True},
                                   headers={"content-md5": "md5 string"})
        self.assertEqual(response.status_code, 501)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"%s"}' % ERR_HEADER_NOT_IMPLEMENTED.encode("utf-8") % b"content-md5")

    def test5save_config(self):
        response = self.client.get('save_config')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.headers['location'], DESTINATION_FILE)
        self.assertEqual(response.content, b'null')
        os.remove(DESTINATION_FILE)

    def test6rename_registered_analysis_component(self):
        old_component_name = 'NewMatchPathValueCombo'
        new_component_name = 'NewMatchPathValueComboDetector'
        response = self.client.put(ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (
            old_component_name, new_component_name))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'null')
        # reset value
        self.client.put(ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (new_component_name, old_component_name))

        old_component_name = 'NotExistingComponent'
        new_component_name = 'NewMatchPathValueComboDetector'
        response = self.client.put(
            ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (old_component_name, new_component_name))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"%s"}' % b"the component '%s' does not exist." % old_component_name.encode('utf-8'))

        old_component_name = 'NewMatchPathValueCombo'
        new_component_name = 'NewMatchPathValueComboDetector'
        response = self.client.put(
            ANALYSIS_COMPONENT_PATH + "?old_component_name=%s&new_component_name=%s" % (old_component_name, new_component_name),
            headers={"content-md5": "md5 string"})
        self.assertEqual(response.status_code, 501)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"%s"}' % ERR_HEADER_NOT_IMPLEMENTED.encode("utf-8") % b"content-md5")

    def test7add_handler_to_atom_filter_and_register_analysis_component(self):
        """This test is problematic as there is no way to remove analysis components without restarting the AMiner."""
        atom_handler = "AtomFilter"
        class_name = "NewMatchPathDetector"
        parameters = ["analysis_context.aminer_config", "analysis_context.atomizer_factory.atom_handler_list", "auto_include_flag=True"]
        component_name = "NewComponent1"
        response = self.client.post(ANALYSIS_COMPONENT_PATH + atom_handler, json={
            "class_name": class_name, "parameters": parameters, "component_name": component_name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'null')

        atom_handler = "UnknownAtomFilter"
        class_name = "NewMatchPathDetector"
        parameters = ["analysis_context.aminer_config", "analysis_context.atomizer_factory.atom_handler_list", "auto_include_flag=True"]
        component_name = "NewComponent1"
        response = self.client.post(ANALYSIS_COMPONENT_PATH + atom_handler,
                                    json={"class_name": class_name, "parameters": parameters, "component_name": component_name})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"atom_handler \'%s\' does not exist!"}' % atom_handler.encode('utf-8'))

        atom_handler = "AtomFilter"
        class_name = "NewMatchPathDetector"
        parameters = ["analysis_context.aminer_config", "analysis_context.atomizer_factory.atom_handler_list", "auto_include_flag=True"]
        component_name = "NewComponent1"
        response = self.client.post(ANALYSIS_COMPONENT_PATH + atom_handler,
                                    json={"class_name": class_name, "parameters": parameters, "component_name": component_name})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(response.content, b'{"detail":"component with same name already registered! (%s)"}' %
                                           component_name.encode('utf-8'))
