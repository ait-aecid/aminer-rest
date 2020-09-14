import unittest
from RemoteControlApi import ERR_RESOURCE_NOT_FOUND, ERR_CONFIG_PROPERTY_NOT_EXISTING, ERR_HEADER_NOT_IMPLEMENTED, app
from fastapi.testclient import TestClient


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
        self.assertEqual(response.content, b'{"detail":"%s"}' % b"the value of the property '%s' must be of type %s!\\n" % (
            property_name.encode('utf-8'), str(type(1000)).encode('utf-8')))

        property_name = 'AMinerUser'
        response = self.client.put('config_property/%s' % property_name, json={"value": "new_aminer"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(self.client.get('config_property/%s' % property_name).content, b'{"%s":"aminer"}' % property_name.encode('utf-8'))
        self.assertEqual(response.content, b'{"detail":"%s"}' % b'property %s could not be changed. Please check the '
                                                                b'propertyName again.\\n' % property_name.encode('utf-8'))

        property_name = 'LogResourceList'
        response = self.client.put('config_property/%s' % property_name, json={"value": ["file:///tmp/syslog.txt"]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers['content-type'], 'application/json')
        self.assertEqual(self.client.get('config_property/%s' % property_name).content, b'{"%s":["file:///tmp/syslog"]}' %
                                                                                        property_name.encode('utf-8'))
        self.assertEqual(response.content, b'{"detail":"%s"}' % b"the property '%s' can only be changed at startup in the AMiner root "
                                                                b"process!\\n" % property_name.encode('utf-8'))

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