import unittest
from RemoteControlApi import ERR_RESOURCE_NOT_FOUND, app
from fastapi.testclient import TestClient


class RemoteControlApiTest(unittest.TestCase):
    """This class tests the REST RemoteControlApi. The start of an AMiner instance and of the RemoteControlApi is not the task of this class
    and must be done beforehand."""
    cmd = ['curl', '-i', '-H', "Accept: application/json", '-H', "Content-Type: application/json", '-X', 'GET']
    config_property_addr = 'http://127.0.0.1:8000/config_property/%s'
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
