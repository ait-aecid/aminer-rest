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
        content = 'from aminer.parsing.FirstMatchModelElement import FirstMatchModelElement\\nfrom aminer.parsing.SequenceModelElement import SequenceModelElement\\nfrom aminer.parsing.FixedDataModelElement import FixedDataModelElement\\nfrom aminer.parsing.DelimitedDataModelElement import DelimitedDataModelElement\\nfrom aminer.parsing.AnyByteDataModelElement import AnyByteDataModelElement\\nfrom aminer.parsing.FixedWordlistDataModelElement import FixedWordlistDataModelElement\\nfrom aminer.parsing.DecimalIntegerValueModelElement import DecimalIntegerValueModelElement\\nfrom aminer.parsing.DateTimeModelElement import DateTimeModelElement\\nfrom aminer.parsing.IpAddressDataModelElement import IpAddressDataModelElement\\nfrom aminer.parsing.OptionalMatchModelElement import OptionalMatchModelElement\\n\\n# This is a template for the \\"aminer\\" logfile miner tool. Copy\\n# it to \\"config.py\\" and define your ruleset.\\n\\nconfig_properties = {}\\n\\n# Define the list of log resources to read from: the resources\\n# named here do not need to exist when aminer is started. This\\n# will just result in a warning. However, if they exist, they have\\n# to be readable by the aminer process! Supported types are:\\n# * file://[path]: Read data from file, reopen it after rollover\\n# * unix://[path]: Open the path as UNIX local socket for reading\\nconfig_properties[\'LogResourceList\'] = [\'file:///tmp/syslog\']\\n\\n# Define the uid/gid of the process that runs the calculation\\n# after opening the log files:\\nconfig_properties[\'AminerUser\'] = \'aminer\'\\nconfig_properties[\'AminerGroup\'] = \'aminer\'\\n\\n# Define the path, where aminer will listen for incoming remote\\n# control connections. When missing, no remote control socket\\n# will be created.\\nconfig_properties[\'RemoteControlSocket\'] = \'/var/run/aminer-remote.socket\'\\n\\n# Read the analyis from this file. That part of configuration\\n# is separated from the main configuration so that it can be loaded\\n# only within the analysis child. Non-absolute path names are\\n# interpreted relatively to the main configuration file (this\\n# file). When empty, this configuration has to contain the configuration\\n# for the child also.\\n# config_properties[\'AnalysisConfigFile\'] = \'analysis.py\'\\n\\nconfig_properties[\'Core.LogDir\'] = \'/tmp/lib/aminer/log\'\\n# Read and store information to be used between multiple invocations\\n# of aminer in this directory. The directory must only be accessible\\n# to the \'AminerUser\' but not group/world readable. On violation,\\n# aminer will refuse to start. When undefined, \'/var/lib/aminer\'\\n# is used.\\nconfig_properties[\'Core.PersistenceDir\'] = \'/tmp/lib/aminer\'\\n\\n# Define a target e-mail address to send alerts to. When undefined,\\n# no e-mail notification hooks are added.\\nconfig_properties[\'MailAlerting.TargetAddress\'] = \'root@localhost\'\\n# Sender address of e-mail alerts. When undefined, \\"sendmail\\"\\n# implementation on host will decide, which sender address should\\n# be used.\\nconfig_properties[\'MailAlerting.FromAddress\'] = \'root@localhost\'\\n# Define, which text should be prepended to the standard aminer\\n# subject. Defaults to \\"aminer Alerts:\\"\\nconfig_properties[\'MailAlerting.SubjectPrefix\'] = \'aminer Alerts:\'\\n# Define a grace time after startup before aminer will react to\\n# an event and send the first alert e-mail. Defaults to 0 (any\\n# event can immediately trigger alerting).\\nconfig_properties[\'MailAlerting.AlertGraceTime\'] = 0\\n# Define how many seconds to wait after a first event triggered\\n# the alerting procedure before really sending out the e-mail.\\n# In that timespan, events are collected and will be sent all\\n# using a single e-mail. Defaults to 10 seconds.\\nconfig_properties[\'MailAlerting.EventCollectTime\'] = 0\\n# Define the minimum time between two alert e-mails in seconds\\n# to avoid spamming. All events during this timespan are collected\\n# and sent out with the next report. Defaults to 600 seconds.\\nconfig_properties[\'MailAlerting.MinAlertGap\'] = 0\\n# Define the maximum time between two alert e-mails in seconds.\\n# When undefined this defaults to \\"MailAlerting.MinAlertGap\\".\\n# Otherwise this will activate an exponential backoff to reduce\\n# messages during permanent error states by increasing the alert\\n# gap by 50% when more alert-worthy events were recorded while\\n# the previous gap time was not yet elapsed.\\nconfig_properties[\'MailAlerting.MaxAlertGap\'] = 600\\n# Define how many events should be included in one alert mail\\n# at most. This defaults to 1000\\nconfig_properties[\'MailAlerting.MaxEventsPerMessage\'] = 1000\\nconfig_properties[\'LogPrefix\'] = \'Original log line: \'\\n\\n# Add your ruleset here:\\n\\ndef build_analysis_pipeline(analysis_context):\\n    \\"\\"\\"Define the function to create pipeline for parsing the log data.\\n\\n    It has also to define an AtomizerFactory to instruct aminer how to\\n    process incoming data streams to create log atoms from them.\\n    \\"\\"\\"\\n    # Build the parsing model:\\n\\n    service_children_disk_report = [\\n        FixedDataModelElement(\'Space\', b\' Current Disk Data is: Filesystem     Type  Size  Used Avail Use%\'),\\n        DelimitedDataModelElement(\'Data\', b\'%\'), AnyByteDataModelElement(\'Rest\')]\\n\\n    service_children_login_details = [\\n        FixedDataModelElement(\'User\', b\'User \'), DelimitedDataModelElement(\'Username\', b\' \'),\\n        FixedWordlistDataModelElement(\'Status\', [b\' logged in\', b\' logged out\']),\\n        OptionalMatchModelElement(\'PastTime\', SequenceModelElement(\'Time\', [\\n            FixedDataModelElement(\'Blank\', b\' \'), DecimalIntegerValueModelElement(\'Minutes\'),\\n            FixedDataModelElement(\'Ago\', b\' minutes ago.\')]))]\\n\\n    service_children_cron_job = [\\n        DateTimeModelElement(\'DTM\', b\'%Y-%m-%d %H:%M:%S\'), FixedDataModelElement(\'UNameSpace1\', b\' \'),\\n        DelimitedDataModelElement(\'UName\', b\' \'), FixedDataModelElement(\'UNameSpace2\', b\' \'), DelimitedDataModelElement(\'User\', b\' \'),\\n        FixedDataModelElement(\'Cron\', b\' cron[\'), DecimalIntegerValueModelElement(\'JobNumber\'),\\n        FixedDataModelElement(\'Details\', b\']: Job `cron.daily` started.\')]\\n\\n    service_children_random_time = [FixedDataModelElement(\'Space\', b\'Random: \'), DecimalIntegerValueModelElement(\'Random\')]\\n\\n    service_children_sensors = [SequenceModelElement(\'CPUTemp\', [\\n        FixedDataModelElement(\'FixedTemp\', b\'CPU Temp: \'), DecimalIntegerValueModelElement(\'Temp\'),\\n        FixedDataModelElement(\'Degrees\', b\'\\\\xc2\\\\xb0C\')]), FixedDataModelElement(\'Space1\', b\', \'), SequenceModelElement(\'CPUWorkload\', [\\n            FixedDataModelElement(\'FixedWorkload\', b\'CPUWorkload: \'), DecimalIntegerValueModelElement(\'Workload\'),\\n            FixedDataModelElement(\'Percent\', b\'%\')]), FixedDataModelElement(\'Space2\', b\', \'),\\n        DateTimeModelElement(\'DTM\', b\'%Y-%m-%d %H:%M:%S\')]\\n\\n    service_children_user_ip_address = [\\n        FixedDataModelElement(\'User\', b\'User \'), DelimitedDataModelElement(\'Username\', b\' \'),\\n        FixedDataModelElement(\'Action\', b\' changed IP address to \'), IpAddressDataModelElement(\'IP\')]\\n\\n    service_children_cron_job_announcement = [\\n        DateTimeModelElement(\'DTM\', b\'%Y-%m-%d %H:%M:%S\'), FixedDataModelElement(\'Space\', b\' \'),\\n        DelimitedDataModelElement(\'UName\', b\' \'), FixedDataModelElement(\'Cron\', b\' cron[\'), DecimalIntegerValueModelElement(\'JobNumber\'),\\n        FixedDataModelElement(\'Run\', b\']: Will run job `\'),\\n        FixedWordlistDataModelElement(\'CronType\', [b\'cron.daily\', b\'cron.hourly\', b\'cron.monthly\', b\'cron.weekly\']),\\n        FixedDataModelElement(\'StartTime\', b\'\\\\\' in 5 min.\')]\\n\\n    service_children_cron_job_execution = [\\n        DateTimeModelElement(\'DTM\', b\'%Y-%m-%d %H:%M:%S\'), FixedDataModelElement(\'Space1\', b\' \'),\\n        DelimitedDataModelElement(\'UName\', b\' \'), FixedDataModelElement(\'Cron\', b\' cron[\'), DecimalIntegerValueModelElement(\'JobNumber\'),\\n        FixedDataModelElement(\'Job\', b\']: Job `\'),\\n        FixedWordlistDataModelElement(\'CronType\', [b\'cron.daily\', b\'cron.hourly\', b\'cron.monthly\', b\'cron.weekly\']),\\n        FixedDataModelElement(\'Started\', b\'\\\\\' started\')]\\n\\n    parsing_model = FirstMatchModelElement(\'model\', [\\n        SequenceModelElement(\'CronAnnouncement\', service_children_cron_job_announcement),\\n        SequenceModelElement(\'CronExecution\', service_children_cron_job_execution),\\n        SequenceModelElement(\'DailyCron\', service_children_cron_job), SequenceModelElement(\'DiskReport\', service_children_disk_report),\\n        SequenceModelElement(\'LoginDetails\', service_children_login_details), DecimalIntegerValueModelElement(\'Random\'),\\n        SequenceModelElement(\'RandomTime\', service_children_random_time), SequenceModelElement(\'Sensors\', service_children_sensors),\\n        SequenceModelElement(\'IPAddresses\', service_children_user_ip_address)])\\n\\n    # Some generic imports.\\n    from aminer.analysis import AtomFilters\\n\\n    # Create all global handler lists here and append the real handlers later on.\\n    # Use this filter to distribute all atoms to the analysis handlers.\\n    atom_filters = AtomFilters.SubhandlerFilter(None)\\n    analysis_context.register_component(atom_filters, component_name=\\"AtomFilter\\")\\n\\n    from aminer.analysis.TimestampCorrectionFilters import SimpleMonotonicTimestampAdjust\\n    simple_monotonic_timestamp_adjust = SimpleMonotonicTimestampAdjust([atom_filters])\\n    analysis_context.register_component(simple_monotonic_timestamp_adjust, component_name=\\"SimpleMonotonicTimestampAdjust\\")\\n\\n    from aminer.events.StreamPrinterEventHandler import StreamPrinterEventHandler\\n    stream_printer_event_handler = StreamPrinterEventHandler(analysis_context)\\n    from aminer.events.Utils import VolatileLogarithmicBackoffEventHistory\\n    volatile_logarithmic_backoff_event_history = VolatileLogarithmicBackoffEventHistory(100)\\n    anomaly_event_handlers = [stream_printer_event_handler, volatile_logarithmic_backoff_event_history]\\n    analysis_context.register_component(volatile_logarithmic_backoff_event_history, component_name=\\"VolatileLogarithmicBackoffEventHistory\\")\\n\\n    # Now define the AtomizerFactory using the model. A simple line based one is usually sufficient.\\n    from aminer.input.SimpleByteStreamLineAtomizerFactory import SimpleByteStreamLineAtomizerFactory\\n    analysis_context.atomizer_factory = SimpleByteStreamLineAtomizerFactory(\\n        parsing_model, [simple_monotonic_timestamp_adjust], anomaly_event_handlers, use_real_time=True)\\n\\n    # Just report all unparsed atoms to the event handlers.\\n    from aminer.analysis.UnparsedAtomHandlers import SimpleUnparsedAtomHandler\\n    simple_unparsed_atom_handler = SimpleUnparsedAtomHandler(anomaly_event_handlers)\\n    atom_filters.add_handler(simple_unparsed_atom_handler, stop_when_handled_flag=True)\\n    analysis_context.register_component(simple_unparsed_atom_handler, component_name=\\"UnparsedHandler\\")\\n\\n    from aminer.analysis.TimestampsUnsortedDetector import TimestampsUnsortedDetector\\n    timestamps_unsorted_detector = TimestampsUnsortedDetector(analysis_context.aminer_config, anomaly_event_handlers)\\n    atom_filters.add_handler(timestamps_unsorted_detector)\\n    analysis_context.register_component(timestamps_unsorted_detector, component_name=\\"TimestampsUnsortedDetector\\")\\n\\n    from aminer.analysis import Rules\\n    from aminer.analysis.AllowlistViolationDetector import AllowlistViolationDetector\\n    allowlist_rules = [\\n        Rules.OrMatchRule([\\n            Rules.AndMatchRule([\\n                Rules.PathExistsMatchRule(\'/model/LoginDetails/PastTime/Time/Minutes\'),\\n                Rules.NegationMatchRule(Rules.ValueMatchRule(\'/model/LoginDetails/Username\', b\'root\'))]),\\n            Rules.AndMatchRule([\\n                Rules.NegationMatchRule(Rules.PathExistsMatchRule(\'/model/LoginDetails/PastTime/Time/Minutes\')),\\n                Rules.PathExistsMatchRule(\'/model/LoginDetails\')]),\\n            Rules.NegationMatchRule(Rules.PathExistsMatchRule(\'/model/LoginDetails\'))])]\\n\\n    # This rule list should trigger, when the line does not look like: User root (logged in, logged out)\\n    # or User \'username\' (logged in, logged out) x minutes ago.\\n    allowlist_violation_detector = AllowlistViolationDetector(analysis_context.aminer_config, allowlist_rules, anomaly_event_handlers)\\n    analysis_context.register_component(allowlist_violation_detector, component_name=\\"Allowlist\\")\\n    atom_filters.add_handler(allowlist_violation_detector)\\n\\n    from aminer.analysis.ParserCount import ParserCount\\n    parser_count = ParserCount(analysis_context.aminer_config, None, anomaly_event_handlers, 10)\\n    analysis_context.register_component(parser_count, component_name=\\"ParserCount\\")\\n    atom_filters.add_handler(parser_count)\\n\\n    from aminer.analysis.EventCorrelationDetector import EventCorrelationDetector\\n    ecd = EventCorrelationDetector(analysis_context.aminer_config, anomaly_event_handlers, check_rules_flag=True,\\n                                   hypothesis_max_delta_time=1.0, learn_mode=True)\\n    analysis_context.register_component(ecd, component_name=\\"EventCorrelationDetector\\")\\n    atom_filters.add_handler(ecd)\\n\\n    from aminer.analysis.NewMatchPathDetector import NewMatchPathDetector\\n    new_match_path_detector = NewMatchPathDetector(analysis_context.aminer_config, anomaly_event_handlers, learn_mode=True)\\n    analysis_context.register_component(new_match_path_detector, component_name=\\"NewMatchPath\\")\\n    atom_filters.add_handler(new_match_path_detector)\\n\\n    def tuple_transformation_function(match_value_list):\\n        \\"\\"\\"Only allow output of the EnhancedNewMatchPathValueComboDetector\\n        after every 10000th element.\\"\\"\\"\\n        extra_data = enhanced_new_match_path_value_combo_detector.known_values_dict.get(tuple(match_value_list))\\n        if extra_data is not None:\\n            mod = 10000\\n            if (extra_data[2] + 1) % mod == 0:\\n                enhanced_new_match_path_value_combo_detector.learn_mode = False\\n            else:\\n                enhanced_new_match_path_value_combo_detector.learn_mode = True\\n        return match_value_list\\n\\n    from aminer.analysis.EnhancedNewMatchPathValueComboDetector import EnhancedNewMatchPathValueComboDetector\\n    enhanced_new_match_path_value_combo_detector = EnhancedNewMatchPathValueComboDetector(\\n        analysis_context.aminer_config, [\'/model/DailyCron/UName\', \'/model/DailyCron/JobNumber\'], anomaly_event_handlers,\\n        learn_mode=2, tuple_transformation_function=tuple_transformation_function)\\n    analysis_context.register_component(enhanced_new_match_path_value_combo_detector, component_name=\\"EnhancedNewValueCombo\\")\\n    atom_filters.add_handler(enhanced_new_match_path_value_combo_detector)\\n\\n    from aminer.analysis.HistogramAnalysis import HistogramAnalysis, LinearNumericBinDefinition, ModuloTimeBinDefinition, \\\\\\n        PathDependentHistogramAnalysis\\n    modulo_time_bin_definition = ModuloTimeBinDefinition(86400, 3600, 0, 1, 24, True)\\n    linear_numeric_bin_definition = LinearNumericBinDefinition(50, 5, 20, True)\\n    histogram_analysis = HistogramAnalysis(analysis_context.aminer_config, [\\n        (\'/model/RandomTime/Random\', modulo_time_bin_definition), (\'/model/Random\', linear_numeric_bin_definition)], 10,\\n        anomaly_event_handlers)\\n    analysis_context.register_component(histogram_analysis, component_name=\\"HistogramAnalysis\\")\\n    atom_filters.add_handler(histogram_analysis)\\n\\n    path_dependent_histogram_analysis = PathDependentHistogramAnalysis(analysis_context.aminer_config, \'/model/RandomTime\',\\n                                                                       modulo_time_bin_definition, 10, anomaly_event_handlers)\\n    analysis_context.register_component(path_dependent_histogram_analysis, component_name=\\"PathDependentHistogramAnalysis\\")\\n    atom_filters.add_handler(path_dependent_histogram_analysis)\\n\\n    from aminer.analysis.MatchValueAverageChangeDetector import MatchValueAverageChangeDetector\\n    match_value_average_change_detector = MatchValueAverageChangeDetector(analysis_context.aminer_config, anomaly_event_handlers, None,\\n                                                                          [\'/model/Random\'], 100, 10)\\n    analysis_context.register_component(match_value_average_change_detector, component_name=\\"MatchValueAverageChange\\")\\n    atom_filters.add_handler(match_value_average_change_detector)\\n\\n    import sys\\n    from aminer.analysis.MatchValueStreamWriter import MatchValueStreamWriter\\n    match_value_stream_writer = MatchValueStreamWriter(\\n        sys.stdout, [\'/model/Sensors/CPUTemp\', \'/model/Sensors/CPUWorkload\', \'/model/Sensors/DTM\'], b\';\', b\'\')\\n    analysis_context.register_component(match_value_stream_writer, component_name=\\"MatchValueStreamWriter\\")\\n    atom_filters.add_handler(match_value_stream_writer)\\n\\n    from aminer.analysis.NewMatchPathValueComboDetector import NewMatchPathValueComboDetector\\n    new_match_path_value_combo_detector = NewMatchPathValueComboDetector(analysis_context.aminer_config, [\\n        \'/model/IPAddresses/Username\', \'/model/IPAddresses/IP\'], anomaly_event_handlers, learn_mode=False)\\n    analysis_context.register_component(new_match_path_value_combo_detector, component_name=\\"NewMatchPathValueCombo\\")\\n    atom_filters.add_handler(new_match_path_value_combo_detector)\\n\\n    from aminer.analysis.NewMatchIdValueComboDetector import NewMatchIdValueComboDetector\\n    new_match_id_value_combo_detector = NewMatchIdValueComboDetector(\\n        analysis_context.aminer_config, [\'/model/type/path/id\', \'/model/type/syscall/id\'], anomaly_event_handlers,\\n        id_path_list=[\'/model/type/path/id\', \'/model/type/syscall/id\'], min_allowed_time_diff=5, learn_mode=True,\\n        allow_missing_values_flag=True, output_logline=True)\\n    analysis_context.register_component(new_match_id_value_combo_detector, component_name=\\"NewMatchIdValueComboDetector\\")\\n    atom_filters.add_handler(new_match_id_value_combo_detector)\\n\\n    from aminer.analysis.NewMatchPathValueDetector import NewMatchPathValueDetector\\n    new_match_path_value_detector = NewMatchPathValueDetector(analysis_context.aminer_config, [\\n        \'/model/DailyCron/Job Number\', \'/model/IPAddresses/Username\'], anomaly_event_handlers, learn_mode=False)\\n    analysis_context.register_component(new_match_path_value_detector, component_name=\\"NewMatchPathValue\\")\\n    atom_filters.add_handler(new_match_path_value_detector)\\n\\n    from aminer.analysis.MissingMatchPathValueDetector import MissingMatchPathValueDetector\\n    missing_match_path_value_detector = MissingMatchPathValueDetector(\\n        analysis_context.aminer_config, [\'/model/DiskReport/Space\'], anomaly_event_handlers, learn_mode=False, default_interval=2,\\n        realert_interval=5)\\n    analysis_context.register_component(missing_match_path_value_detector, component_name=\\"MissingMatch\\")\\n    atom_filters.add_handler(missing_match_path_value_detector)\\n\\n    from aminer.analysis.TimeCorrelationDetector import TimeCorrelationDetector\\n    time_correlation_detector = TimeCorrelationDetector(\\n        analysis_context.aminer_config, anomaly_event_handlers, 2, min_rule_attributes=1, max_rule_attributes=5,\\n        record_count_before_event=70000, output_logline=True)\\n    analysis_context.register_component(time_correlation_detector, component_name=\\"TimeCorrelationDetector\\")\\n    atom_filters.add_handler(time_correlation_detector)\\n\\n    from aminer.analysis.TimeCorrelationViolationDetector import TimeCorrelationViolationDetector, CorrelationRule, EventClassSelector\\n    cron_job_announcement = CorrelationRule(\'CronJobAnnouncement\', 5, 6, artefact_match_parameters=[\\n        (\'/model/CronAnnouncement/JobNumber\', \'/model/CronExecution/JobNumber\')])\\n    a_class_selector = EventClassSelector(\'Announcement\', [cron_job_announcement], None)\\n    b_class_selector = EventClassSelector(\'Execution\', None, [cron_job_announcement])\\n    rules = [Rules.PathExistsMatchRule(\'/model/CronAnnouncement/Run\', a_class_selector),\\n             Rules.PathExistsMatchRule(\'/model/CronExecution/Job\', b_class_selector)]\\n\\n    time_correlation_violation_detector = TimeCorrelationViolationDetector(analysis_context.aminer_config, rules, anomaly_event_handlers)\\n    analysis_context.register_component(time_correlation_violation_detector, component_name=\\"TimeCorrelationViolationDetector\\")\\n    atom_filters.add_handler(time_correlation_violation_detector)\\n\\n    from aminer.events.DefaultMailNotificationEventHandler import DefaultMailNotificationEventHandler\\n    if DefaultMailNotificationEventHandler.CONFIG_KEY_MAIL_TARGET_ADDRESS in analysis_context.aminer_config.config_properties:\\n        mail_notification_handler = DefaultMailNotificationEventHandler(analysis_context)\\n        analysis_context.register_component(mail_notification_handler, component_name=\\"MailHandler\\")\\n        anomaly_event_handlers.append(mail_notification_handler)\\n'
        self.assertEqual(response.content, f"{{\"filename\":\"{DESTINATION_FILE}\",\"content\":\"{content}\"}}".encode())
        os.remove(DESTINATION_FILE)
        response = self.client.get("/", headers=self.authorization_headers)
        print(response.content.decode('unicode_escape'))

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
