#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

try:
    import indigo
except ImportError:
    print "Attachments can only be used from within Indigo"
    raise ImportError

import sys
import time
import os
import base64
import logging
import requests
import re
from datetime import datetime
from dateutil.parser import parse

from ghpu import GitHubPluginUpdater

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse, parse_qs

########################################

def updateVar(name, value, folder):
    if name not in indigo.variables:
        return indigo.variable.create(name, value=value, folder=folder)
    else:
        return indigo.variable.updateValue(name, value)

########################################
class MyHTTPServer(HTTPServer):

    def setKey(self, authKey):
        self.authKey = authKey


class AuthHandler(BaseHTTPRequestHandler):

    def do_POST(self):

        # ifttt doesn't send consistent date strings. seriously?
        date_re = re.compile('^(Jan(uary)?|Feb(ruary)?|Mar(ch)?|Apr(il)?|May|Jun(e)?|Jul(y)?|Aug(ust)?|Sep(tember)?|Oct(ober)?|Nov(ember)?|Dec(ember)?)\s+[0-9]{1,2},?\s+[0-9]{2,4}')

        self.logger = logging.getLogger("Plugin.AuthHandler")
        client_host, client_port = self.client_address
        self.logger.debug("AuthHandler: POST from %s:%s to %s" % (str(client_host), str(client_port), self.path))

        post_data = self.rfile.read(int(self.headers.getheader('Content-Length')))

        # self.logger.debug(u"Header dump: \"%s\"" % self.headers)

        self.logger.debug(u"AuthHandler: POST raw data received: \"%s\"" % post_data)

        request = urlparse(self.path)

        if request.path.startswith('/ifttt'):
            self.logger.info(u"Received HTTP POST from %s" % str(client_host))
            if len(request.path) > 8:
                var_prefix = request.path[7:] + "_"
                # self.logger.debug(u"Prefix: %s" % var_prefix)
            else:
                var_prefix = ""
            query = parse_qs(post_data)
            for k in query:
                # TODO: smarten this up to accept an integer so we can use variable id
                # if re.match('^[0-9]', k):
                #     # this is a variable id
                #     pass
                the_key = str(k.strip())
                var_name = (var_prefix + re.sub('[^a-zA-Z0-9_-]', '_', the_key)).lower()
                var_value = str(query[k][-1].strip())
                if date_re.match(var_value):
                    # TODO: make this a toggleable option?
                    try:
                        # this could be a date/time string?
                        parse_attempt = parse(var_value)
                        date_string = parse_attempt.strftime('%Y-%m-%d %H:%M:%S')
                        self.logger.debug(u"Converting time string for variable \"%s\": \"%s\" -> \"%s\"" % (var_name, var_value, date_string))
                        var_value = date_string
                    except ValueError as e:
                        self.logger.debug(u"Received unparseable time string for variable \"%s\": \"%s\"" % (var_name, var_value))
                        pass

                self.logger.info(u"Updating variable \"%s\" with \"%s\"" % (var_name, var_value))
                updateVar(var_name, var_value, indigo.activePlugin.pluginPrefs["folderId"])
                if var_prefix is not "":
                    # TODO: make this optional somehow
                    post_key_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    updateVar(var_prefix + "updated", post_key_time, indigo.activePlugin.pluginPrefs["folderId"])
        else:
            # TODO: 404 error?
            pass

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()


    def do_GET(self):
        self.logger = logging.getLogger("Plugin.AuthHandler")
        client_host, client_port = self.client_address
        self.logger.debug("AuthHandler: GET from %s:%s for %s" % (str(client_host), str(client_port), self.path))

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        auth_header = self.headers.getheader('Authorization')

        if auth_header == None:
            self.logger.debug("AuthHandler: Request has no Authorization header")
            self.wfile.write("<html>\n<head><title>Indigo HTTPd Plugin</title></head>\n<body>")
            self.wfile.write("\n<p>Basic Authentication Required</p>")
            self.wfile.write("\n</body>\n</html>\n")

        elif auth_header == ('Basic ' + self.server.authKey):
            self.logger.debug(u"AuthHandler: Request has correct Authorization header")
            self.wfile.write("<html>\n<head><title>Indigo HTTPd Plugin</title></head>\n<body>")
            request = urlparse(self.path)

            if request.path == "/setvar":
                query = parse_qs(request.query)
                for key in query:
                    self.logger.debug(u"AuthHandler: setting variable httpd_%s to %s" % (key, query[key][0]))
                    updateVar("httpd_"+key, query[key][0], indigo.activePlugin.pluginPrefs["folderId"])
                    self.wfile.write("\n<p>Updated variable %s</p>" % key)

                indigo.activePlugin.triggerCheck()

            else:
                self.logger.debug(u"AuthHandler: Unknown request: %s" % self.request)

            self.wfile.write("\n</body>\n</html>\n")

        else:
            self.logger.debug(u"AuthHandler: Request with invalid Authorization header")
            self.wfile.write("<html>\n<head><title>Indigo HTTPd Plugin</title></head>\n<body>")
            self.wfile.write("\n<p>Invalid Authentication</p>")
            self.wfile.write("\n</body>\n</html>\n")



class Plugin(indigo.PluginBase):

    ########################################
    # Main Plugin methods
    ########################################
    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(msg)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)

        try:
            self.logLevel = int(self.pluginPrefs[u"logLevel"])
        except:
            self.logLevel = logging.INFO
        self.indigo_log_handler.setLevel(self.logLevel)
        self.logger.debug(u"logLevel = " + str(self.logLevel))

        # initialize vars
        self.updater = None
        self.updateFrequency= None
        self.next_update_check = None

        self.authKey = None
        self.port = None
        self.my_ip = None
        self.ifttturl = None


    def startup(self):
        indigo.server.log(u"Starting HTTPd")

        self.updater = GitHubPluginUpdater(self)
        self.updateFrequency = float(self.pluginPrefs.get('updateFrequency', '24')) * 60.0 * 60.0
        self.next_update_check = time.time()

        user = self.pluginPrefs.get('httpUser', 'username')
        password = self.pluginPrefs.get('httpPassword', 'password')

        self.authKey = base64.b64encode(user + ":" + password)

        self.port = int(self.pluginPrefs.get('httpPort', '43888'))
        self.my_ip = self.discoverMyIp()
        if self.my_ip:
            self.ifttturl = 'http://' + self.my_ip + ':' + str(self.port) + '/ifttt'

            ipaddr = indigo.Dict()
            ipaddr["address"] = str(self.my_ip)
            ipaddr["lastcheck"] = int(time.time())
            ipaddr["url"] = self.ifttturl
            self.pluginPrefs["ipaddr"] = ipaddr

        else:
            self.ifttturl = 'unknown'

        self.logger.debug(u"IFTTT URL should be: %s" % self.ifttturl)

        if "IFTTT" in indigo.variables.folders:
            myFolder = indigo.variables.folders["IFTTT"]
        else:
            myFolder = indigo.variables.folder.create("IFTTT")
        self.pluginPrefs["folderId"] = myFolder.id

        self.triggers = {}

        self.logger.debug(u"Starting HTTP server on port %d" % self.port)
        try:
            self.httpd = MyHTTPServer(("", self.port), AuthHandler)
        except:
            self.logger.error(u"Unable to open port %d for HHTTP Server" % self.port)
            self.httpd = None
        else:
            self.httpd.timeout = 1.0
            self.httpd.setKey(self.authKey)



    def shutdown(self):
        indigo.server.log(u"Shutting down HTTPd")


    def runConcurrentThread(self):

        try:
            while True:

                self.httpd.handle_request()

                if (self.updateFrequency > 0.0) and (time.time() > self.next_update_check):
                    self.next_update_check = time.time() + self.updateFrequency
                    self.updater.checkForUpdate()

                self.sleep(0.1)

        except self.StopThread:
            pass


    ####################

    def triggerStartProcessing(self, trigger):
        self.logger.debug("Adding Trigger %s (%d) - %s" % (trigger.name, trigger.id, trigger.pluginTypeId))
        assert trigger.id not in self.triggers
        self.triggers[trigger.id] = trigger

    def triggerStopProcessing(self, trigger):
        self.logger.debug("Removing Trigger %s (%d)" % (trigger.name, trigger.id))
        assert trigger.id in self.triggers
        del self.triggers[trigger.id]

    def triggerCheck(self):
        for triggerId, trigger in sorted(self.triggers.iteritems()):
            self.logger.debug("Checking Trigger %s (%s), Type: %s" % (trigger.name, trigger.id, trigger.pluginTypeId))
            if trigger.pluginTypeId == 'requestReceived':
                indigo.trigger.execute(trigger)


    ####################
    def validatePrefsConfigUi(self, valuesDict):
        # TODO: validate everything passed in. :P
        self.logger.debug(u"validatePrefsConfigUi called")
        errorDict = indigo.Dict()

        updateFrequency = int(valuesDict['updateFrequency'])
        if (updateFrequency < 0) or (updateFrequency > 24):
            errorDict['updateFrequency'] = u"Update frequency is invalid - enter a valid number (between 0 and 24)"

        httpPort = int(valuesDict['httpPort'])
        if httpPort < 1024:
            # TODO: check to see if this port is actually available by trying to bind to it
            errorDict['httpPort'] = u"HTTP Port Number invalid - enter a number between 1024 and 65535"

        if len(errorDict) > 0:
            return (False, valuesDict, errorDict)
        return (True, valuesDict)

    ########################################
    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        if not userCancelled:
            try:
                self.logLevel = int(valuesDict[u"logLevel"])
            except:
                self.logLevel = logging.INFO
            self.indigo_log_handler.setLevel(self.logLevel)
            self.logger.debug(u"logLevel = " + str(self.logLevel))

            self.updateFrequency = float(self.pluginPrefs.get('updateFrequency', "24")) * 60.0 * 60.0
            self.logger.debug(u"updateFrequency = " + str(self.updateFrequency))
            self.next_update_check = time.time()

    def discoverMyIp(self):
        self.logger.debug(u"Attempting to discover my external IP address...")
        try:
            req = requests.get("http://checkip.dyndns.com", timeout=30.0)
        except requests.exceptions.RequestException as e:
            self.logger.error(u"Unable to discover external IP address by polling http://checkip.dyndns.com/")
            return None

        ipv4_address = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
        ipv4 = ipv4_address.search(req.text)
        if not ipv4:
            ipv6_address = re.compile(
                    '(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)')
            ipv6 = ipv6_address.search(req.text)
            if ipv6:
                ip = "[" + ipv6.group() + "]"
            else:
                # uh oh.
                ip = None
        else:
            ip = ipv4.group()

        if ip:
            self.logger.debug(u"Discovered IP address: %s" % ip)
        else:
            self.logger.debug(u"Unable to discover IP address.")
        return ip

    def validateDeviceConfigUi(self, values, type_id, device_id):
        # TODO: validate everything coming in
        self.logger.debug(u"Entering validateDeviceConfigUi: typeId: %s  devId: %s" % (type_id, str(device_id)))
        errors_dict = indigo.Dict()
        errors_dict['showAlertText'] = ""
        if type_id == "iftttSender":
            # TODO: create this address from the URL in the main config
            values['address'] = "kjahsdkashdkjh/" + values['iftttEventName']

        return True, values

    def deviceStartComm(self, device):
        self.logger.debug(u"Entering deviceStartComm")
        device.stateListOrDisplayStateIdChanged()
        device.updateStateOnServer('status', value='initializing', clearErrorState=True)
        device.updateStateOnServer('status', value='available', clearErrorState=True)
        device.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)
        return True

    def deviceStopComm(self, device):
        self.logger.debug(u"Entering deviceStopComm")
        device.updateStateOnServer('status', value='disabled', clearErrorState=True)
        device.updateStateImageOnServer(indigo.kStateImageSel.Error)
        return True

    def didDeviceCommPropertyChange(self, orig_device, new_device):
        # self.logger.debug(u"Entering didDeviceCommPropertyChange")
        return False

    def deviceUpdate(self, orig_device, new_device):
        self.logger.debug(u"Entering deviceUpdated")
        return True

    def deviceDeleted(self, device):
        self.logger.debug(u"Entering deviceDeleted")
        return True



    ########################################
    # Menu Methods
    ########################################

    def checkForUpdates(self):
        self.updater.checkForUpdate()

    def updatePlugin(self):
        self.updater.update()

    def forceUpdate(self):
        self.updater.update(currentVersion='0.0.0')

