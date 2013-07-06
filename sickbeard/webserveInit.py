# Author: Nic Wolfe <nic@wolfeden.ca>
# URL: http://code.google.com/p/sickbeard/
#
# This file is part of Sick Beard.
#
# Sick Beard is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sick Beard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sick Beard.  If not, see <http://www.gnu.org/licenses/>.

import cherrypy.lib.auth_basic
import os.path

import sickbeard

from sickbeard import logger
from sickbeard.webserve import WebInterface

from sickbeard.helpers import create_https_certificates

import struct, socket

def initWebServer(options={}):
    options.setdefault('port', 8081)
    options.setdefault('host', '0.0.0.0')
    options.setdefault('log_dir', None)
    options.setdefault('username', '')
    options.setdefault('password', '')
    options.setdefault('web_root', '/')
    options.setdefault('whitelist',   '')
    assert isinstance(options['port'], int)
    assert 'data_root' in options

    def http_error_401_hander(status, message, traceback, version):
        """ Custom handler for 401 error """
        if status != "401 Unauthorized":
            logger.log(u"CherryPy caught an error: %s %s" % (status, message), logger.ERROR)
            logger.log(traceback, logger.DEBUG)
        return r'''<!DOCTYPE html>
<html>
    <head>
        <title>%s</title>
    </head>
    <body>
        <br/>
        <font color="#0000FF">Error %s: You need to provide a valid username and password.</font>
    </body>
</html>
''' % ('Access denied', status)

    def http_error_404_hander(status, message, traceback, version):
        """ Custom handler for 404 error, redirect back to main page """
        return r'''<!DOCTYPE html>
<html>
    <head>
        <title>404</title>
        <script type="text/javascript" charset="utf-8">
          <!--
          location.href = "%s/home/"
          //-->
        </script>
    </head>
    <body>
        <br/>
    </body>
</html>
''' % options['web_root']

    # cherrypy setup
    enable_https = options['enable_https']
    https_cert = options['https_cert']
    https_key = options['https_key']

    if enable_https:
        # If either the HTTPS certificate or key do not exist, make some self-signed ones.
        if not (https_cert and os.path.exists(https_cert)) or not (https_key and os.path.exists(https_key)):
            if not create_https_certificates(https_cert, https_key):
                logger.log(u"Unable to create CERT/KEY files, disabling HTTPS")
                sickbeard.ENABLE_HTTPS = False
                enable_https = False

<<<<<<< HEAD
        if not (os.path.exists(https_cert) and os.path.exists(https_key)):
            logger.log(u"Disabled HTTPS because of missing CERT and KEY files", logger.WARNING)
            sickbeard.ENABLE_HTTPS = False
            enable_https = False

    mime_gzip = ('text/html',
                 'text/plain',
                 'text/css',
                 'text/javascript',
                 'application/javascript',
                 'text/x-javascript',
                 'application/x-javascript',
                 'text/x-json',
                 'application/json'
                 )

    options_dict = {
        'server.socket_port': options['port'],
        'server.socket_host': options['host'],
        'log.screen': False,
        'engine.autoreload.on': False,
        'engine.autoreload.frequency': 100,
        'engine.reexec_retry': 100,
        'tools.gzip.on': True,
        'tools.gzip.mime_types': mime_gzip,
        'error_page.401': http_error_401_hander,
        'error_page.404': http_error_404_hander,
    }

    if enable_https:
        options_dict['server.ssl_certificate'] = https_cert
        options_dict['server.ssl_private_key'] = https_key
        protocol = "https"
    else:
        protocol = "http"

    logger.log(u"Starting Sick Beard on " + protocol + "://" + str(options['host']) + ":" + str(options['port']) + "/")
    cherrypy.config.update(options_dict)

    # setup cherrypy logging
    if options['log_dir'] and os.path.isdir(options['log_dir']):
        cherrypy.config.update({ 'log.access_file': os.path.join(options['log_dir'], "cherrypy.log") })
        logger.log(u'Using %s for cherrypy log' % cherrypy.config['log.access_file'])

    conf = {
        '/': {
            'tools.staticdir.root': options['data_root'],
            'tools.encode.on': True,
            'tools.encode.encoding': 'utf-8',
        },
        '/images': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'images'
        },
        '/js': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'js'
        },
        '/css': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'css'
        },
    }
    app = cherrypy.tree.mount(WebInterface(), options['web_root'], conf)

    def addressInNetwork(ip,net):
        """Is an address in a network. 
           Returns: 
              True - If 'ip' is an address in 'net' which is a string in the format x.x.x.x/y
              False - If 'ip' not in 'net' or if there is an error."""
        
        if net == "":
            return False
        
        try:
            ipaddr = struct.unpack('>L',socket.inet_aton(ip))[0]
            netaddr,bits = net.split('/')
            ipnet = struct.unpack('>L',socket.inet_aton(netaddr))[0]
            mask = ((2L<<(int(bits))-1) - 1)<<(32-int(bits))

            return ipaddr & mask == ipnet & mask
        except ValueError: # Will get here if whitelist is incorrectly formatted
            logger.log(u'Configuration Error: \'whitelist\' option is malformed. Value: %s, assuming no whitelisted hosts until restart.' % net, logger.ERROR )
            options['whitelist'] = ""
            
            return False

    def check_ip():
            """Will check current request address against 'whitelist' and will disable authentication with those that match. 'whitelist' is a list in the form of 'a.a.a.a/b[,c.c.c.c/d]'"""
            try:
                # Iterate through whitelisted networks
                for whitelist_network in options['whitelist'].split(','): 
                    # Check if current network matches remote address
                    if addressInNetwork(cherrypy.request.remote.ip, whitelist_network.strip()):

                        # Search for and remove basic_auth hook from list of hooks to execute
                        old_hooks = cherrypy.request.hooks['before_handler']
                        new_hooks = []
                        for hook in old_hooks:
                            if hook.callback != cherrypy.lib.auth_basic.basic_auth:
                                new_hooks.append(hook)

                        cherrypy.request.hooks['before_handler'] = new_hooks

                        # No need to continue checking if already matched once
                        return True 
            except Exception:
                logger.log(u'webserverInit.py:check_ip() - Error while processing whitelist. whitelist = %s' % options['whitelist'], logger.ERROR)

            return True

    if options['whitelist'] != "":
            checkipaddress = cherrypy.Tool('on_start_resource', check_ip, 1)
            cherrypy.tools.checkipaddress = checkipaddress

            app.merge({'/': { 'tools.checkipaddress.on': True } })
                
    # auth
    if options['username'] != "" and options['password'] != "":
        checkpassword = cherrypy.lib.auth_basic.checkpassword_dict({options['username']: options['password']})
        app.merge({
            '/': {
                'tools.auth_basic.on': True,
                'tools.auth_basic.realm': 'SickBeard',
                'tools.auth_basic.checkpassword': checkpassword
            },
            '/api': {
                'tools.auth_basic.on': False
            },
            '/api/builder': {
                'tools.auth_basic.on': True,
                'tools.auth_basic.realm': 'SickBeard',
                'tools.auth_basic.checkpassword': checkpassword
            }
        })

    cherrypy.server.start()
    cherrypy.server.wait()
