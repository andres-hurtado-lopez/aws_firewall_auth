#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2
import json
import subprocess
import sys
import re

print "=============================================================="
print "|      Proceso de actualizacion de Firewall Servidores AWS   |"
print "=============================================================="
print
print "=== Obteniendo la direccion ip actual ==="
s = subprocess.check_output(["curl", "--silent", "http://whatsmyip.com"])
p = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
ips = p.findall(s)

if len(ips) < 1:
    print "No se pudo determinar la direccion IP usando http://whatsmyip.com"
    sys.exit()

print "Direccion IP obtenida: " + ips[0]

actual_ip = ips[0]

locations = json.load(open('config.json'))

for location in locations:
    #conectarse con la region AWS
    conn = boto.ec2.connect_to_region(location["region"],
                                      aws_access_key_id=location["aws_access_key_id"],
                                      aws_secret_access_key=location["aws_secret_access_key"])

    #eliminar grupo de seguridad viejo
    conn.delete_security_group(name=location["secgroup"])

    #crear grupo de seguridad nuevo
    web = conn.create_security_group(location["secgroup"], location["secgroup"])
    web.authorize('tcp', 22, 22, actual_ip+'/32')
    web.authorize('tcp', 3906, 22, actual_ip+'/32')
