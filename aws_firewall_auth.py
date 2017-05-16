#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2
import boto.exception
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

    #listar los grupos de seguridad para obtener datos de las reglas que
    #van a ser revocadas
    groups = conn.get_all_security_groups()

    for group in groups:
        
        if group.name == location["secgroup"]:
            print "Procesando grupo={name} id_grupo={group_id}".format(name=group.name,group_id=group.id)
            print
            for rule in group.rules:
                try:
                    print "Eliminando regla {rule} con ip antigua".format(rule=repr(rule))

                    #eliminar grupo de seguridad viejo
                    rc_remove = rule.remove_rule(ip_protocol=rule.ip_protocol,
                                      from_port=rule.from_port,
                                      to_port=rule.to_port,
                                      src_group_name=group.name,
                                      src_group_owner_id=group.owner_id,
                                      cidr_ip=rule.grants,
                                      src_group_group_id=group.id)

                    print "Resultado eliminacion :"+repr(rc_remove)

                    #crear grupo de seguridad nuevo
                    print "Creando regla con ip nueva"
                    rc_add = rule.add_rule(ip_protocol=rule.ip_protocol,
                                   from_port=rule.from_port,
                                   to_port=rule.to_port,
                                   src_group_name=group.name,
                                   src_group_owner_id=group.owner_id,
                                   cidr_ip=actual_ip,
                                   src_group_group_id=group.id)

                    print "Resultado creacion :"+repr(rc_add)
                except boto.exception.EC2ResponseError, e:
                    print "Error modificando regla: nombre_grupo={name} id_grupo={group_id}. Error {e}".format(name=group.name,group_id=group.id, e=repr(e))
                


#Error modificando regla:EC2ResponseError: 400 Bad Request
#<?xml version="1.0" encoding="UTF-8"?>
#<Response><Errors><Error><Code>DependencyViolation</Code><Message>resource sg-9ce598e4 has a dependent object</Message></Error></Errors><RequestID>a92c83be-de2f-46b7-b4be-5c03b8872d57</RequestID></Response>
#> /home/pi/Projects/aws_firewall_auth/aws_firewall_auth.py(40)<module>()
#-

#Requisitos para el funcionamiento
#1. El usuario AWS asignado debe tener el rol AmazonEC2FullAccess para poder usar este script
#2. Debe estar instalado AWS CLI
#3. Debe estar instalado python 2.7x
#4. Acceso a el sitio http://whatsmyip.com
#
#import sys
#import re
#import subprocess
#import json
#import AWSCredentials
#
#print "=============================================================="
#print "|      Proceso de actualizacion de Firewall Servidores AWS   |"
#print "=============================================================="
#print
#print "=== Obteniendo la direccion ip actual ==="
#s = subprocess.check_output(["curl", "--silent", "http://whatsmyip.com"])
#p = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
#ips = p.findall(s)
#if len(ips) < 1:
#    print "No se pudo determinar la direccion IP usando http://whatsmyip.com"
#    sys.exit()
#
#print "Direccion IP obtenida: " + ips[0]
#
#for credentialEntry in AWSCredentials.locations:
#    print
#    print
#    print "=== Configurando Servicio AWS: %(name)s, en la region: %(region)s ===" % {'name': credentialEntry['name'], 'region': credentialEntry['region']}
#    print "Configurando aws-cli ..."
#    print
#    subprocess.check_output("aws configure set aws_access_key_id %(aws_access_key_id)s " % { 'aws_access_key_id':credentialEntry['aws_access_key_id'] })
#    subprocess.check_output("aws configure set aws_secret_access_key %(aws_secret_access_key)s " % { 'aws_secret_access_key':credentialEntry['aws_secret_access_key'] })
#    subprocess.check_output("aws configure set default.region %(region)s " % { 'region':credentialEntry['region'] })
#    subprocess.check_output("aws configure set default.output json ")
#
#    print "Descargando los accesos configurados actualmente para el grupo de seguridad %(secgroup)s ..." % {'secgroup' : credentialEntry['secgroup']}
#    print
#    try:
#        raw_json = subprocess.check_output("aws ec2 describe-security-groups --group-names %(secgroup)s --output json" % {'secgroup' : credentialEntry['secgroup'] } )
#        secgroup_entries = json.loads(raw_json)
#    except:
#        print "No es posible listar los accesos de seguridad anteriores para poder borrarlos"
#        sys.exit()
#                        
#        for entry in secgroup_entries['SecurityGroups'][0]['IpPermissions']:
#            print "Revocando --group-name %(secgroup)s --protocol %(IpProtocol)s --port %(FromPort)s --cidr %(CidrIp)s ..." % {'secgroup' : credentialEntry['secgroup'], 'IpProtocol': entry['IpProtocol'], 'FromPort':entry['FromPort'],'CidrIp':entry['IpRanges'][0]['CidrIp'] }
#            print
#            subprocess.check_output("aws ec2 revoke-security-group-ingress --group-name %(secgroup)s --protocol %(IpProtocol)s --port %(FromPort)s --cidr %(CidrIp)s " % {'secgroup' : credentialEntry['secgroup'], 'IpProtocol': entry['IpProtocol'], 'FromPort':entry['FromPort'],'CidrIp':entry['IpRanges'][0]['CidrIp'] })
#            print "Creando --group-name %(secgroup)s --protocol %(IpProtocol)s --port %(FromPort)s --cidr %(addr)s/32 ..."  % {'secgroup' : credentialEntry['secgroup'], 'IpProtocol': entry['IpProtocol'], 'FromPort':entry['FromPort'], 'addr' : ips[0]}
#            print
#            subprocess.check_output("aws ec2 authorize-security-group-ingress --group-name %(secgroup)s --protocol %(IpProtocol)s --port %(FromPort)s --cidr %(addr)s/32"  % {'secgroup' : credentialEntry['secgroup'], 'IpProtocol': entry['IpProtocol'], 'FromPort':entry['FromPort'], 'addr' : ips[0]})
#
#print "======== Proceso Finalizado ========"
#raw_input('Cierre la ventana o presione [enter] para terminar...')
