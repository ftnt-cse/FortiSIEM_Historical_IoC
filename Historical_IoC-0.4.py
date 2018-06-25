#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" FortiSIEM , Historical IoC
it enables FortiSIEM to find previously infected machines after each FortiGuard IoC update.

Todo:
    * increase IoC sources to cover all available ones beside FortiGuard

PS: THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND

"""
__author__ = "Naili Mahdi"
__license__ = "GPL"
__version__ = "0.4"
__maintainer__ = "Naili Mahdi"
__email__ = "nailix10@gmail.com"
__status__ = "alpha"

import socket
import string
import re
import sys
import os
import xml.dom.minidom
import time
import requests
import pg8000 as dbapi
import datetime
from datetime import datetime
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import logging
import dateutil.parser as date_parser

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(sys.argv[0])
hdlr = logging.FileHandler(sys.argv[0] + '.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 

logger.setLevel(logging.DEBUG)

fsm_ip='127.0.0.1'
fsm_admin='super/admin'
fsm_password=''
db_username=''
db_password=''
report_hours='10'
dump_response=True


# Functions
def dump_to_file(dumpfile,data):
	#writes server response data to file
	if dump_response:
		try:
			f = open(dumpfile, "w")
			try:
				f.write(data)
			finally:
				f.close()
		except IOError:
			print 'Can t write response to file'


def to_epoch(mytime):
	# Convert time to epoch
	tz_str = '''-12 Y
	-11 X NUT SST
	-10 W CKT HAST HST TAHT TKT
	-9 V AKST GAMT GIT HADT HNY
	-8 U AKDT CIST HAY HNP PST PT
	-7 T HAP HNR MST PDT
	-6 S CST EAST GALT HAR HNC MDT
	-5 R CDT COT EASST ECT EST ET HAC HNE PET
	-4 Q AST BOT CLT COST EDT FKT GYT HAE HNA PYT
	-3 P ADT ART BRT CLST FKST GFT HAA PMST PYST SRT UYT WGT
	-2 O BRST FNT PMDT UYST WGST
	-1 N AZOT CVT EGT
	0 Z EGST GMT UTC WET WT
	1 A CET DFT WAT WEDT WEST
	2 B CAT CEDT CEST EET SAST WAST
	3 C EAT EEDT EEST IDT MSK
	4 D AMT AZT GET GST KUYT MSD MUT RET SAMT SCT
	5 E AMST AQTT AZST HMT MAWT MVT PKT TFT TJT TMT UZT YEKT
	6 F ALMT BIOT BTT IOT KGT NOVT OMST YEKST
	7 G CXT DAVT HOVT ICT KRAT NOVST OMSST THA WIB
	8 H ACT AWST BDT BNT CAST HKT IRKT KRAST MYT PHT SGT ULAT WITA WST
	9 I AWDT IRKST JST KST PWT TLT WDT WIT YAKT
	10 K AEST ChST PGT VLAT YAKST YAPT
	11 L AEDT LHDT MAGT NCT PONT SBT VLAST VUT
	12 M ANAST ANAT FJT GILT MAGST MHT NZST PETST PETT TVT WFT
	13 FJST NZDT
	11.5 NFT
	10.5 ACDT LHST
	9.5 ACST
	6.5 CCT MMT
	5.75 NPT
	5.5 SLT
	4.5 AFT IRDT
	3.5 IRST
	-2.5 HAT NDT
	-3.5 HNT NST NT
	-4.5 HLV VET
	-9.5 MART MIT'''

	tzd = {}
	for tz_descr in map(str.split, tz_str.split('\n')):
		tz_offset = int(float(tz_descr[0]) * 3600)
		for tz_code in tz_descr[1:]:
			tzd[tz_code] = tz_offset

	parsed_time = date_parser.parse(mytime,tzinfos=tzd)
	return int(parsed_time.strftime('%s'))


def to_time(mytime):
	#return a converted epoch as time and date
	return time.strftime('%Y-%m-%d', time.localtime(mytime)),time.strftime('%H:%M:%S', time.localtime(mytime))


def fetch_db_ioc(username,password,host='127.0.0.1',database='phoenixdb',port=5432):
	# retrieves ioc list from phoenixdb, host, db and port are set to default, username and password has to be supplied

	# Args:
	#     host (str)			: db server IP (localhost if running on FSM)
	#     databas (str)			: db name (phoenixdb)
	#     username (str)		: db username, you may want to create your own and grant it phoenixdb privileges
	#     password (str)		: db password
	#     port (str)			: db port (5432 by default on FSM)

	# Returns:
	#	  list of dictionaries containing the count, srcip,dstip
	fortiguard_ioc=[]
	query='select low_ip from ph_malware_ip where group_id=500615 and active=true;' 
	#query='select low_ip from ph_malware_ip where active=true;' 	

	try:
		conn=dbapi.connect(database=database,host=host, port=port,user=username	,password=password,ssl=False)
		curr=conn.cursor()
		curr.execute(query)
		for row in curr.fetchall():
			fortiguard_ioc.extend(row)
			dump_to_file("sqlreposne.txt",str(fortiguard_ioc))
		return fortiguard_ioc

	except Exception as err:
		logger.error(err)
		return False

def xml_parser(xmldata):
	# parses the received report from FSM
	# Args:
	#     xmldata (str)			: xml string to be parsed

	# Returns:
	#	  list of dictionaries containing the count,srcip,dstip
	res_list=[]
	total_count=0
	doc = xml.dom.minidom.parseString(xmldata)
	
	#Get total count if it exists
	node = doc.documentElement        
	if node.nodeType == xml.dom.Node.ELEMENT_NODE:
		for (name, value) in node.attributes.items():
			if name == 'totalCount':
				if value is not None:
					total_count = value
				else:
					total_count=0

	nodes = doc.getElementsByTagName("attribute")
	for node in nodes:  
		attr = node.getAttribute("name")
		if attr == 'FIRST(deviceTime)':
			device_time=node.firstChild.data
			event_epoch=to_epoch(device_time)
			event_date,event_time=to_time(event_epoch)
		if attr == 'COUNT(*)':
			count=node.firstChild.data
		if attr == 'srcIpAddr':
			srcip=node.firstChild.data
		if attr == 'destIpAddr':
			dstip=node.firstChild.data
			res_list.append({dstip:srcip + ',' + count+ ',' +event_date+ ',' +event_time})
	return total_count,res_list


def fetch_address_list(server, username, password):
	# Fetches src,dst,count report from FortiSIEM via REST API
	# Args:
	#     server (str)			: FSM IP Address
	#     username (str)		: FSM admin username ex: super/admin
	#     password (str)		: FSM password

	# Returns:
	#	  list of unique destination IPs
	try:
		report=[]
		session = requests.Session()
		# Post report query
		xmlquery = xml.dom.minidom.parseString("""<?xml version="1.0" ?>
		<Reports>
		<Report id="" group="">
		<Name>Custom Destination</Name>
		<CustomerScope groupByEachCustomer="true"><Include all="true"/> <Exclude/></CustomerScope> 
		<Description>All destinations</Description>
		<SelectClause numEntries="All">
		<AttrList>srcIpAddr,FIRST(deviceTime),destIpAddr,COUNT(*)</AttrList>
		</SelectClause>
		<ReportInterval><Window unit="Hourly" val=\""""+report_hours+"""\"/></ReportInterval>
		<PatternClause window="3600">
		<SubPattern id="20881754" name="Filter_FW_23">
		<SingleEvtConstr>reptDevIpAddr IN (Group@PH_SYS_DEVICE_FIREWALL)  AND  srcIpAddr IN (Group@PH_SYS_NETWORK_ENTERPRISE_INTERNAL_NET)</SingleEvtConstr>
		<GroupByAttr>srcIpAddr,destIpAddr</GroupByAttr>
		</SubPattern>
		</PatternClause>
		</Report>
		</Reports>""")

		authentication=HTTPBasicAuth(username, password)
		header={'Content-Type': 'text/xml'}
		response = session.post('https://' + server + '/phoenix/rest/query/eventQuery',verify=False,auth=authentication,headers=header,data=xmlquery.toxml())

		if len(response.content) != 19:
			logger.error("Server response: %s \nWrong username/password or invalid query ID\n" % response.content)
			return False
		
		queryId = response.content
		progress = '0'

		while progress != '100':
			response = session.get('https://' + server + '/phoenix/rest/query/progress/' + queryId,verify=False,auth=authentication)
			logger.info("Report progress %s" % response.content)
			progress = response.content
			time.sleep(2)

		response = session.get('https://' + server + '/phoenix/rest/query/events/' + queryId +'/0/1000',verify=False,auth=authentication)
		if response.status_code == 200:
			#collect the first response and extract totalCount value
			dump_to_file("xmlreposne.txt",response.content)
			total_count,fsm_report=xml_parser(response.content)
			report+=fsm_report
			logger.info("Total records received: %s" % total_count)
			logger.info("Current report length: %i" % len(report))
			pages = 0
			if int(total_count) > 1000:
				pages = int(total_count) / 1000
				if int(total_count) % 1000 > 0:
					pages += 1
			if pages > 0:
				for i in range(1,pages):
					response = session.get('https://' + server + '/phoenix/rest/query/events/' + queryId + '/' + str(i * 1000) + '/1000',verify=False,auth=authentication)
					#print str(i*1000+1)+'/1000'
					if response.status_code == 200:
						total_count,fsm_report=xml_parser(response.content)
						report+=fsm_report
						logger.info("Current report length: %i" % len(report))


		return report

	except requests.ConnectionError:
		logger.error("Connection error, Make sure the device is listening in 443")
		return False        
	except requests.ConnectTimeout:
		logger.error("Connection timeout")
		return False  
	except requests.exceptions.RequestException as e:
		logger.error("An error occured: %s" % e)	
		sys.exit(1)

def send_log(fsm_ip,srcip,dstip,event_date,event_time,count=0):
	# Send a syslog to FortiSIEM matching FortiGate "FortiGate-Antivirus-Botnet" event type

	# Args:
	#     fsm_ip (str)			: FSM IP Address
	#     srcip (str)			: botnet connection srcip
	#     dstip (str)			: botnet connection dstip
	#     count (str)			: number of sessions
	#     report_seconds (str)	: dstip report from FSM generated for x seconds (1,2,3h...etc)

	# Returns:
	#	  list of unique destination IPs
	log = '<188>' + time.strftime('%b %e %H:%M:%S',time.localtime(time.time())) + '[PH_AUDIT_MALWARE_DATA_UPDATED]:[phCustId]=1,[eventSeverity]=PHL_INFO,[folder]=Emerging \
Threat Malware IP,[phEventCategory]=2,[infoURL]=https://fortiguard.com/webfilter?q=' + dstip + ',[count]=' + str(count) + ',[updateTime]=' + str(to_epoch(event_time + ' ' + event_date)) + ',\
[procName]=AppServer,[user]=' + srcip + ',[phLogDetail]=Botnet connection detected ' + str(count) + ' times from ' + srcip + ' to ' + dstip


	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect((fsm_ip,1470))
	s.sendall(log)
	s.close()	
	logger.info(log)

if __name__ == '__main__':
	sessions = fetch_address_list(fsm_ip,fsm_admin,fsm_password)
	ioc = fetch_db_ioc(db_username,db_password)	
	if ioc:
		for connection in sessions:
			for dstip, values in connection.items(): 
				if dstip.strip() in ioc:
					srcip,count,event_date,event_time = values.split(",")
					print 'Infected machine found',srcip,count,event_date,event_time
					send_log('127.0.0.1',srcip,dstip,event_date,event_time,count)

