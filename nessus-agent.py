#!/usr/bin/env python

from nessrest import ness6rest
import os, sys, io
from pprint import pprint as pp
import csv
import time

username = os.environ.get('nessus_user')
password = os.environ.get('nessus_pass')

scanner = ness6rest.Scanner(url="https://nessus-manager.prod.sec.msap.io:8834", login=username, password=password)

target_scan = sys.argv[1]
target_scan = 'manual dynamic - devx'
print target_scan

spin_hosts = open('spin-hosts.list').read().rstrip().split("\n")

plugins_ignore=['Network daemons not managed by the package system']
agents = {}
plugins = {}

def get_agents():
  scanner.action('agents', method='get')

  for agent in scanner.res['agents']:
    agent_uuid = agent['uuid']
    if agent_uuid in agents:
      print "duplicate agent uuid %s"%(agent_uuid)
      #pp(agent)
      #sys.exit(1)
    agents[agent_uuid] = agent

if scanner:
	scanner.action(action='scans', method='get')
	folders = scanner.res['folders']
	scans = scanner.res['scans']
        get_agents()

	for f in folders:
		if not os.path.exists(f['name']):
			if f['type'] != 'trash':
				os.mkdir(f['name'])

	for s in scans:
		scanner.scan_name = s['name']
		scanner.scan_id = s['id']

		if scanner.scan_name != target_scan:
			continue

                scanner.action(action="scans/" + str(scanner.scan_id), method="GET")
		scanner.scan_update_targets("10.7.1.191,10.7.1.30")
		scanner.scan_run()
		pp(scanner.res)
		exit(1)

		pp(s)
		if s['status'] == 'running':
			print "job currently running"
			exit(1)
		exit(1)

		scanner.get_host_ids(scanner.scan_name)
		for host_id in scanner.host_ids.keys():
			#print scanner.scan_id, host_id
			scanner.get_host_details(scanner.scan_id, host_id)
			host_details = scanner.host_details[scanner.scan_id][host_id]
		        host_start = host_details['info']['host_start']
			#pp(host_details['info'])
		        host_ip = host_details['info']['host-ip']
			host_fqdn = host_details['info']['host-fqdn']
			m = 0
			for agent_uuid, agent in agents.items():
				if host_details['info']['mac-address'].lower() in agent['mac_addrs'] and \
				   host_details['info']['host-ip'] == agent['ip']:
					agent_status = agent['status']
					scan_dur = time.time()-int(agent['last_scanned'])
					vuln_names = []
					for vulnerability in host_details['vulnerabilities']:
						if vulnerability['plugin_name'] in plugins_ignore or \
						   vulnerability['severity'] == 0:
							continue
						vuln_names.append(vulnerability['plugin_name'])
						continue
						#pp(vulnerability)
						plugin_id = vulnerability['plugin_id']
						if not plugin_id in plugins:
							scanner.action(action="scans/" + str(scanner.scan_id) + "/hosts/" + str(host_id) + "/plugins/" + str(plugin_id), method="GET")
							plugins[plugin_id] = scanner.res
							#pp(scanner.res)

					if m != 0:
						print "duplicate"
						sys.exit(1)
					m += 1

					if len(vuln_names) > 0:
					  print "%s %s last scan %d with %d vulnerabilities"%(agent_status,host_fqdn,scan_dur,len(vuln_names))
		sys.exit()
		pp(scanner.host_details)


		folder_name = next(f['name'] for f in folders if f['id'] == s['folder_id'])
		folder_type = next(f['type'] for f in folders if f['id'] == s['folder_id'])
		# skip trash items?
		if folder_type == 'trash':
			print "trash"
			continue
		if s['status'] == 'completed':
			file_name = '%s_%s' % (scanner.scan_name, scanner.scan_id)
			print file_name

			#scan = scanner.download_scan(export_format = 'nessus')

			file_modes = 'wb'
			relative_path_name = os.path.join(folder_name, file_name)
			#with io.open(relative_path_name, file_modes) as fp:
			#	fp.write(scanner.download_scan(export_format = 'csv'))
			# ['Plugin ID', 'CVE', 'CVSS', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Synopsis', 'Description', 'Solution', 'See Also', 'Plugin Output']
			with io.open(relative_path_name, 'r') as fp:
				rows = csv.reader(fp)
				headers = None
				for row in rows:
					if not headers:
						headers = row
						continue
					host = row[ headers.index('Host') ]
					cve = row[ headers.index('CVE') ]
					risk = row[ headers.index('Risk') ]

					#if risk == 'None':
					#	continue
					#if host in spin_hosts:
						#print "spin host %s, skipping"%(host)
					#	continue

					#print "%s %s -> %s"%(risk,host,cve)



#host_id = 7
#{u'host-fqdn': u'syslogng-043b0fd257c7fe915-ue1.devx.msap.io',
# u'host-ip': u'10.7.1.183',
# u'host_end': u'Wed Feb 20 21:27:36 2019',
# u'host_start': u'Wed Feb 20 21:27:31 2019',
# u'mac-address': u'12:32:D0:BC:62:A2',
# u'operating-system': u'Linux Kernel 4.14.97-74.72.amzn1.x86_64 on Amazon Linux AMI'}
#{u'auto_unlinked': 0,
# u'core_build': u'1',
# u'core_version': u'7.2.1',
# u'distro': u'amzn-x86-64',
# u'groups': [u'devx', u'all hosts'],
# u'id': 1167,
# u'ip': u'10.7.1.183',
# u'last_connect': 1550792034,
# u'last_scanned': 1550718046,
# u'linked_on': 1535494692,
# u'mac_addrs': u'["12:32:d0:bc:62:a2"]',
# u'name': u'syslogng-043b0fd257c7fe915-ue1.devx.msap.io',
# u'platform': u'LINUX',
# u'plugin_feed_id': u'201902201242',
# u'status': u'on',
# u'unlinked_on': None,
# u'uuid': u'31d15e31-1f63-41b1-af73-db062f305201'}
