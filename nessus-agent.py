#!/usr/bin/env python

from nessrest import ness6rest
import os, sys, io
from pprint import pprint as pp
import cvs

username='a25a1dbff783a37293e78d4d7a504a0d9a90bf6395d7a3675b8ee281609d3150'
password='7fc72b77dc710a565c361abc2e529d996bd6037506c1ae13366351bb78aee32b'

username = os.environ.get('nessus_user')
password = os.environ.get('nessus_pass')

scanner = ness6rest.Scanner(url="https://nessus-manager.prod.sec.msap.io:8834", login=username, password=password)

target_scan = sys.argv[1]
print target_scan

if scanner:
	scanner.action(action='scans', method='get')
	folders = scanner.res['folders']
	scans = scanner.res['scans']

	for f in folders:
		if not os.path.exists(f['name']):
			if f['type'] != 'trash':
				os.mkdir(f['name'])

	for s in scans:
		scanner.scan_name = s['name']
		scanner.scan_id = s['id']
		if scanner.scan_name != target_scan:
			continue
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
		with io.open(relative_path_name, file_modes) as fp:
			fp.write(scanner.download_scan(export_format = 'csv'))
		with io.open(relative_path_name, 'r') as fp:
			rows = csv.reader(fp)
			for row in rows:
				print row

