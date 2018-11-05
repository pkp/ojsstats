import re
import sys
import csv
import gzip
import glob
import requests
from xml.etree import ElementTree

instances = []
csv_output = 'data/ojs_in_logs.csv'

access_log_files = glob.glob('/var/log/httpd/access*gz')

with gzip.open(access_log_files[-1]) as most_recent_log:
	for i, line in enumerate(most_recent_log):
		get = re.search('\s\"GET\s/ojs/xml/ojs-version.xml', str(line))
		if get:

			ip = re.search('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(line))

			version_string = re.search('\"(\S+)\"\s0\s80$', str(line))

			if "ojs2" in version_string.group(1):
				ojs_version = re.search('ojs2/(\S+)', version_string.group(1))

			elif "PKP" in version_string.group(1):
				version_xml = requests.get((ip + '/dbscripts/xml/version.xml'))
				if version_xml.status_code == 200:
					tree = ElementTree.fromstring(version_xml.content)
					if tree.findall('.//application')[0] == "ojs2":
						ojs_version = tree.findall('.//release')[0]

			if not ojs_version:
				continue

			major_version = "ojs" + ojs_version[0]

			beacon_id = re.search('ojs-version.xml?id=(\S+?)&', str(line))
			if beacon_id:
				beacon_id = beacon_id.group(1)
			else:
				beacon_id = ""

			oai_url = re.search('oai=(\S+?)\sHTTP', str(line))
			if oai_url:
				oai_url = oai_url.group(1)
			else:
				oai_url = ""

			instances.append({"base_url": ("http://" + ip), "first_found": "", "product": major_version, "version": ojs_version, "beacon_id": beacon_id, "oai_url": oai_url})


keys = instances[0].keys()
with open(csv_output, "wb") as output_file:
	dict_writer = csv.DictWriter(output_file, keys)
	dict_writer.writeheader()
	dict_writer.writerows(instances)