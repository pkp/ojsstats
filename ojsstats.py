import re
import sys
import csv
import gzip
import glob
import urllib.request as urllib2 # forward-port from python 2
import json
import time
import random
import socket
import requests
import sqlite3 as lite
import datetime as dt

from tld import get_tld
from geoip import geolite2
from sickle import Sickle
from dateutil.parser import parse
from xml.etree import ElementTree as ET

litecon = lite.connect('data/ojs_oai.db')


def find_country_in_title(journal):
	if journal[3] in country_from_title:
		return country_from_title[journal[3]][1]

	# randomly sort the haystack since we're returning the first match
	# so we're not favouring matches in alphabetical order
	for key, value in sorted(nat_to_iso3.items(), key=lambda x: random.random()):
		if journal[2].lower().find(key.lower()) >= 0:
			country_from_title[journal[3]] = (key, value)
			return value
	return None


def find_journal_endpoint(oai_url, setSpec):
	if re.search("\?page=oai", oai_url):
		journal_endpoint = re.sub("\?", ("/index.php?journal=" + setSpec + "&"), oai_url)
	else:
		journal_endpoint = re.sub("index\/", (setSpec + "/"), oai_url)

	journal_endpoint = re.sub("[&\?]?verb=Identify", "", journal_endpoint)
	return journal_endpoint


def find_journal_url(oai_url, setSpec):
	if oai_url.find("page=oai") > 0:
		journal_url = re.sub('\?.*', '/index.php?journal='+setSpec, oai_url)
	else:
		journal_url = re.sub('index/oai.*', setSpec, oai_url)

	return journal_url


def find_oai_endpoint(url):
	''' Finds an OAI endpoint given a base OJS-install URL '''

	url = url.strip("/")
	urls_to_try = []
	urls_to_try.append(url + "/index/oai?verb=Identify")
	urls_to_try.append(url + "/index.php/index/oai?verb=Identify")
	urls_to_try.append(url + "?page=oai&verb=Identify")
	urls_to_try.append(url + "/index.php?page=oai&verb=Identify")

	for url_to_try in urls_to_try:
		oai_url = False
		repository_id_xml_block = False
		repository_identifier = False
		date_hit = False
		ip = False
		ojs_version = False

		try:
			print("Going after: %s" % url_to_try)
			request = urllib2.Request(url_to_try)
			response = urllib2.urlopen(request, timeout=180)
			oai_xml = response.read()
		except urllib2.HTTPError:
			continue
		except urllib2.URLError:
			continue
		except:
			# some other error, but probably still OK to ignore
			# because it was thrown by urllib2, which means the URL did not work
			continue # move onto next URL

		try:
			oai_xml_tree = ET.fromstring(oai_xml)
		except:
			# invalid XML means we can move onto next URL
			continue # move onto next URL

		# This could be made more efficient than a findall
		for element in oai_xml_tree.findall(".//{http://www.openarchives.org/OAI/2.0/oai-identifier}repositoryIdentifier"):
			repository_id_xml_block = element
			repository_identifier = element.text

		# if no repo id was found, then this is not the URL we're looking for.
		if repository_id_xml_block is False:
			continue

		for element in oai_xml_tree.findall(".//{http://oai.dlib.vt.edu/OAI/metadata/toolkit}version"):
			ojs_version = element.text

		date_hit = dt.datetime.today().strftime("%m/%d/%Y")

		url_without_http = re.sub("http://", "", url)
		try:
			ip = socket.gethostbyname(re.sub("/([^/]*)$", "", url_without_http))
		except:
			print("Failed to get IP of a valid URL: %s" % url_without_http)
			continue

		oai_url = url_to_try
		break

	# if we didn't find a repo, do not return a list
	if repository_id_xml_block is False or oai_url is False:
		return False

	if not repository_identifier:
		repository_identifier = ip + re.sub("http://[^/]+/", "/", oai_url)

	return [oai_url.lower(), repository_identifier, date_hit, ip, ojs_version]


def verify_not_missing_journal(journal_endpoint, setSpec):
	testing_url = (re.sub("verb=Identify", "verb=ListRecords&metadataPrefix=oai_dc&set=", journal_endpoint) + setSpec)
	request = urllib2.Request(testing_url)
	response = urllib2.urlopen(request, timeout=180)
	oai_xml = response.read()
	# parsing XML with regex yeaaaaaaaaaaah [air guitar]
	if re.search("noRecordsMatch", oai_xml):
		return True
	return False


def get_journals(oai_list_sets_url):
	''' Hit an installations OAI endpoint for the list of "sets" (journals) '''
	spec_name_pairs = []
	while True:
		token = None
		try:
			request = urllib2.Request(oai_list_sets_url)
			response = urllib2.urlopen(request, timeout=180)
			oai_xml = response.read()
		except:
			return False

		try:
			sets_tree = ET.fromstring(oai_xml)
		except:
			return False

		for element in sets_tree.findall(".//{http://www.openarchives.org/OAI/2.0/}set"):
			spec_name_pair = []
			for child in element:
				if child.tag != "{http://www.openarchives.org/OAI/2.0/}setDescription":
					spec_name_pair.append(child.text)

			spec_name_pairs.append(spec_name_pair)

		for element in sets_tree.findall(".//{http://www.openarchives.org/OAI/2.0/}resumptionToken"):
			token = element.text

		if token and len(token) > 0:
			oai_list_sets_url = re.sub("&resumptionToken.*", "", oai_list_sets_url) + "&resumptionToken=" + token
		else:
			break

	return spec_name_pairs


def find_journal_endpoint(oai_url, setSpec):
	''' Figure out the OAI endpoint for the journal given the OAI endpoint for install + setSpec '''
	if re.search("\?page=oai", oai_url):
		journal_endpoint = re.sub("\?", ("/index.php?journal=" + setSpec + "&"), oai_url)
	else:
		journal_endpoint = re.sub("index\/", (setSpec + "/"), oai_url)

	is_missing = verify_not_missing_journal(journal_endpoint, setSpec)
	if is_missing:
		return None
	return journal_endpoint


def find_journal_contact(journal_endpoint):
	''' Get the journal contact info from the journal-specific OAI endpoint '''
	try:
		request = urllib2.Request(journal_endpoint)
		response = urllib2.urlopen(request, timeout=180)
		oai_xml = response.read()
	except:
		return False

	try:
		oai_xml_tree = ET.fromstring(oai_xml)
	except:
		return False

	for element in oai_xml_tree.findall(".//{http://www.openarchives.org/OAI/2.0/}adminEmail"):
		journal_contact = element.text

	return journal_contact


def beacon_log_parser():
	# TODO: change this to write directly to sqlite
	instances = []
	csv_output = 'data/ojs_in_logs.csv'

	if len(sys.argv) > 1:
		access_log_files = glob.glob(sys.argv[1])
	else:
		access_log_files = glob.glob('/var/log/httpd/')
	access_log_files = access_log_files + "access*gz"

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
						tree = ET.fromstring(version_xml.content)
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


def check_ojs():
	# TODO: this should be reading from sqlite
	with open(sys.argv[1], 'rb') as ojslogs:
		logreader = csv.reader(ojslogs)
		for row in logreader:
			base_url = row[0] # row[0] has the potential OJS base_url extracted from logs
			oai_data = find_oai_endpoint(base_url)

			print(oai_data)
			if not oai_data:
				with open("data/checkOJSlog.txt", "a") as logfile:
					logfile.write("couldn't hit endpoint for %s\n" % base_url)

				continue

			oai_url, repository_identifier, date_hit, ip, ojs_version = oai_data

			try:
				with litecon:
					litecur = litecon.cursor()
					try:
						# disable any old IP addresses for this domain name
						litecur.execute("UPDATE endpoints SET enabled=0 WHERE oai_url=? AND ip!=?", (oai_url, ip))

						litecur.execute("INSERT INTO endpoints (oai_url, repository_identifier, first_hit, last_hit, ip, version, enabled) VALUES(?,?,?,?,?,?,?)", (oai_url, repository_identifier, date_hit, date_hit, ip, ojs_version, 1))

					except lite.IntegrityError:

						print("already had %s:%s" % (repository_identifier, ip))
						# if it can't insert a site it's already crawled, check if it's been upgraded and add to upgrades table
						litecur.execute('SELECT version FROM endpoints WHERE repository_identifier=? AND ip=?', (repository_identifier, ip))
						oldversion = litecur.fetchone()[0].encode()

						try:
							if oldversion != ojs_version:
								litecur.execute("INSERT INTO upgrades (repository_identifier, ip, oldversion, newversion, date_hit) VALUES(?,?,?,?,?)", (repository_identifier, ip, oldversion, ojs_version, date_hit))
						except lite.IntegrityError:
							pass

						litecur.execute('UPDATE endpoints SET last_hit=?, enabled = 1 WHERE repository_identifier=? AND ip=?', (date_hit, repository_identifier, ip))

				oai_list_sets_url = re.sub("verb=Identify", "verb=ListSets", oai_url)
				journals = get_journals(oai_list_sets_url)

				for journal in journals:
					setSpec = journal[0]
					setName = journal[1]

					# only those setSpecs without a : are journals (with : they are sections)
					if not re.search(":", setSpec):
						journal_endpoint = find_journal_endpoint(oai_url, setSpec)
						if journal_endpoint is None:
							continue
						else:
							journal_contact = find_journal_contact(journal_endpoint)

						with litecon:
							litecur = litecon.cursor()
							try:

								litecur.execute("INSERT INTO journals (repository_identifier, ip, setSpec, setName, first_hit, last_hit, contact) VALUES(?,?,?,?,?,?,?)", (repository_identifier, ip, setSpec, setName, date_hit, date_hit, journal_contact))
								archive_id = int(litecur.lastrowid)
								litecur.execute("UPDATE journals SET archive_id=? WHERE repository_identifier=? AND ip=? AND setSpec=?", (archive_id, ojs["repository_identifier"], ojs["ip"], ojs["setSpec"]))

							except lite.IntegrityError:
								print("Already had %s" % setSpec)
								# on failed to insert, update the last hit date
								litecur.execute("UPDATE journals SET last_hit=? WHERE repository_identifier=? AND ip=? AND setSpec=?", (date_hit, repository_identifier, ip, setSpec))
			except:
				with open("data/checkOJSlog.txt", "a") as logfile:
					logfile.write("something failed other than looking up URL for %s\n." % oai_url)


def harvest():
	with litecon:
		c = litecon.cursor()
		c2 = litecon.cursor()

		dates_csv = open("data/dates.csv", "w")
		writer = csv.DictWriter(dates_csv, fieldnames=list(range(1990,(int(time.strftime("%Y")) + 1))))
		writer.writeheader()

		for row in c.execute("SELECT repository_identifier, setSpec, setName, ip FROM journals"):
			ojs = dict(zip(["repository_identifier", "setSpec", "title", "ip"], row))

			if ojs["title"] is None:
				continue

			c2.execute("SELECT oai_url FROM endpoints WHERE repository_identifier=? AND ip=? AND enabled = 1", (repository_identifier, ip))
			try: 
				oai_url = litecur.fetchone()[0]
			except: 
				# there may not be any enabled endpoints 
				continue

			ojs["oai_endpoint"] = find_journal_endpoint(oai_url, setSpec)
			ojs["journal_url"] = find_journal_url(oai_url, setSpec)

			pub_years = []
			sickle = Sickle(ojs["oai_endpoint"])
			records = sickle.ListRecords(metadataPrefix="nlm", ignore_deleted=True)

			while records:
				record = records.next()
				for source in record.metdata["source"]:
					match = re.search(r"(199[0-9]|20\d{2})", source)
					if match:
						year = match[0]
					else:
						year = parse(record.metadata["date"][0]).strftime('%Y')
				pub_years.append(year)

			year_count = Counter()
			for pub_year in pub_years:
				year_count[pub_year] += 1

			final_count = dict(year_count)
			# TODO: this needs to have record_dates.columns = ['record_id', 'archive_id','dcdate', 'source']
			# seems like the opposite of what it's doing currently
			writer.writerow(final_count)

		dates_csv.close()


def country_lookup():
	country_from_title = {}
	wb_country_info = {}
	iso2_to_iso3 = {}

	country_stop_words = ['islands', 'saint', 'and', 'republic', 'virgin', 'united', 'south', 'of', 'new', 'the']

	request = urllib2.Request("http://api.worldbank.org/countries?per_page=400&format=json" )
	response = urllib2.urlopen(request, timeout=30)
	wb_country_data = json.load(response)[1]

	for country in wb_country_data:
		if country['region']['value'] == 'Aggregates': continue

		iso3 = country['id'].lower()
		wb_country_info[iso3] = {'iso2': country['iso2Code'].lower(), 'name': country['name'], 'region_id': country['region']['id'], 'region_name': country['region']['value']}
		iso2_to_iso3[country['iso2Code'].lower()] = iso3

	# some corrections/additions from the freegeoip results
	iso2_to_iso3['uk'] = 'gbr' # uk -> great britain
	iso2_to_iso3['rs'] = 'srb' # serbia -> serbia & montenegro
	iso2_to_iso3['me'] = 'srb' # montenegro -> serbia & montenegro
	iso2_to_iso3['tl'] = 'tls' # tl -> east timor
	iso2_to_iso3['tw'] = 'twn' # tw -> taiwan
	wb_country_info['twn'] = {'iso2': 'tw', 'region_id': 'EAS', 'region_name': 'East Asia & Pacific (all income levels)'}

	# now some corrections to map onto the world-countries.json from d3
	iso2_to_iso3['ro'] = 'rou' # ro -> romania
	iso2_to_iso3['hk'] = 'chn' # hong kong -> china

	nat_to_iso3 = {}

	for country in wb_country_data:
		if country['iso2Code'].lower() not in iso2_to_iso3: continue

		iso3 = iso2_to_iso3[country['iso2Code'].lower()]

		nat = [x for x in re.split('[^\w\ \&]', country['name']) if x not in country_stop_words][0].strip(' s').strip('aeiou')

		# a few that get confused
		if nat == 'Austr':
			nat = 'Austria'
		elif nat == 'Austral':
			nat = 'Australia'

		if len(nat) > 4:
			nat_to_iso3[nat] = iso3

	tld_to_country = {}
	with open('tldtoiso2.csv') as f: 
		f.readline() # throw away header
		for line in f:
			line = line.strip().lower().split(',')
			if line[2] != 'none':
				tld_to_country[line[0]] = line[2]

	with litecon:
		litecur = litecon.cursor()
		litecur.execute("SELECT repository_identifier, setSpec, setName, archive_id, ip FROM journals WHERE archive_id IS NOT NULL")
		journals = litecur.fetchall()

		for journal in journals:
			repository_identifier, setSpec, setName, archive_id, ip = journal

			match = geolite2.lookup(ip)
			if match is not None:
				try:
					journal_geoip = match.country.lower()
				except:
					journal_geoip = None
			else:
				journal_geoip = None

			if setName is not None:
				country_in_title = find_country_in_title(journal)
			else:
				country_in_title = None

			litecur.execute("SELECT oai_url FROM endpoints WHERE repository_identifier=? AND ip=?", (repository_identifier, ip))
			oai_url = litecur.fetchone()[0]
			
			# extract the TLD
			domain = get_tld(oai_url, as_object=True, fail_silently=True)
			if domain: 
				tld = domain.suffix[domain.suffix.find('.')+1:]
			else:
				tld = None
			
			country = False
			if country_in_title is not None:
				country = country_in_title
			elif tld is not None and tld != "php" and tld != "com" and tld != "net" and tld != "org" and tld != "info":
				if tld == "edu":
					country = "usa"
				try:
					country = iso2_to_iso3[tld_to_country[tld]]
				except:			  
					pass
			
			# special handling of the JOLs
			if tld == 'info':
				if domain.domain == 'vjol':
					country = 'vnm'
				elif domain.domain == 'banglajol':
					country = 'bgd'
				elif domain.domain == 'ajol':
					country = 'zaf'
				elif domain.domain == 'nepjol':
					country = 'npl'
				elif domain.domain == 'philjol':
					country = 'phl'
				elif domain.domain == 'mongoliajol':
					country = 'mng'
				elif domain.domain == 'lamjol':
					if not country_in_title: 
						country = 'pri' # these are not really PRI, but want them to go to LatAm

			if not country:
				try:
					country = iso2_to_iso3[journal_geoip]
				except:
					continue

			region_id = wb_country_info[country]['region_id']
			region_name = wb_country_info[country]['region_name'].strip()

			try:
				litecur.execute("INSERT INTO locales (archive_id, tld, country_in_title, geo_ip, country, region_id, region_name) VALUES(?,?,?,?,?,?,?)", (archive_id, tld, country_in_title, journal_geoip, country, region_id, region_name))
			except:
				litecur.execute("UPDATE locales SET tld=?, country_in_title=?, geo_ip=?, country=?, region_id=?, region_name=? WHERE archive_id = ?", (tld, country_in_title, journal_geoip, country, region_id, region_name, archive_id))


if __name__ == "__main__":

	with litecon:
		litecur = litecon.cursor()
		litecur.execute("CREATE TABLE IF NOT EXISTS endpoints (oai_url TEXT, repository_identifier TEXT, first_hit TEXT, last_hit TEXT, ip TEXT, version TEXT, enabled INTEGER)")
		litecur.execute("CREATE UNIQUE INDEX IF NOT EXISTS id_plus_ip ON endpoints (repository_identifier, ip)")

		litecur.execute("CREATE TABLE IF NOT EXISTS journals (repository_identifier TEXT, ip TEXT, setSpec TEXT, setName TEXT, first_hit TEXT, last_hit TEXT, contact TEXT, archive_id INTEGER)")
		litecur.execute("CREATE UNIQUE INDEX IF NOT EXISTS id_plus_ip_plus_spec ON journals (repository_identifier, ip, setSpec)")

		litecur.execute("CREATE TABLE IF NOT EXISTS upgrades(repository_identifier TEXT, ip TEXT, oldversion TEXT, newversion TEXT, date_hit TEXT)")
		
		litecur.execute("CREATE TABLE IF NOT EXISTS locales (archive_id TEXT, tld TEXT, country_in_title TEXT, geo_ip TEXT, country TEXT, region_id TEXT, region_name TEXT)")
		litecur.execute("CREATE UNIQUE INDEX IF NOT EXISTS locale_index ON locales (archive_id)")

	beacon_log_parser()
	check_ojs()
	harvest()
	country_lookup()

	# TODO: statscrunch currently expects data/archive_settings.csv with lastIndexedDate, recordCount, harvesterUrl