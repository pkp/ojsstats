"""OJS Stats.

Usage:
  ojsstats.py [--onlylogparse | --onlyharvest] [--logpath=<path>]

Options:
  --onlylogparse    Quit after parsing logs into the DB.
  --onlyharvest     Don't parse logs; only harvest and export.
  --logpath=<path>  The path to parse logs from. Defaults to /var/log/httpd.

"""

import os
import re
import sys
import csv
import gzip
import glob
import urllib.request as urllib2 # forward-port from python 2
import urllib.parse
import urllib.error
import json
import time
import random
import requests
import collections
import sqlite3 as lite
import datetime as dt
import geoip2.database
import geoip2.errors

from docopt import docopt
from tld import get_tld
from sickle import Sickle
from dateutil.parser import parse
from xml.etree import ElementTree as ET


def find_country_in_title(journal, country_from_title, nat_to_iso3):
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

	is_missing = verify_not_missing_journal(journal_endpoint, setSpec)
	if is_missing:
		return None
	return journal_endpoint


def find_oai_endpoint(url, ip, is_beacon):
	if is_beacon == False:
		url = url.strip("/")
		urls_to_try = []
		urls_to_try.append(url + "/index/oai?verb=Identify")
		urls_to_try.append(url + "/index.php/index/oai?verb=Identify")
		urls_to_try.append(url + "?page=oai&verb=Identify")
		urls_to_try.append(url + "/index.php?page=oai&verb=Identify")
	else:
		urls_to_try = []
		urls_to_try.append(url + "&verb=Identify")
		urls_to_try.append(url + "?verb=Identify")

	for url_to_try in urls_to_try:
		oai_url = False
		repository_id_xml_block = False
		repository_identifier = False
		date_hit = False

		try:
			print("Going after: %s" % url_to_try)
			request = urllib2.Request(url_to_try)
			response = urllib2.urlopen(request, timeout=20)
			oai_xml = response.read()
		except:
			continue

		try:
			oai_xml_tree = ET.fromstring(oai_xml)
		except:
			continue

		# This could be made more efficient than a findall
		for element in oai_xml_tree.findall(".//{http://www.openarchives.org/OAI/2.0/oai-identifier}repositoryIdentifier"):
			repository_id_xml_block = element
			repository_identifier = element.text

		# if no repo id was found, then this is not the URL we're looking for.
		if repository_id_xml_block is False:
			continue

		date_hit = dt.datetime.today().strftime("%m/%d/%Y")
		oai_url = url_to_try

	# if we didn't find a repo, do not return a list
	if repository_id_xml_block is False or oai_url is False:
		return False

	if not repository_identifier:
		repository_identifier = ip + re.sub("http://[^/]+/", "/", oai_url)

	return [oai_url, repository_identifier, date_hit]


def verify_not_missing_journal(journal_endpoint, setSpec):
	testing_url = (re.sub("verb=Identify", "verb=ListRecords&metadataPrefix=oai_dc&set=", journal_endpoint) + setSpec)
	request = urllib2.Request(testing_url)
	try:
		response = urllib2.urlopen(request, timeout=20)
	except:
		return True
	oai_xml = response.read()
	if "noRecordsMatch" in str(oai_xml):
		return True
	return False


def get_journals(oai_list_sets_url):
	spec_name_pairs = []
	while True:
		token = None
		try:
			request = urllib2.Request(oai_list_sets_url)
			response = urllib2.urlopen(request, timeout=20)
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


def find_journal_contact(journal_endpoint):
	try:
		request = urllib2.Request(journal_endpoint)
		response = urllib2.urlopen(request, timeout=20)
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


def beacon_log_parser(logpath):
	if not logpath:
		access_log_files = '/var/log/httpd'
	else:
		access_log_files = logpath	
	access_log_files = glob.glob(access_log_files + "/access*gz")

	with gzip.open(access_log_files[-1]) as most_recent_log:
		for i, line in enumerate(most_recent_log):
			get = re.search('\s\"GET\s/ojs/xml/ojs-version.xml', str(line))
			if not get:
				continue

			ip = re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(line)).group(0)

			version_string = re.search('\"(\S+)\"\s0\s80', str(line))

			try:
				if "ojs2" in version_string.group(1):
					ojs_version = re.search('ojs2/(\S+)', version_string.group(1)).group(1)
				elif "PKP" in version_string.group(1):
					version_xml = requests.get((ip + '/dbscripts/xml/version.xml'))
					tree = ET.fromstring(version_xml.content)
					if tree.findall('.//application')[0] == "ojs2":
						ojs_version = tree.findall('.//release')[0]
			except:
				continue

			beacon_id = re.search('ojs-version\.xml\?id=(\S+?)&', str(line))
			if beacon_id:
				beacon_id = beacon_id.group(1)
			else:
				beacon_id = ""

			oai_url = re.search('oai=(\S+?)\sHTTP', str(line))
			if oai_url:
				oai_url = oai_url.group(1)
				oai_data = find_oai_endpoint(urllib.parse.unquote(oai_url), ip, True)
			else:
				oai_url = ""
				oai_data = find_oai_endpoint("https://" + ip, ip, False)

			if not oai_data:
				with open("data/checkOJSlog.txt", "a") as logfile:
					logfile.write("couldn't hit endpoint for %s\n" % ip)
				continue

			oai_url, repository_identifier, date_hit = oai_data

			with litecon:
				try:
					c = litecon.cursor()
					try:
						# disable any old IP addresses for this domain name
						c.execute("UPDATE endpoints SET enabled=0 WHERE oai_url=? AND ip!=?", (re.sub("verb=Identify", "verb=identify", oai_url), ip))

						c.execute("INSERT INTO endpoints (beacon_id, oai_url, repository_identifier, first_hit, last_hit, ip, version, enabled) VALUES(?,?,?,?,?,?,?,?)", (beacon_id, re.sub("verb=Identify", "verb=identify", oai_url), repository_identifier, date_hit, date_hit, ip, ojs_version, 1))

					except lite.IntegrityError:
						print("already had %s:%s:%s" % (repository_identifier, ip, beacon_id))

						# check to see if it already exists without a beacon ID and update if we have one
						c.execute('SELECT beacon_id FROM endpoints WHERE repository_identifier=? AND ip=?', (repository_identifier, ip))
						if beacon_id and not c.fetchone()[0]:
							c.execute("UPDATE endpoints SET beacon_id=? WHERE repository_identifier=? AND ip=?", (beacon_id, repository_identifier, ip))

						# check if it's been upgraded and add to upgrades table
						c.execute('SELECT version FROM endpoints WHERE beacon_id=? AND repository_identifier=? AND ip=?', (beacon_id, repository_identifier, ip))
						oldversion = c.fetchone()[0].encode()
						try:
							if oldversion != ojs_version:
								c.execute("INSERT INTO upgrades (beacon_id, repository_identifier, ip, oldversion, newversion, date_hit) VALUES(?,?,?,?,?,?)", (beacon_id, repository_identifier, ip, oldversion, ojs_version, date_hit))
						except lite.IntegrityError:
							pass

						c.execute('UPDATE endpoints SET last_hit=?, enabled = 1 WHERE beacon_id=? AND repository_identifier=? AND ip=?', (date_hit, beacon_id, repository_identifier, ip))

					oai_list_sets_url = re.sub("verb=Identify", "verb=ListSets", oai_url)
					journals = get_journals(oai_list_sets_url)

					for journal in journals:
						setSpec, setName = journal

						# only those setSpecs without a : are journals (with : they are sections)
						if not re.search(":", setSpec):
							journal_endpoint = find_journal_endpoint(oai_url, setSpec)
							if journal_endpoint is None:
								continue
							else:
								journal_contact = find_journal_contact(journal_endpoint)

							try:
								c.execute("INSERT INTO journals (repository_identifier, ip, setSpec, setName, first_hit, last_hit, contact) VALUES(?,?,?,?,?,?,?)", (repository_identifier, ip, setSpec, setName, date_hit, date_hit, journal_contact))
								archive_id = int(c.lastrowid)
								# generate and insert legacy "archive id" from old harvester codepaths; still used for lookups
								c.execute("UPDATE journals SET archive_id=? WHERE repository_identifier=? AND ip=? AND setSpec=?", (archive_id, repository_identifier, ip, setSpec))

							except lite.IntegrityError:
								print("Already had %s" % setSpec)
								# on failed to insert, update the last hit date
								c.execute("UPDATE journals SET last_hit=? WHERE repository_identifier=? AND ip=? AND setSpec=?", (date_hit, repository_identifier, ip, setSpec))
				except Exception as e:
					with open("data/checkOJSlog.txt", "a") as logfile:
						logfile.write("%s failed for  %s\n" % (e, oai_url))


def country_lookup():
	country_from_title = {}
	wb_country_info = {}
	iso2_to_iso3 = {}
	reader = geoip2.database.Reader('GeoLite2-Country.mmdb')

	country_stop_words = ['islands', 'saint', 'and', 'republic', 'virgin', 'united', 'south', 'of', 'new', 'the']

	response = requests.get("http://api.worldbank.org/countries?per_page=400&format=json" )
	wb_country_data = response.json()[1]

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
		c = litecon.cursor()
		c.execute("SELECT repository_identifier, setSpec, setName, archive_id, ip FROM journals")
		journals = c.fetchall()

		for journal in journals:
			repository_identifier, setSpec, setName, archive_id, ip = journal

			try:
				match = reader.country(ip)
				if match.country.names:
					journal_geoip = match.country.names["en"].lower()
				else:
					journal_geoip = None
			except geoip2.errors.AddressNotFoundError:
				journal_geoip = None

			if setName is not None:
				country_in_title = find_country_in_title(journal, country_from_title, nat_to_iso3)
			else:
				country_in_title = None

			c.execute("SELECT oai_url FROM endpoints WHERE repository_identifier=? AND ip=?", (repository_identifier, ip))
			oai_url = c.fetchone()[0]
			
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
				c.execute("INSERT INTO locales (archive_id, tld, country_in_title, geo_ip, country, region_id, region_name) VALUES(?,?,?,?,?,?,?)", (archive_id, tld, country_in_title, journal_geoip, country, region_id, region_name))
			except:
				c.execute("UPDATE locales SET tld=?, country_in_title=?, geo_ip=?, country=?, region_id=?, region_name=? WHERE archive_id = ?", (tld, country_in_title, journal_geoip, country, region_id, region_name, archive_id))


def harvest():
	journals_per_year = collections.Counter()
	articles_per_year = collections.Counter()
	hosts_per_year = {str(k): [] for k in range(1990,(int(time.strftime("%Y")) + 1))}
	sampled_years = ["%03d" % a for a in range(1990,(int(time.strftime("%Y")) + 1))]

	with litecon:
		c = litecon.cursor()
		c2 = litecon.cursor()

		dates_csv = open("data/all_articles_by_date.csv", "w", newline='')
		dates_writer = csv.DictWriter(dates_csv, fieldnames=sampled_years)
		dates_writer.writeheader()

		countries_csv = open("data/journals_per_country.csv", "w", newline='')
		countries_writer = csv.writer(countries_csv)
		countries_writer.writerow(["year", "country", "region_id", "region_name", "archive_id"])

		counts_csv = open("data/ojs_counts.csv", "w", newline='')
		counts_writer = csv.writer(counts_csv)
		counts_writer.writerow(["year", "journals", "articles", "hosts", "avgnumarts"])

		for row in c.execute("SELECT repository_identifier, setSpec, setName, ip, archive_id FROM journals"):
			ojs = dict(zip(["repository_identifier", "setSpec", "title", "ip", "archive_id"], row))

			if ojs["title"] is None:
				with open("data/checkOJSlog.txt", "a") as logfile:
					logfile.write("Title missing for %s\n" % (ojs["archive_id"],))
				continue

			c2.execute("SELECT oai_url, last_hit FROM endpoints WHERE repository_identifier=? AND ip=? AND enabled = 1", (ojs["repository_identifier"], ojs["ip"]))
			try: 
				oai_url, last_hit = c2.fetchone()
			except: 
				with open("data/checkOJSlog.txt", "a") as logfile:
					logfile.write("Endpoint lookup failed for %s\n" % (ojs["archive_id"],))
				continue

			delta = dt.datetime.today() - dt.datetime.strptime(last_hit, "%m/%d/%Y")
			if delta.days > 30:
				with open("data/checkOJSlog.txt", "a") as logfile:
					logfile.write("%s not hit in the last 30 days\n" % (ojs["archive_id"],))
				continue

			ojs["oai_endpoint"] = find_journal_endpoint(oai_url, ojs["setSpec"])
			if ojs["oai_endpoint"] is None:
				with open("data/checkOJSlog.txt", "a") as logfile:
					logfile.write("Couldn't find endpoint for %s\n" % (ojs["archive_id"],))
				continue

			pub_years = []
			# remove verb=Identify for sickle
			sickle = Sickle(ojs["oai_endpoint"][:-14])
			try:
				records = sickle.ListRecords(metadataPrefix="nlm", ignore_deleted=True)
			except:
				with open("data/checkOJSlog.txt", "a") as logfile:
					logfile.write("List records call failed for %s\n" % (ojs["archive_id"],))
				continue

			while records:
				try:
					try:
						record = records.next()
					except:
						break

					if "year" not in record.metadata.keys():
						try:
							year = parse(record.metadata["date"][0]).strftime('%Y')
						except KeyError:
							break
					else:
						match = re.search(r"(1\d{3}|20\d{2})", record.metadata["year"][0])
						if match:
							year = match.group(0)
					pub_years.append(year)

				except StopIteration:
					break

			year_count = collections.Counter()
			for pub_year in pub_years:
				if pub_year in sampled_years:
					year_count[pub_year] += 1

			dates_writer.writerow(year_count)

			for pub_year in year_count:
				if year_count[pub_year] >= 10:
					articles_per_year[pub_year] += year_count[pub_year]
					hosts_per_year[pub_year].append(oai_url)
					journals_per_year[pub_year] += 1
					c2.execute("SELECT country, region_id, region_name FROM locales WHERE archive_id=?", (ojs["archive_id"],))
					try:
						locale = dict(zip(["country", "region_id", "region_name"], c2.fetchone()))
						countries_writer.writerow([pub_year, locale["country"], locale["region_id"], locale["region_name"], ojs["archive_id"]])
					except:
						print("region lookup issue for " + str(ojs["archive_id"]))


		dates_csv.close()
		countries_csv.close()

		for year in sampled_years:
			counts_writer.writerow([year, journals_per_year[year], articles_per_year[year], len(set(hosts_per_year[year])), (articles_per_year[year]/journals_per_year[year])])
		counts_csv.close()


if __name__ == "__main__":
	os.makedirs('data', exist_ok=True)
	litecon = lite.connect('data/ojs_oai.db')
	arguments = docopt(__doc__)

	with litecon:
		c = litecon.cursor()
		# update old schema
		try:
			c.execute("ALTER TABLE endpoints ADD COLUMN beacon_id TEXT")
			c.execute("ALTER TABLE upgrades ADD COLUMN beacon_id TEXT")
		except:
			pass
		c.execute("CREATE TABLE IF NOT EXISTS endpoints (beacon_id TEXT, oai_url TEXT, repository_identifier TEXT, first_hit TEXT, last_hit TEXT, ip TEXT, version TEXT, enabled INTEGER)")
		c.execute("CREATE UNIQUE INDEX IF NOT EXISTS id_plus_ip ON endpoints (repository_identifier, ip)")
		c.execute("CREATE UNIQUE INDEX IF NOT EXISTS beacon ON endpoints (beacon_id)")

		c.execute("CREATE TABLE IF NOT EXISTS journals (repository_identifier TEXT, ip TEXT, setSpec TEXT, setName TEXT, first_hit TEXT, last_hit TEXT, contact TEXT, archive_id INTEGER)")
		c.execute("CREATE UNIQUE INDEX IF NOT EXISTS id_plus_ip_plus_spec ON journals (repository_identifier, ip, setSpec)")

		c.execute("CREATE TABLE IF NOT EXISTS upgrades (beacon_id TEXT, repository_identifier TEXT, ip TEXT, oldversion TEXT, newversion TEXT, date_hit TEXT)")
		
		c.execute("CREATE TABLE IF NOT EXISTS locales (archive_id TEXT, tld TEXT, country_in_title TEXT, geo_ip TEXT, country TEXT, region_id TEXT, region_name TEXT)")
		c.execute("CREATE UNIQUE INDEX IF NOT EXISTS locale_index ON locales (archive_id)")

	if not arguments["--onlyharvest"]:
		beacon_log_parser(arguments["--logpath"])
	if arguments["--onlylogparse"]:
		quit()
	country_lookup()
	harvest()