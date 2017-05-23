import re
import csv
import urllib2
import socket
from xml.etree import ElementTree as ET
import sqlite3 as lite
import datetime as dt
import sys


litecon = lite.connect('data/ojs_oai.db')


with litecon:

# set up SQL tables
	litecur = litecon.cursor()
	litecur.execute("CREATE TABLE IF NOT EXISTS endpoints (oai_url TEXT, repository_identifier TEXT, first_hit TEXT, last_hit TEXT, ip TEXT, version TEXT, enabled INTEGER)")
# unique index on repository id + ip address
	litecur.execute("CREATE UNIQUE INDEX IF NOT EXISTS id_plus_ip ON endpoints (repository_identifier, ip)")

	litecur.execute("CREATE TABLE IF NOT EXISTS journals (repository_identifier TEXT, ip TEXT, setSpec TEXT, setName TEXT, first_hit TEXT, last_hit TEXT, contact TEXT, archive_id INTEGER)")
# unique index on oai url + setSpec
	litecur.execute("CREATE UNIQUE INDEX IF NOT EXISTS id_plus_ip_plus_spec ON journals (repository_identifier, ip, setSpec)")
	litecur.execute("CREATE TABLE IF NOT EXISTS upgrades(repository_identifier TEXT, ip TEXT, oldversion TEXT, newversion TEXT, date_hit TEXT)")


def find_oai_endpoint(url):
	''' Finds an OAI endpoint given a base OJS-install URL '''

	url = url.strip("/")
	urls_to_try = []  # all the combinations of possible OAI URLs, given the base url
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
			print "Going after: %s" % url_to_try
			request = urllib2.Request(url_to_try,headers={'User-Agent' : "PKP using urllib2"})
			response = urllib2.urlopen(request, timeout=180)
			oai_xml = response.read()
		except urllib2.HTTPError:
			continue	# move onto next URL
		except urllib2.URLError:
			continue 	# move onto next URL
		except:
			# some other error, but probably still OK to ignore
			# because it was thrown by urllib2, which means the URL did not work
			continue # move onto next URL

		try:

			oai_xml_tree = ET.fromstring(oai_xml)
		except:
			# invalid XML means we can move onto next URL
			continue # move onto next URL

		# this is really inefficient and I'll use proper xpath later
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
			print "Failed to get IP of a valid URL: %s" % url_without_http
			continue

		oai_url = url_to_try
		break

	# if we didn't find a repo, do not return a list
	if repository_id_xml_block is False or oai_url is False:
		return False

	if not repository_identifier:
		repository_identifier = ip + re.sub("http://[^/]+/", "/", oai_url)

	# this should probably be a proper dict but it's a list for now
	return [oai_url.lower(), repository_identifier, date_hit, ip, ojs_version]


def get_journals(oai_list_sets_url):
	''' Hit an installations OAI endpoint for the list of "sets" (journals) '''
	spec_name_pairs = []
	while True:
		token = None
		try:
			request = urllib2.Request(oai_list_sets_url,headers={'User-Agent' : "PKP using urllib2"})
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


def verify_not_missing_journal(journal_endpoint, setSpec):
	testing_url = (re.sub("verb=Identify", "verb=ListRecords&metadataPrefix=oai_dc&set=", journal_endpoint) + setSpec)
	request = urllib2.Request(testing_url, headers={'User-Agent' : "PKP using urllib2"})
	response = urllib2.urlopen(request, timeout=180)
	oai_xml = response.read()
	# parsing XML with regex yeaaaaaaaaaaah [air guitar]
	if re.search("noRecordsMatch", oai_xml):
		return True

	return False

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
		request = urllib2.Request(journal_endpoint, headers={'User-Agent' : "PKP using urllib2"})
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


with open(sys.argv[1], 'rb') as ojslogs:
	logreader = csv.reader(ojslogs)
	for row in logreader:
		base_url = row[0] # row[0] has the potential OJS base_url extracted form logs
		oai_data = find_oai_endpoint(base_url)

		print oai_data
		if not oai_data:
			with open("data/checkOJSlog.txt", "a") as logfile:
				logfile.write("couldn't hit endpoint for %s\n" % base_url)

			continue

		# oai_data is a list with the following: [oai_url.lower(), repository_identifier, date_hit, ip, ojs_version]
		oai_url = oai_data[0]
		repository_identifier = oai_data[1]
		date_hit = oai_data[2]
		ip = oai_data[3]
		ojs_version = oai_data[4]

		try:
			with litecon:
				litecur = litecon.cursor()
				try:
					# disable any old IP addresses for this domain name
					litecur.execute("UPDATE endpoints SET enabled=0 WHERE oai_url=? AND ip!=?", (oai_url, ip))

					litecur.execute("INSERT INTO endpoints (oai_url, repository_identifier, first_hit, last_hit, ip, version, enabled) VALUES(?,?,?,?,?,?,?)", (oai_url, repository_identifier, date_hit, date_hit, ip, ojs_version, 1))

				except lite.IntegrityError:

					print "already had %s:%s" % (repository_identifier, ip)
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

						except lite.IntegrityError:
							print "Already had %s" % setSpec
							# on failed to insert, update the last hit date
							litecur.execute("UPDATE journals SET last_hit=? WHERE repository_identifier=? AND ip=? AND setSpec=?", (date_hit, repository_identifier, ip, setSpec))
		except:
			with open("data/checkOJSlog.txt", "a") as logfile:
				logfile.write("something failed other than looking up URL for %s\n." % oai_url)
