import re
import sqlite3 as lite
import sys
import urllib2
import json
import random
from geoip import geolite2
# pip install python-geoip-geolite2

from tld import get_tld
# pip install tld

litecon = lite.connect('data/ojs_oai.db')


with litecon:

# set up SQL table
	litecur = litecon.cursor()
	litecur.execute("CREATE TABLE IF NOT EXISTS locales (archive_id TEXT, tld TEXT, country_in_title TEXT, geo_ip TEXT, country TEXT, region_id TEXT, region_name TEXT)")
	litecur.execute("CREATE UNIQUE INDEX IF NOT EXISTS locale_index ON locales (archive_id)")


# prep for finding country from title
country_from_title = {}
wb_country_info = {}
iso2_to_iso3 = {}

country_stop_words = ['islands', 'saint', 'and', 'republic', 'virgin', 'united', 'south', 'of', 'new', 'the']


request = urllib2.Request("http://api.worldbank.org/countries?per_page=400&format=json" ,headers={'User-Agent' : "PKP using urllib2"})
response = urllib2.urlopen(request, timeout=30)
wb_country_data = json.load(response)[1]

for country in wb_country_data:
	if country['region']['value'] == 'Aggregates': continue

	iso3 = country['id'].lower()
	wb_country_info[iso3] = {'iso2': country['iso2Code'].lower(), 'name': country['name'], 'region_id': country['region']['id'], 'region_name': country['region']['value']}
	# print country
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

def find_country_in_title(journal):
	if journal[3] in country_from_title:
		return country_from_title[journal[3]][1]

	# randomly sort the haystack since we're returning the first match
	# so we're not favouring matches in alphabetical order
	for key, value in sorted(nat_to_iso3.items(), key=lambda x: random.random()):
		if journal[2].lower().find(key.lower()) >= 0:
			country_from_title[journal[3]] = (key, value)
			# print row['archive_title'], key, value
			return value

	return None


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
	# this needs to run after harvester insert so archive_id is present
	journals = litecur.fetchall()

	# this code block is duplicated from harvester insert, could probably make it run at the end of that script
	for journal in journals:
		repository_identifier = journal[0]
		setSpec = journal[1]
		setName = journal[2]
		archive_id = journal[3]
		ip = journal[4]

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
