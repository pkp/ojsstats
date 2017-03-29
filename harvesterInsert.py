# coding: utf-8
import sys
import sqlite3 as lite
import MySQLdb as mdb
from config import harvester_sql_password

import re

litecon = lite.connect('data/ojs_oai.db')

con = None
try:
	# connect
	con = mdb.connect(host = '192.168.24.80', user = 'harvester2_pkp', passwd = harvester_sql_password, db = 'harvester2_pkp', use_unicode=True, charset="utf8")

	cur = con.cursor()

except mdb.Error, e:
	print "Error %d: %s" % (e.args[0],e.args[1])
	sys.exit(1)


def insert(title, ip, journal_url, journal_oai_endpoint):
	cur.execute("SELECT a.archive_id FROM archives a JOIN archive_settings s ON (a.archive_id = s.archive_id) WHERE a.url = %s AND s.setting_name = 'ip' and s.setting_value = %s", (journal_url, ip))

	check = cur.fetchone()

	if check:
		# double check we aren't inserting duplicate URL's
		# the above should always return false, since we're keeping track in sqlite when an insert succeeds
		return check[0]

	try:
		cur.execute("INSERT INTO archives (harvester_plugin, schema_plugin, user_id, title, url, enabled) VALUES (%s, %s, %s, %s, %s, %s)", ('OAIHarvesterPlugin', 'DublinCorePlugin', 1, title, journal_url, 1))

		archive_id = cur.lastrowid

		cur.execute("INSERT INTO archive_settings (archive_id, setting_name, setting_type, setting_value) VALUES (LAST_INSERT_ID(), %s, %s, %s)", ('oaiIndexMethod', 'string', 1))
		cur.execute("INSERT INTO archive_settings (archive_id, setting_name, setting_type, setting_value) VALUES (LAST_INSERT_ID(), %s, %s, %s)", ('ip', 'string', ip))
		cur.execute("INSERT INTO archive_settings (archive_id, setting_name, setting_type, setting_value) VALUES (LAST_INSERT_ID(), %s, %s, %s)", ('harvesterUrl', 'string', journal_oai_endpoint))

		con.commit()

	except Exception as e:
		# something went wrong, it shouldn't have
		# by returning false, we guarantee an insert will be attempted again next time around
		print e
		return False

	return archive_id


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


with litecon:
	litecur = litecon.cursor()
	litecur.execute("SELECT repository_identifier, setSpec, setName, ip FROM journals WHERE archive_id IS NULL")
	# this will be big-ish in memory but shouldn't be a major issue, the whole SQLite db is about 60mb after one full run.
	journals = litecur.fetchall()

	for journal in journals:
		repository_identifier = journal[0]
		setSpec = journal[1]
		if journal[2] is not None:
			title = journal[2]
		else:
			title = "NoTitle"
		ip = journal[3]

		if not title:
			continue

		litecur.execute("SELECT oai_url FROM endpoints WHERE repository_identifier=? AND ip=? AND enabled = 1", (repository_identifier, ip))
		
		endpoint = litecur.fetchone()
		oai_url = endpoint[0]

		journal_endpoint = find_journal_endpoint(oai_url, setSpec)
		journal_url = find_journal_url(oai_url, setSpec)

		archive_id = insert(title, ip, journal_url, journal_endpoint)

		if not archive_id:
			# failed to insert, so move onto next journal (will be tried again next time)
			continue

		# add archive_id to journals table in sqlite
		with litecon:
			litecur = litecon.cursor()
			litecur.execute("UPDATE journals SET archive_id=? WHERE repository_identifier=? AND ip=? AND setSpec=?", (archive_id, repository_identifier, ip, setSpec))


# disable everything that needs to be disabled
with litecon:
	litecur = litecon.cursor()
	litecur.execute("SELECT archive_id FROM journals j JOIN endpoints e ON (j.repository_identifier = e.repository_identifier AND j.ip = e.ip) WHERE e.enabled = 0 and j.archive_id IS NOT NULL")
	# this will be big-ish in memory but shouldn't be a major issue, the whole SQLite db is about 60mb after one full run.
	journals = litecur.fetchall()

	for journal in journals:
		archive_id = journal[0]
		cur.execute("UPDATE archives SET enabled = 0 WHERE archive_id = %s", (archive_id))

		
