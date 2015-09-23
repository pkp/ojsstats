import sys
import sqlite3 as lite
import MySQLdb as mdb
import MySQLdb.cursors as cursors
from config import harvester_sql_password

import re

#litecon = lite.connect('data/ojs_oai.db')

try:
	# connect
	# ve must use ze SS or else ve have ze timeout!
	main_con = mdb.connect(host = '192.168.24.80', user = 'harvester2_pkp', passwd = harvester_sql_password, db = 'harvester2_pkp', use_unicode=True, charset="utf8", cursorclass=cursors.SSCursor)
	cur = main_con.cursor()

	lookup_con = mdb.connect(host = '192.168.24.80', user = 'harvester2_pkp', passwd = harvester_sql_password, db = 'harvester2_pkp', use_unicode=True, charset="utf8")
	cur2 = lookup_con.cursor()

except mdb.Error, e:
	print "Error %d: %s" % (e.args[0],e.args[1])
	sys.exit(1)


cur.execute("SELECT record_id, archive_id, CAST(getTagContents(contents, 'dc:identifier', '; ') AS CHAR(1023)) as article_url FROM records")

removed_from_archive_ids = set()
added_to_archive_ids = set()
fix_count = 0

for row in cur:
	record_id = row[0]
	archive_id = row[1]
	article_url = row[2]

	if re.search("page=article", article_url):
		journal_url = re.sub("&page=article.*", (""), article_url)
	else:
		journal_url = re.sub("/article/view.*", "", article_url)

	cur2.execute("SELECT archive_id FROM archives WHERE url = %s", journal_url)
	try:
		archive_id_by_url = cur2.fetchone()[0]
		print archive_id
		if archive_id_by_url != archive_id:
			# cur2.execute("UPDATE records SET archive_id = ? WHERE record_id = ?", (row[0], record_id))
			print "Updated record: %s from %s to %s" % (record_id, archive_id, archive_id_by_url)
			removed_from_archive_ids.add(archive_id)
			added_to_archive_ids.add(archive_id_by_url)
			fix_count += 1
	except:
		print "did not find: %s" % journal_url
		exit(1)




print "Removed from %s archives" % len(removed_from_archive_ids)
print "Added to %s archives" % len(added_to_archive_ids)
print "modified %s records" % fix_count
