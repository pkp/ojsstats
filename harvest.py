from dateutil.parser import parse
from sickle import Sickle
import time
import sqlite
import csv
import re

db = sqlite3.connect('data/ojs_oai.db')
c = db.cursor()
c2 = db.cursor()
dates_csv = open("data/dates.csv", "w")
writer = csv.DictWriter(dates_csv, fieldnames=list(range(1990,(int(time.strftime("%Y")) + 1))))
writer.writeheader()

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
	writer.writerow(final_count)

dates_csv.close()