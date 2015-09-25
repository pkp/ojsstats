# git pull, then parse logs on Mondays
50 9 * * 1 cd /home/pkp_tracker/ojsstats; git pull; cp d3/* /var/www/html/pkp_www/files/ojsstats/d3/.; /usr/bin/php pkp-log-parser.php;

# query journals and insert into SQLite on Tuesdays (this takes ~18h to run from scratch, less so if already populated)
3 3 * * 2 cd /home/pkp_tracker/ojsstats; rm data/ojs_split_logs*; split -l 1500 data/ojs_in_logs.csv data/ojs_split_logs_; for x in $(find data -name ojs_split_logs*); do python -u checkOJS.py $x &> $(echo $x | sed -e 's/ojs_split/python_out/g') & done

# insert into harvester on Wednesdays, then add country data
30 22 * * 3 cd /home/pkp_tracker/ojsstats; python harvesterInsert.py; python countryLookup.py

# harvester cron looks like this:
# 45 23 * * 3  /home/pkp/harvest/harvest-all-parallel.sh

# on Thursdays, grab some data from the Harvester, then crunch numbers
30 23 * * 4 cd /home/pkp_tracker/ojsstats; mysql -u harvester2_pkp -h 192.168.24.80 -p$HARVESTER_SQL_PASSWORD harvester2_pkp -e"set names utf8; SELECT record_id, archive_id, CAST(getTagContents(contents, 'dc:date', '; ') AS DATE) as dcdate, CAST(getTagContents(contents, 'dc:source', '; ') AS CHAR(1023)) as source FROM records;" > data/dates.txt; mysqldump -u harvester2_pkp -h 192.168.24.80 -p$HARVESTER_SQL_PASSWORD harvester2_pkp archive_settings > data/archive_settings.sql; python mysqldump_to_csv.py data/archive_settings.sql > data/archive_settings.csv; scl enable python27 "python statscrunch.py"

# finally, on Friday mornings, copy the output data to where d3 can use it, and save old numbers
30 10 * * 5 bash -c "cp /home/pkp_tracker/ojsstats/data/ojs_counts.csv /var/www/html/pkp_www/files/ojsstats/data/ojs_counts.csv; cp /home/pkp_tracker/ojsstats/data/journals_per_country.csv /var/www/html/pkp_www/files/ojsstats/data/journals_per_country.csv; export TODAY=$(date +'%m-%d-%Y'); cp /home/pkp_tracker/ojsstats/data/ojs_counts.csv /home/pkp_tracker/ojsstats/data/old/ojs_counts/$TODAY; cp /home/pkp_tracker/ojsstats/data/journals_per_country.csv /home/pkp_tracker/ojsstats/data/old/journals_per_country/$TODAY"
