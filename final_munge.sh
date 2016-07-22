#!/bin/bash

cp /home/pkp_tracker/ojsstats/data/ojs_counts.csv /var/www/html/pkp_www/files/ojsstats/data/ojs_counts.csv
cp /home/pkp_tracker/ojsstats/data/journals_per_country.csv /var/www/html/pkp_www/files/ojsstats/data/journals_per_country.csv
cp /home/pkp_tracker/ojsstats/data/all_journals.csv /var/www/html/pkp_www/files/ojsstats/data/all_journals.csv
export TODAY=$(date +"%m-%d-%Y")
cp /home/pkp_tracker/ojsstats/data/ojs_counts.csv /home/pkp_tracker/ojsstats/data/old/ojs_counts/$TODAY
cp /home/pkp_tracker/ojsstats/data/journals_per_country.csv /home/pkp_tracker/ojsstats/data/old/journals_per_country/$TODAY
cp /home/pkp_tracker/ojsstats/data/all_journals.csv /home/pkp_tracker/ojsstats/data/old/all_journals/$TODAY