
# In[ ]:

import sys, re, os, gc
import difflib, random
import pandas as pd
import numpy as np
import csv, json
from unidecode import unidecode

import sqlite3 as lite

from datetime import date, timedelta


# In[ ]:

record_dates = pd.read_csv('data/dates.txt', sep="\t")
record_dates.columns = ['record_id', 'archive_id','dcdate', 'source']
record_dates.set_index('archive_id', inplace=True)


# In[ ]:

archive_settings  = pd.read_csv('data/archive_settings.csv', encoding='utf8', escapechar='\\')
archive_settings.columns = ['archive_id','setting_name', 'setting_value', 'type']
archive_settings.set_index('archive_id', inplace=True)
lastIndexedDate = archive_settings[archive_settings.setting_name == 'lastIndexedDate'][['setting_value']]
lastIndexedDate.columns=['lastIndexedDate']


# In[ ]:

record_dates = record_dates.merge(lastIndexedDate, how="left", left_index=True, right_index=True)


# In[ ]:

# remove stuff we haven't harvested in the last 30 days
record_dates = record_dates[record_dates.lastIndexedDate >= (date.today() - timedelta(days=30)).strftime("%Y-%m-%d")]


# In[ ]:

litecon = lite.connect('data/ojs_oai.db')
countries = pd.read_sql("select archive_id, country, region_id, region_name from locales", litecon, index_col='archive_id')
countries.index = countries.index.astype(int)


# In[ ]:

record_dates = record_dates.merge(countries, how="left", left_index=True, right_index=True)


# In[ ]:

installations = pd.read_sql("select archive_id, repository_identifier, ip from journals", litecon, index_col='archive_id')
installations['install_id'] = installations.apply(lambda row: "%s_%s" % (row['repository_identifier'], row['ip']), axis=1)
del installations['repository_identifier']
del installations['ip']


# In[ ]:

record_dates = record_dates.merge(installations, how="left", left_index=True, right_index=True)


# In[ ]:

record_dates = record_dates.reset_index().set_index('record_id')


# In[ ]:

# archive_settings cleanup to make Alex happy
try:
    del archive_settings
    del lastIndexedDate
    del countries
    del installations
    cleanedup = gc.collect()
except:
    pass


# In[ ]:

year_regex = re.compile('.*(?:[^\d\-]|^)((?:1\d|20)\d{2})(?:\)|\;|$).*')

# pull the year out of the ( ) if it is present
def find_best_year(y, s):
    try:
        y = int(y)
        if not (y <= date.today().year and y > 1000):
            y = None  # this means an invalid year in dcdate
    except:
        y = None

    try:
        r=year_regex.match(s)
        year_in_source = int(r.group(1))
        if year_in_source <= date.today().year and year_in_source > 1000:
            y = year_in_source
    except:
        pass

    return y
# We're doing chained assignment somewhere here, but its not a problem, so turn off warning
pd.options.mode.chained_assignment = None

#
# a simple attempt at fixing wrong publication years by pulling a year from the source
#
record_dates['year'] = record_dates.dcdate.astype(str).map(lambda x: x[0:4])
record_dates['year'] = record_dates.apply(lambda row: find_best_year(row['year'], row['source']), axis=1)

# cleanup the years column
record_dates = record_dates[record_dates.year > 0] # remove things that still have no date

# and cast column to int to remove .0 from the end when it gets turned to str later
record_dates['year'] = record_dates.year.astype(int)


# update dates that are likely to be in the islamic calendar
record_dates['year'] = record_dates.year.map(lambda x: x if ((x <= date.today().year) and (x >= 1900 - 622)) else x + 622)


# In[ ]:

# grab only those journals that have at least x articles in that year
last_year = date.today().year - 1

def filter_by_num_articles(n):
    grouped=record_dates.reset_index().groupby(['year', 'archive_id'])

    filtered = grouped.filter(lambda x: len(x) >= n)

    journals_data = filtered.ix[:,['archive_id', 'year']]
    journals_data.to_csv('data/journals_with_%s_articles_any_year.csv' % n)

    journals_data = filtered[filtered['year'] == last_year].ix[:,['archive_id','year']]
    journals_data.to_csv('data/journals_with_%s_articles_%s.csv' % (n, last_year))

    return filtered, journals_data

filtered, journals_data = filter_by_num_articles(10)
print len(filtered)


# In[ ]:

countdata = {}
articles_per_journal = {}
# record_dates = record_dates[record_dates.year >= 1990]
last_year = date.today().year - 1
for year in map(int, sorted(record_dates.year.unique())):
    if year < 1990 or year > last_year:
        continue

    count_journals = len(filtered[filtered["year"]==year].archive_id.unique())
    count_articles = len(filtered[filtered["year"]==year])
    count_hosts = len(filtered[filtered["year"]==year].install_id.unique())

    # num_journals, num_articles, num_hosts
    countdata[year] = [count_journals, count_articles, count_hosts]

    # get number of articles per journal per year
    # count, mean, std, min, 25%, 50%, 75%, max
    articles_per_journal[year] = record_dates[record_dates['year']==year].groupby('archive_id').size().describe().tolist()


# write the journal/article/hosts count
f = open('data/ojs_counts.csv', 'wb')
csvWriter = csv.writer(f)
csvWriter.writerow(['year', 'journals', 'articles', 'hosts'])
for year, data in countdata.iteritems():
    csvWriter.writerow([year] + data)
f.close()

# write the articles per year counts
f = open('data/articles_per_journal.csv', 'wb')
csvWriter = csv.writer(f)
csvWriter.writerow(['year', 'count', 'mean', 'std', 'min', 'p25', 'p50', 'p75', 'max'])
for year, data in articles_per_journal.iteritems():
    csvWriter.writerow([year] + data)
f.close()

# write the number of journals per country
filtered.groupby(['year', 'country', 'region_id', 'region_name']).archive_id.unique().apply(len).to_csv('data/journals_per_country.csv', header=True)
