# -*- coding: utf-8 -*-
# <nbformat>3.0</nbformat>

# <codecell>

import sys, re, os, gc
import difflib, random
import pandas as pd
import numpy as np
import csv, json
from unidecode import unidecode

import sqlite3 as lite

from datetime import date, timedelta

# <codecell>

record_dates = pd.read_csv('data/dates.txt', sep="\t")
record_dates.columns = ['record_id', 'archive_id','dcdate', 'source']
record_dates.set_index('archive_id', inplace=True)

# <codecell>

archive_settings  = pd.read_csv('data/archive_settings.csv', encoding='utf8', escapechar='\\')
archive_settings.columns = ['archive_id','setting_name', 'setting_value', 'type']
archive_settings.set_index('archive_id', inplace=True)
lastIndexedDate = archive_settings[archive_settings.setting_name == 'lastIndexedDate'][['setting_value']]
lastIndexedDate.columns=['lastIndexedDate']
recordCount = archive_settings[archive_settings.setting_name == 'recordCount'][['setting_value']]
recordCount.columns=['recordCount']

def find_journal_url(oai_url):
	if oai_url.find("page=oai") > 0:
		journal_url = re.sub('page=oai.*', '', oai_url)
	else:
		journal_url = re.sub('/oai.*?$', '', oai_url)

	return journal_url

harvesterUrl = archive_settings[archive_settings.setting_name == 'harvesterUrl'][['setting_value']]
harvesterUrl.columns=['url']
harvesterUrl['url'] = harvesterUrl.url.apply(find_journal_url)

# <codecell>

record_dates = record_dates.merge(lastIndexedDate, how="left", left_index=True, right_index=True)

# <codecell>

record_dates = record_dates.merge(recordCount, how="left", left_index=True, right_index=True)

# <codecell>

record_dates = record_dates.merge(harvesterUrl, how="left", left_index=True, right_index=True)

# <codecell>

# remove stuff we haven't harvested in the last 30 days
record_dates = record_dates[record_dates.lastIndexedDate >= (date.today() - timedelta(days=30)).strftime("%Y-%m-%d")]

# <codecell>

litecon = lite.connect('data/ojs_oai.db')
countries = pd.read_sql("select archive_id, country, region_id, region_name from locales", litecon, index_col='archive_id')
countries.index = countries.index.astype(int)

# <codecell>

record_dates = record_dates.merge(countries, how="left", left_index=True, right_index=True)

# <codecell>

installations = pd.read_sql("select archive_id, repository_identifier, ip, setName as journal_title, contact from journals", litecon, index_col='archive_id')
installations['install_id'] = installations.apply(lambda row: "%s_%s" % (row['repository_identifier'], row['ip']), axis=1)
del installations['repository_identifier']
del installations['ip']

# <codecell>

record_dates = record_dates.merge(installations, how="left", left_index=True, right_index=True)

# <codecell>

record_dates = record_dates.reset_index().set_index('record_id')

# <codecell>

# archive_settings cleanup to make Alex happy
try: 
    del archive_settings
except:
    pass

try:
    del lastIndexedDate
except:
    pass

try:
    del recordCount
except:
    pass

try:
    del countries
except:
    pass    

try:
    del installations
except:
    pass    

cleanedup = gc.collect()

# <codecell>

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

# <codecell>

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

def filter_by_num_articles_last_two_years(n): 
    archive_ids = record_dates[record_dates.year.between(last_year-2, last_year-1)].groupby('archive_id').filter(lambda x: len(x) >= n).archive_id.unique()
    filtered = record_dates[record_dates.archive_id.isin(archive_ids)]
    return filtered

article_threshold = 10
filtered, journals_data = filter_by_num_articles(article_threshold)
# filtered = filter_by_num_articles_last_two_years(article_threshold)

# <codecell>

countdata = {}
articles_per_journal = {}
# record_dates = record_dates[record_dates.year >= 1990]
if date.today().month > 4: 
    last_year = date.today().year - 1
else:
    last_year = date.today().year - 2
    
for year in map(int, sorted(record_dates.year.unique())):
    if year < 1990 or year > last_year:
        continue
        
    count_journals = len(filtered[filtered["year"]==year].archive_id.unique())
    count_articles = len(filtered[filtered["year"]==year])
    count_hosts = len(filtered[filtered["year"]==year].install_id.unique())
    avg_articles_per_journal = filtered[filtered['year']==year].groupby(['year', 'archive_id']).apply(len).mean()

    # num_journals, num_articles, num_hosts
    countdata[year] = [count_journals, count_articles, count_hosts, avg_articles_per_journal]

    # get number of articles per journal per year
    # count, mean, std, min, 25%, 50%, 75%, max
    articles_per_journal[year] = record_dates[record_dates['year']==year].groupby('archive_id').size().describe().tolist()

print "Total number of journals in %s: %s" % (year, count_journals)

# write the journal/article/hosts count
f = open('data/ojs_counts.csv', 'wb')
csvWriter = csv.writer(f)
csvWriter.writerow(['year', 'journals', 'articles', 'hosts', 'avgnumarts'])
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
filtered_country = filtered.groupby(['year', 'country', 'region_id', 'region_name']).archive_id.unique().apply(len)
filtered_country.to_csv('data/journals_per_country.csv', header=True)

# <codecell>

all_journals = record_dates[['archive_id', 'journal_title', 'url', 'contact', 'lastIndexedDate', 'recordCount', 'country', 'region_name']].set_index('archive_id', drop=True).drop_duplicates()

# <codecell>

for y in countdata: 
    all_journals[y] = all_journals.index.isin(filtered[filtered["year"] == y].archive_id)

all_journals['any_year'] = all_journals.index.isin(filtered[filtered["year"].between(min(countdata.keys()), max(countdata.keys()))].archive_id)

# <codecell>

all_journals.to_csv('data/all_journals.csv', header=True, encoding='utf8')

# <codecell>

print "Number of reachable installations: %s" % len(record_dates.install_id.unique())
print "Number of countries: %s" % len(record_dates.country.unique())
print "Number of world regions: %s" % len(record_dates.region_name.unique())

print "Number of journals with > %s articles in previous two years: %s" % (article_threshold, len(filtered.archive_id.unique()))

# <codecell>

print "Top by countries for %s: " % last_year
filtered_country = filtered[filtered.year==last_year].groupby(['country', 'region_id', 'region_name']).archive_id.unique().apply(len).reset_index()
filtered_country.sort('archive_id', ascending=False).head(10)

# <codecell>

try: 
    import urllib2
    request = urllib2.Request("http://api.worldbank.org/countries?per_page=500&format=json" ,headers={'User-Agent' : "PKP using urllib2"})
    response = urllib2.urlopen(request, timeout=30)
    with open('data/worldbank.json', 'w') as f:
        f.write(response.read())
except:
    pass
    
with open('data/worldbank.json') as f:
    response = f.read()

wb_country_data = json.loads(response)[1]
wb_country_income_map = {w['id'].lower(): w['incomeLevel']['id'] for w in wb_country_data}
filtered['incomeLevel'] = filtered.country.apply(lambda x: wb_country_income_map[x] if x in wb_country_income_map else None)
income_level_names = {w['incomeLevel']['id']: w['incomeLevel']['value'] for w in wb_country_data}

# <codecell>

response

# <codecell>

{w['region']['id'].lower(): w['region']['value'] for w in wb_country_data}

# <codecell>

print "Regions sorted for %s: " % last_year
filtered_country = filtered[filtered.year==last_year].groupby(['region_id', 'region_name']).archive_id.unique().apply(len).reset_index()
print filtered_country.sort('archive_id', ascending=False)
print 
print "North America & Europe: %s" % filtered_country[filtered_country.region_id.isin(['NAC', 'ECS'])].archive_id.sum()
print "Total: %s" % filtered_country.archive_id.sum()

# <codecell>

filtered_income = filtered.groupby('incomeLevel').archive_id.unique().apply(len).reset_index()
filtered_income.set_index('incomeLevel', inplace=True)
filtered_income.columns = ['journals']
# filtered_income.reindex([u'LIC', u'LMC', u'UMC', u'HIC', u'INX']).plot(kind="bar")
print filtered_income.sort('journals', ascending=False)

# <codecell>

def by_income(l):
    x = filtered_income.ix[l].sum()[0]
    return (x, 100.0*x/filtered_income['journals'].sum())
print "Low income: %s (%.2f%%)" % by_income(['LIC'])
print "Lower-middle income: %s (%.2f%%)" % by_income(['LMC'])
print "Upper middle income %s (%.2f%%)" % by_income(['UMC'])
print "High income %s (%.2f%%)" % by_income(['HIC'])
print "Not Classified %s (%.2f%%)" % by_income(['INX'])

# <codecell>

def by_income(l):
    x = len(filtered_income[filtered_income.incomeLevel.isin(l)])
    return (x, 100.0*x/len(filtered_income))

filtered_income = filtered[filtered.year == 2015]
print "Low income: %s (%.1f%%)" % by_income(['LIC'])
print "Lower-middle income: %s (%.1f%%)" % by_income(['LMC'])
print "Upper middle income %s (%.1f%%)" % by_income(['UMC'])
print "High income %s (%.1f%%)" % by_income(['HIC'])
print "Not Classified %s (%.2f%%)" % by_income(['INX'])

# <codecell>

df = filtered_income.copy()
# df['incomeLevel'] = df.incomeLevel.map(lambda x: x if x != 'NOC' and x != 'OEC' else 'HIC')
df = df.groupby(['incomeLevel', 'archive_id']).apply(len) # this is 2015, see above
df = df.reset_index().groupby('incomeLevel').mean()
df[0].head()

# <codecell>

print "Number of articles since 1990: %s" % sum([x[1] for x in countdata.itervalues()])

# <codecell>

df = record_dates.groupby(['year', 'archive_id']).apply(len).reset_index()
y = 2010
print "On average %.2f articles per year since %s" % (df[df.year >= y][0].mean(), y)
print "On average %.2f articles per year before %s" % (df[df.year < y][0].mean(), y)

df = df[(df.year >= 1990) & (df.year<=last_year)].groupby('year')[0].mean()
# print
# print df
# df.plot(kind="bar", title="Average Number of articles per journal")

# <codecell>

# archive_settings[archive_settings.setting_name .head()

# <codecell>

# df['domain'] = df.url.map(lambda x: urlparse(x).netloc if str(x) > 4 and str(x)[0:4] == 'http' else None)

# <codecell>

# df_acuks = df[df.domain.str.endswith('ac.uk').fillna(False)]

# <codecell>

# harvesterUrl = archive_settings[archive_settings.setting_name == 'harvesterUrl'][['setting_value']]
# harvesterUrl.columns=['url']
# harvesterUrl['url'] = harvesterUrl.url.apply(find_journal_url)

# <codecell>

# all_journals.ix[3138]

# <codecell>

# df_acuks[['journal_title', 'url', 'recordCount']].sort('recordCount', ascending=False).to_excel('data/acuks_for_2015.xls')

