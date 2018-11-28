**This is the crazy way in which we calculate how many OJS journals there are!**

This is mostly run by cron, following cron.sh. A detailed description of the process is described below.

Written and maintained by @axfelix (ojsstats.py) and @jalperin (statscrunch.py).

# The Process: 

## 1. Processing the PKP Website logs

Because every OJS installation contains a link back to the PKP Website, there is a high likelihood of someone following the link, leaving a trace in the PKP Website log files. These log files are then parsed for referrer URL that contain known URL patterns (e.g. /about/aboutThisPublishingSystem, and /index.php/article/articleView). False positives are acceptable at this stage, since these URLs will be verified as OJS installations in the following step. 

## 2. Verify URL by contacting expected URL of OAI endpoint 

Once a suspected OJS URL is found in the PKP Website logs, the corresponding URL for the OAI endpoint can be deduced by following the standard URL patterns of OJS (see source for details). There are four possible locations for the OAI endpoint (depending on configuration options) and they are each checked, using the OAI verb “Identify,” until one returns a valid OAI response. If none is found, the URL is discarded and not included in the dataset. 

## 3. Save repository information

A valid OAI response with for an “Identify” verb contains a repository identifier, as well as the OJS version number. The IP address of the server can also be queried using the domain name.  Since OAI repository identifiers are not unique between installations (in fact, many leave the default value), a combination of the repository identifier and the IP address can be used as a unique identifier for every installation. 

## 4. Identify all OJS journals at the same installation

OJS allows for multiple journals to be configured in a single installation. To avoid having to find each individual journal URL, the OAI verb “ListSets” can be queried to identify every journal that is available from that endpoint. ListSets will return both sections and journals names and abbreviations, but the absence of a “:” in the set abbreviation can be used to distinguish between them. 

## 5. Save journal name and contact information

The journal name can be saved from the list of Sets, and by using the “Identify” verb again at each journal-specific endpoint, the journal contact information (email) can be extracted from the OAI response. This also serves as a final confirmation that the URL found corresponds to a valid OJS journal. 

## 6. Add known OJS OAI URLs to an instance of the PKP Harvester 

Once a known valid OJS journal OAI endpoint is found, the URL is harvested over OAI.

## 7. Look up the journal’s country

A journal’s country of origin is determined, with some degree of error, by first looking for a partial country name in the journal’s title. A country list from the World Bank is used for this purpose. The country names are stemmed using some simple heuristics (see source code) so that nationalities are matched (i.e., instead of searching for “Canada,” the algorithm searches for “Canad” so that journal names that contain “Canadian” will also be matched). If no country names can be found in the journal titles, the top level domain of the URL is used (e.g., .ca domains are deemed to be Canadian journals). Finally, if the top level domain is not country specific (e.g., .com, .edu, .org) then the IP address is looked up in a GeoIP database (see source for detail). 

## 8. Collect the article metadata for every journal

In the course of the Harvester’s normal operation, the OAI metadata records for every published article can be collected. This harvested data is then periodically extracted into a comma separated file, with one article per row. 

## 9. Process the article data to identify journals and calculate statistics

In the final processing, the publication data stored with the article is used, and a few data integrity and corrections are performed. For example, years of publication prior to 1278, the dates are assumed to be in the islamic calendar and adjusted to gregorian time. Similarly, because of a bug in older version of OJS which caused an incorrect publication date to be recorded, a heuristic is used to extract the publication year from the issue descriptor metadata tag (dc:source). Details of these corrections can be seen in the source code. 