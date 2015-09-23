<?php
error_reporting(E_ERROR | E_PARSE);
$filename = 'data/ojs_in_logs.csv';
$oxsUrls = array();

function sortByChangeTime($file1, $file2) {
    return (filemtime($file1) < filemtime($file2)); 
}

$access_log_files = glob('/var/log/httpd/access*gz');
// sort by change time
usort($access_log_files, 'sortByChangeTime'); 

// use the most recently changed log file
$fp = gzopen($access_log_files[0], 'r');
while ($line = fgets($fp)) {
	if (!preg_match('/^([0-9.]+ )+(?:- )+\[(.*)\] "GET (.*) HTTP\/1\.[01]" 200 [0-9]+ "(.*)"( 0) \d+?$/', trim($line), $matches)) continue;

	list($junk, $ip, $time, $url, $referrer, $junk) = $matches;

	// test for URLs that are either 'index.php' type urls (common for PKP apps),
	// or else look for about/aboutThisPublishingSystem in the case of mod_rewrite
	// or else look for a few other common OJS URL patterns
	// if they aren't OJS, this will be detected elsewhere
	if (preg_match('/(http:\/\/.*)\/index.php/', $referrer, $matches) || preg_match('/(http:\/\/.*)\/about\/aboutThisPublishingSystem/', $referrer, $matches) ||
preg_match('/(http:\/\/.*)\/article\/articleView/', $referrer, $matches) ||
preg_match('/(http:\/\/.*)\/issue\/current/', $referrer, $matches) ||
preg_match('/(http:\/\/.*)\/about\/siteMap/', $referrer, $matches) ||
preg_match('/(http:\/\/.*)&page=about&op=aboutThisPublishingSystem/', $referrer, $matches) ||
preg_match('/(http:\/\/.*)&page=article&op=articleView/', $referrer, $matches) ||
preg_match('/(http:\/\/.*)&page=issue&op=current/', $referrer, $matches) ||
preg_match('/(http:\/\/.*)&page=about&op=SiteMap/', $referrer, $matches)
	) {
		list($junk, $oxsUrl) = $matches;
		$oxsUrls[] = $oxsUrl;
	}
}
fclose($fp);

$oxsUrls = array_unique($oxsUrls);

$knownUrls = array();
@$fp = fopen($filename, 'r');
if ($fp) {
	while ($line = fgetcsv($fp)) {
		// use an assoc_array and ignore the value
		// to be used for uniqueness testing
		$knownUrls[$line[0]] = true;
	}
	fclose($fp);
}

$fp = fopen($filename, 'a+');

foreach ($oxsUrls as $url) {
	if (isset($knownUrls[$url])) continue;
	$knownUrls[$url] = true;

	// if we don't find a version.xml, it is not a PKP app
	@$contents = file_get_contents($url . '/dbscripts/xml/version.xml');
	if ($contents === false) continue;

	$parser =& xml_parser_create();
	$result = xml_parse_into_struct($parser, $contents, $values);
	xml_parser_free($parser);
	if (!$result) continue;

	$results = null;
	foreach ($values as $i) if ($i['type'] == 'complete') {
		$results[$i['tag']] = $i['value'];
	}

	// we differentiate between PKP apps
	if (substr($results['APPLICATION'], 0, 3) == 'ojs') {
		fputcsv($fp, array(
			$url,
			strftime('%m/%d/%Y'),
			$results['APPLICATION'],
			$results['RELEASE']
		));
	}
}

fclose($fp);

?>
