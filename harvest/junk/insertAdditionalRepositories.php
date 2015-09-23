<?php

/**
 * insertAdditionalRepositories.php
 *
 * This script takes a CSV-formatted list of journals and ensures that each
 * has an OAI repository in the PKP harvester database, creating entries as
 * necessary. Once synchronized, the new entries should be ready for normal
 * OAI harvesting.
 */

$fp = fopen('journalOpenAccessStatus.out', 'r');

$db = new mysqli('localhost', 'harvester2-pkp', 'password_goes-here', 'harvester2-pkp');
if ($db->connect_errno) {
	die("Unable to connect to database.\n");
}

fgets($fp); // Discard header row
while (list($url, $journalTitle, $ojsVersion, $issn, $dateModified, $dateAvailable, $pathInfo, $country, $oaiUrl, $validOAIContent, $lang, $oaiTotal) = fgetcsv($fp, 0, "\t")) {
	if (!$validOAIContent) continue; // Skip invalid repos

	// Clean up the OAI URL
	$questionMarkPos = strpos($oaiUrl, '?');
	if ($questionMarkPos === false) continue; // Should contain ?; if not, skip the archive.

	// Figure out some details
	$oaiUrl = substr($oaiUrl, 0, $questionMarkPos);
	$escapedOaiUrl = $db->escape_string($oaiUrl);

	// Check to see if the repo already exists in the harvester
	$result = $db->query('SELECT archive_id FROM archive_settings WHERE setting_name=\'harvesterUrl\' AND setting_value=\'' . $escapedOaiUrl . '\'');
	if ($result->fetch_assoc()) {
		continue;
	}
	$result->close();

	// It's not in the repository. Add it.
	$db->query("INSERT INTO archives (harvester_plugin, schema_plugin, user_id, title, url, enabled) VALUES ('OAIHarvesterPlugin', 'DublinCorePlugin', 1, '" . $db->escape_string($journalTitle) . "', '" . $db->escape_string($url) . "', 1)");
	$db->query("INSERT INTO archive_settings (archive_id, setting_name, setting_type, setting_value) VALUES (LAST_INSERT_ID(), 'oaiIndexMethod', 'string', '1')");
	$db->query("INSERT INTO archive_settings (archive_id, setting_name, setting_type, setting_value) VALUES (LAST_INSERT_ID(), 'harvesterUrl', 'string', '$escapedOaiUrl')");
	echo $oaiUrl . "\n";
}

$db->close();

?>
