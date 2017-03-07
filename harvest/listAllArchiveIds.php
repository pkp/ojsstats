<?php

$db = new mysqli('localhost', 'harvester2-pkp', 'password_goes_here', 'harvester2-pkp');
if ($db->connect_errno) {
	die("Unable to connect to database.\n");
}

// List all archives in random sort order.
// Random sort order 1) helps prevent sequentially listed archives from getting
// hit in parallel, and 2) ensures that ill-behaved archives won't always stall
// the process at the same point.
$result = $db->query('SELECT archive_id FROM archives WHERE enabled = 1 ORDER BY rand()');
while (list($archiveId) = $result->fetch_array()) {
	echo $archiveId . "\n";
}
$result->close();

$db->close();

?>
