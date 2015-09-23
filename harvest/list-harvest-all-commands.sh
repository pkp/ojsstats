#!/bin/bash

for archiveId in `php ~/harvest/listAllArchiveIds.php`; do
	echo php tools/harvest.php $archiveId from=last
done
