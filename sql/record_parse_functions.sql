DELIMITER |

DROP FUNCTION IF EXISTS getTagContents|
CREATE FUNCTION getTagContents(str TEXT, tagname VARCHAR(255), sep VARCHAR(255)) RETURNS text DETERMINISTIC
BEGIN
	DECLARE result, thisResult TEXT;
	DECLARE startPos, endPos INT;
	DECLARE ix INT;

	SET ix=1;
	SET result=NULL;

	occurs: LOOP
		# Find the start tag
		SET startPos = LOCATE(CONCAT('<', tagname), str, ix);
		IF startPos = 0 THEN
			# Could not find start tag.
			RETURN result;
		END IF;
		SET startPos = LOCATE('>', str, startPos) + 1;

		# Find the end tag
		SET endPos = LOCATE(CONCAT(CONCAT('</', tagname), '>'), str, startPos);
		IF endPos = 0 THEN
			# Could not find end tag following start tag.
			RETURN result;
		END IF;

		# Found start and end tags; return the content between them.
		SELECT TRIM(SUBSTRING(str FROM startPos FOR endPos - startPos)) INTO thisResult;
		IF thisResult <> '' THEN
			IF result IS NOT NULL THEN
				SET result=CONCAT(result, sep);
				SET result=CONCAT(result, thisResult);
			ELSE
				SET result=thisResult;
			END IF;
		END IF;

		SET ix = endPos;
	END LOOP occurs;

	RETURN result;
END |

DROP FUNCTION IF EXISTS getMinArchiveDate|
CREATE FUNCTION getMinArchiveDate(archiveId INT) RETURNS int DETERMINISTIC
BEGIN
	DECLARE minYear INT;
	DECLARE rawYear VARCHAR(255);
	SELECT MIN(YEAR(getTagContents(contents, 'dc:date', ''))) FROM records WHERE archive_id = archiveId INTO minYear;
	RETURN minYear;
END |

DROP FUNCTION IF EXISTS getMaxArchiveDate|
CREATE FUNCTION getMaxArchiveDate(archiveId INT) RETURNS int DETERMINISTIC
BEGIN
	DECLARE maxYear INT;
	SELECT MAX(YEAR(getTagContents(contents, 'dc:date', ''))) FROM records WHERE archive_id = archiveId INTO maxYear;
	RETURN maxYear;
END |

DROP FUNCTION IF EXISTS getRecordCount|
CREATE FUNCTION getRecordCount(archiveId INT) RETURNS int DETERMINISTIC
BEGIN
	DECLARE recordCount INT;
	SELECT count(*) FROM records WHERE archive_id = archiveId INTO recordCount;
	RETURN recordCount;
END |

