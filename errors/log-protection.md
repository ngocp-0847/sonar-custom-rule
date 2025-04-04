V7.3 Log Protection
Logs that can be trivially modified or deleted are useless for investigations and prosecutions. Disclosure of logs
can expose inner details about the application or the data it contains. Care must be taken when protecting logs
from unauthorized disclosure, modification or deletion.
# Description L1 L2 L3 CWE
7.3.1 Verify that all logging components appropriately encode data to prevent log
injection. (C9)
✓ ✓ 117
7.3.2 [DELETED, DUPLICATE OF 7.3.1]
7.3.3 Verify that security logs are protected from unauthorized access and
modification. (C9)
✓ ✓ 200
7.3.4 Verify that time sources are synchronized to the correct time and time zone.
Strongly consider logging only in UTC if systems are global to assist with postincident forensic analysis. (C9)