# UAL

<em><b>This script is a work in progress.</b></em>

This script was inspired by KStrike written by Brian Moran of BriMor Labs and Eric Zimmerman's SumECmd.exe.

Special thanks to Joachim Metz for creation of libesedb.  Without it, this script would not be possible.

I need a tool that can process all of the UAL ESE database files, without the need of pre-processing these files.  Output options are need for flexibilty to ingest the data with other tools.

This script is designed with an input in mind of pointing to a directory containing all of the SUM ESE files.  

SystemIdentity.mdb is parsed for:
* ROLE_IDS for GUID mapping.
* CHAINED_DATABASES for obtaining the year to Chained Database mapping and validate if they existed in the provided input directory.
* SYSTEM_IDENTITY  is parsed an provide for analsyis as needed.

Current.mdb and all Chained Databases
* Parsed as is into a human readable format.
* TODO: Maxmind Lookups for the IP Address in the DNS table.
* TODO: CLIENTS - Enrichments from DNS and ROLE_ACCESS table.
* TODO: CLIENTS - Do something useful with the Day### fields like KStrike, so that a overall timeline of events can be created as an output option.
* TODO: Test VIRTUALMACHINES Table processing.  The processing is coded in, but since no data has been found for testing, data in this table could bork the script.




This script does not rely on pre-defined dictionaries for GUID dictionary and that in theory should make it with stand changes made by Microsfoft.

When the script is ready for general use, the user will have the option to select one of the following outputs, CSV, JSON, XLSX or SQLITE.

<b>Current Requirements:</b>
* Python 3 (Developed and tested with Python 3.9)
* Colorlogs (pip install colorlog)
* maxminddb (pip install maxminddb)
* Pandas (pip install pandas)
* libesedb (pyesedb) (compile from source:  https://github.com/libyal/libesedb)  (pip install libesedb-python failed for 3.8 and 3.9, YMMVH)
* GeoLite2-City.mmdb (https://www.maxmind.com) Place in a subdirectory named <i>script_location</i>\maxmind\GeoLite2-City.mmdb

