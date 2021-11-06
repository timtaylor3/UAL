# UAL

<em>Usage: </em>
<code>UALParser.py -d **path_to_sum_dir* -o *path_to_write the data* -t *output_type*</code>

This script was inspired by KStrike written by Brian Moran and Eric Zimmerman's SumECmd.exe.

I needed a tool that can overcome the limitations of these tools.  

I wanted to process all UAL ESE database files without the need of cleaning the files.  I also wanted different output options are need for flexibilty to ingest the data with other tools.

This script is designed with an input in mind of pointing to a directory containing all of the SUM ESE files.  

Output Options are currently csv, json, sqlite or xlsx.  

SystemIdentity.mdb is parsed for:
- ROLE_IDS for GUID mapping.
- CHAINED_DATABASES for obtaining the year to Chained Database mapping and validate if they existed in the provided input directory.
- SYSTEM_IDENTITY is parsed an provide for analsyis as needed.

Current.mdb and all Chained Databases
- Parsed as is into a human readable format.
- Maxmind Lookups for the IP Address in the DNS table.
- Enrichments from DNS and ROLE_ACCESS table.
- TODO: Test VIRTUALMACHINES Table processing.  The processing is coded in, but since no data has been found for testing, data in this table could bork the script.

This script does not rely on pre-defined dictionaries for GUID dictionary and that in theory should make it with stand changes made by Microsoft.  Some role_ids GUIDs are pre-populated with known values, but will only be used in the event there were no role_ids GUIDs found in the SystemIdentity ESE tables or if the SystemIdentity ESE database is not processed.

<b>Current Requirements:</b>
- Python 3 (Developed and tested with Python 3.9)
- Colorlogs (pip install colorlog)
- maxminddb (pip install maxminddb)
- Pandas (pip install pandas)
- libesedb (pyesedb) (compile from source:  https://github.com/libyal/libesedb)  (pip install libesedb-python failed for 3.8 and 3.9, YMMVH)
- GeoLite2-City.mmdb (https://www.maxmind.com) Place in a subdirectory named <i>script_location</i>\maxmind\GeoLite2-City.mmdb

References: 
- https://github.com/brimorlabs/KStrike
- https://ericzimmerman.github.io/#!index.md
- https://advisory.kpmg.us/blog/2021/digital-forensics-incident-response.html
