# banner_enum
Python Script to take Text file with IP and Port, perform banner enumeration

The script take a text file with IP's and ports, it will perform a tcp connect, grab the banner of the service (if available)
it continues then to take the identified service and search through searchsploit to identify any known exploits for the service.

API key for VULNERS needed for online searching.
Local copy of searchsploit required to search local.

usage: banner_enum.py [-h] -i INPUT [-b BANNERS] [-o OUTPUT] [-k VULNERS_KEY] [-d DELAY] [--html-out reportname.html]

A nuclei template are generated on completion and a html export report. 
