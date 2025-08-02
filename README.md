# banner_enum
Python Script to take Text file with IP and Port, perform banner enumeration

The script take a text file with IP's and ports, it will perform a tcp connect, grab the banner of the service (if available)
it continues then to take the identified service and search through searchsploit to identify any known exploits for the service.

API key for VULNERS needed for online searching.
Local copy of searchsploit required to search local.

USAGE:
usage: banner_enum.py [-h] -i INPUT [-k APIKEY] [-o OUTPUT] [--json JSON] [--xml XML] [--nuclei NUCLEI] [--pdf PDF]



A nuclei template are generated on completion and a html export report. 


SYSTEM REQUIREMENT:

sudo apt install python3-cffi libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev libxml2 libxslt1.1 libjpeg-dev zlib1g-dev libpng-dev libpango1.0-dev
The script assumes that pipx was used to install the requirements for the PDF export.
If not, the pdf export will be skipped with all the other formats still available.

