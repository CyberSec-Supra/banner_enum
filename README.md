# banner_enum
Python Script to take Text file with IP and Port, perform banner enumeration

The script take a text file with IP's and ports, it will perform a tcp connect, grab the banner of the service (if available)
it continues then to take the identified service and search through searchsploit to identify any known exploits for the service.
