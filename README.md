# cvescan

Dependencies:
- `/bin/sh`
- `nmap`
- `git`

This program makes sure you have all the pre-requisites ready to scan for CVEs using `nmap`.
Once the NSE scripts are in place, we do a full CVE scan using `nmap` under the hood, so all normal `nmap` options are available.

Since `vulners` is now a part of `nmap`, this script just makes sure that `vulscan` is also installed and the databases up-to-date
before running `nmap`.

I might build some command line options into this at some point, but in the meantime, feel free to use and edit as necessary for your use-case. 
