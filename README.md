# CVEscan

Dependencies:
- `/bin/sh`
- `nmap`
- `git`

This program makes sure you have all the pre-requisites ready to scan for CVEs using `nmap`.
Once the NSE scripts are in place, we do a full CVE scan using `nmap` under the hood, so all normal `nmap` options are available.

Since `vulners` is now a part of `nmap`, this script just makes sure that `vulscan` is also installed and the databases up-to-date
before running `nmap`.

Feel free to use and edit as necessary for your use-case. 

## Usage:

`git clone https://github.com/phx/cvescan && cd cvescan`

Put `cvescan` somewhere in your `$PATH` where you can summon it by name whenever you need it:

`sudo mv cvescan /usr/local/bin/`

First time usage:

`sudo cvescan`

Update the CVE databases:

`sudo cvescan -u`

Actually running a CVE scan:

`sudo cvescan google.com -p443`

(Yadda, yadda, will take all normal `nmap` arguments)

**Note:**

- requires `-sV`, and will add it automatically if it's not an existing argument.
