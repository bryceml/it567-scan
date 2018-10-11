# scan.py

This is only intended to be run on ubuntu.  I tested it on 18.10 and 18.04 but it will probably work on 16.04 just fine.

# Dependancies:

* python3-scapy
* pandoc
* wkhtmltopdf 
* texlive-latex-extra

You should be able to just apt-get install these with:

```bash
sudo apt-get -y install python3-scapy pandoc wkhtmltopdf texlive-latex-extra
```

# Use:

use `python3 scan.py -h` to see usage.

# Features:

* Scan multiple ports using comma separated list on the command line
* Scan multiple hosts using comma separated list on the command line
* Outputs a pdf report
