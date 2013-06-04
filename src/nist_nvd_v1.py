# Copyright 2013

# Pramod Dematagoda <pmd.lotr.gandalf@gmail.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import urllib2

import xml.parsers.expat

from victim_file import download_file

# TODO - cache the results after a run, it currently takes ages for a single run
# - Implement threading in the library to make runs faster
# - May be use CVE v1 files as these are much smaller? (Are they good enough?)

# Language agnostic databases
cve_sources_recent = ["http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-modified.xml",
                      "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-recent.xml"]

cve_sources_full = ["http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2002.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2003.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2004.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2005.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2006.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2007.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2008.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2009.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2010.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2011.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2012.xml",
                    "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2013.xml"]

cve = ""          # The current CVE ID/s being parsed
p_name = ""         # The current package name being parsed
valid = False     # Is the entry currently being processed something we want? a global because the value's needed by two functions
vuln_list = None    # The dictionary of valid vulnerable entries currently parsed

DEBUG_MODE = True # Is debug mode on?


def get_entries (output_dict):
    '''
    Function parses and aggregates _all_ vulnerability information from the predefind sources

    output is a dictionary of the following format:
    dict[package_name] - returns a dictionary(dict2) of the format
    dict2[version] which gives a list of CVEs affecting the given version
    dict2[vendor] returns the vendor for the given package_name
    '''
    global vuln_list

    vuln_list = output_dict

    for src in cve_sources_recent:
        source = _get_source (src)
        if source is None:
            continue
        else:
            _parse_nvd_file (source)

    
    if not DEBUG_MODE: 
        for src in cve_sources_full:
            source = _get_source (src)
            if source is None:
                continue
            else:
                _parse_nvd_file (source)

    return vuln_list


def _get_source (url):
    '''
    Function that tries to download a file from the given url
    '''

    try:
        ret = urllib2.urlopen (url)
    except urllib2.HTTPError as h:
        print h.reason
        return None
    except urllib2.URLError as u:
        print u.reason
        return None

    print "Downloaded " + url    # Just for debugging, have we really downloaded the file?

    return ret


def _parse_helper_nvd (name, attr):
    '''
    Function that checks if data currently being processed is what we're looking for
    '''
    global valid
    global cve
    global p_name

    if name == "entry":
        cve = attr["name"].encode ("ascii")

    if name == "prod":
        vendor = attr["vendor"].encode ("ascii")
        p_name = attr["name"].encode ("ascii")
        if p_name not in vuln_list:
            vuln_list[p_name] = {}
            vuln_list[p_name]["vendor"] = vendor

    if name == "vers":
        version = attr["num"].encode ("ascii")
        if "edition" in attr:
            if len (version) == 0:
                version = attr["edition"].encode ("ascii")
            else:
                version = version + "-" + attr["edition"].encode ("ascii")

        if version not in vuln_list[p_name]:
            vuln_list[p_name][version] = [cve]
        else:            
            vuln_list[p_name][version].append (cve)


def _parse_nvd_file (input_file):
    '''
    Function to parse the data in the nvd file to find the appropriate cve entries and the program name and version
    '''
    nvd_parser = xml.parsers.expat.ParserCreate ()
    nvd_parser.StartElementHandler = _parse_helper_nvd
    nvd_parser.ParseFile (input_file)
