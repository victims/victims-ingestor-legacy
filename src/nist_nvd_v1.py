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
from datetime import datetime

import xml.parsers.expat

from victim_file import download_file
import victim_db_manager

# TODO - cache the results after a run, it currently takes ages for a single run
# - Implement threading in the library to make runs faster

# Language agnostic databases
cve_sources_full = ["http://nvd.nist.gov/download/nvdcve-2002.xml",
                    "http://nvd.nist.gov/download/nvdcve-2003.xml",
                    "http://nvd.nist.gov/download/nvdcve-2004.xml",
                    "http://nvd.nist.gov/download/nvdcve-2005.xml",
                    "http://nvd.nist.gov/download/nvdcve-2006.xml",
                    "http://nvd.nist.gov/download/nvdcve-2007.xml",
                    "http://nvd.nist.gov/download/nvdcve-2008.xml",
                    "http://nvd.nist.gov/download/nvdcve-2009.xml",
                    "http://nvd.nist.gov/download/nvdcve-2010.xml",
                    "http://nvd.nist.gov/download/nvdcve-2011.xml",
                    "http://nvd.nist.gov/download/nvdcve-2012.xml",
                    "http://nvd.nist.gov/download/nvdcve-2013.xml"]

cve = ""          # The current CVE ID/s being parsed
p_name = ""         # The current package name being parsed
valid = False     # Is the entry currently being processed something we want? a global because the value's needed by two functions
vuln_list = None    # The dictionary of valid vulnerable entries currently parsed

cache_db = None

DEBUG_MODE = True # Is debug mode on?
CACHING = True # Is caching turned on?

def _cache_uptodate ():
    """
    Check if the cache is up to date
    """
    if cache_db.check_mtime_within ():
        return True

    cache_db.renew_table ()

    return False

def get_entries (output_dict):
    """
    Function parses and aggregates _all_ vulnerability information from the predefind sources

    output is a dictionary of the following format:
    dict[package_name] - returns a dictionary(dict2) of the format
    dict2[version] which gives a list of CVEs affecting the given version
    dict2[vendor] returns the vendor for the given package_name
    """
    global vuln_list

    vuln_list = output_dict

    if CACHING:
        global cache_db

        cache_db = victim_db_manager.VictimDB (table="cache_nistv1")

        if _cache_uptodate ():
            return cache_db.get_cache ()

    for src in cve_sources_full:
        source = _get_source (src)
        if source is None:
            continue
        else:
            _parse_nvd_file (source)

    if CACHING:
        cache_db.create_cache (vuln_list)
        cache_db.add_mtime_stamp ()


def _get_source (url):
    """
    Function that tries to download a file from the given url
    """

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
    """
    Function that checks if data currently being processed is what we're looking for
    """
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
                version = version + attr["edition"].encode ("ascii")

        if version not in vuln_list[p_name]:
            vuln_list[p_name][version] = [cve]
        else:
            vuln_list[p_name][version].append (cve)


def _parse_nvd_file (input_file):
    """
    Function to parse the data in the nvd file to find the appropriate cve entries and the program name and version
    """
    nvd_parser = xml.parsers.expat.ParserCreate ()
    nvd_parser.StartElementHandler = _parse_helper_nvd
    nvd_parser.ParseFile (input_file)
