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

# NIST v1 file links
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

# The current CVE ID/s being parsed
cve = ""

# The current package name being parsed
p_name = ""

'''
Is the entry currently being processed something we want?
A global because the value's needed by two functions.
'''
valid = False

# The dictionary of valid vulnerable entries currently parsed
vuln_list = None

# Reference to the VictimDB object in use
cache_db = None

# Is caching turned on?
CACHING = True

def _cache_uptodate ():
    """
    Check if the cache is up to date.

    Outputs :
    Returns True if the cache is within date.
    Returns False if the cache needs to be rebuilt.
    """
    if cache_db.check_mtime_within ():
        return True

    cache_db.renew_table ()

    return False

def get_entries ():
    """
    Function parses and aggregates _all_ vulnerability
    information from the predefind sources.

    Outputs :
    Returns a dictionary of the following format:
    dict[package_name] - returns a dictionary(dict2) of the format
    dict2[version] - list of CVEs affecting the given version
    dict2[vendor] - returns the vendor for the given package_name.
    """
    global vuln_list

    vuln_list = {}

    if CACHING:
        global cache_db

        # Get a reference to the database where the cache is stored
        cache_db = victim_db_manager.VictimDB (table="cache_nistv1")

        if _cache_uptodate ():
            # Just return the cache if it is up to date
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

    return vuln_list


def _get_source (url):
    """
    Function that tries to download a file from the given url.

    Inputs :
    url - URL of file to download.

    Outputs :
    Returns None if the file can be downloaded.
    Returns the reference to the downloaded file.
    """

    try:
        ret = urllib2.urlopen (url)
    except urllib2.HTTPError as h:
        print h.reason
        return None
    except urllib2.URLError as u:
        print u.reason
        return None

    return ret


def _parse_helper_nvd (name, attr):
    """
    Helper function that checks if data currently being processed
    is what we're looking for, if it is then the data is added
    to the global dictionary.

    Inputs :
    name - name of the tag being parsed.
    attr - the contents of the tag being parsed.
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
    Function to parse the data in the nvd file to find the
    appropriate cve entries and the program name and version.

    Inputs :
    input_file - File object to be parsed.
    """
    nvd_parser = xml.parsers.expat.ParserCreate ()
    nvd_parser.StartElementHandler = _parse_helper_nvd
    nvd_parser.ParseFile (input_file)
