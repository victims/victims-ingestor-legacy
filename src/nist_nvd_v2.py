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

# NIST database files
cve_sources_recent = ["https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-modified.xml",
                      "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-recent.xml"]

cve_sources_full = ["https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2002.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2003.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2004.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2005.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2006.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2007.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2008.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2009.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2010.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2011.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2012.xml",
                    "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2013.xml",]

cve = ""          # The current CVE ID/s being parsed
valid = False     # Is the entry currently being processed something we want? a global because the value's needed by two functions
vuln_list = None    # The dictionary of valid vulnerable entries currently parsed

DEBUG_MODE = False # Is debug mode on?


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
        source = _get_source (src)   # Change over to victim file's download function
        if source is None:
            continue
        else:
            _parse_nvd_file (source)

    if not DEBUG_MODE: # Currently debug mode makes no real sense, fix it up
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


# Maybe break the next bit in to another library?
def _parse_helper_nvd (name, attr):
    '''
    Function that checks if data currently being processed is what we're looking for
    '''
    global valid
    global cve

    if name == "entry":
        cve = attr["id"]

    if name == "vuln:product":
        valid = True
    else:
        valid = False


def _validate_data (entry):
    '''
    Function to parse a given line of data from the nvd file to grab the information we need
    '''

    cve_package = ""
    cve_package_version = ""
    vendor = ""

    # It seems like the data we would need is contained after the 2nd element
    # in the list, this may need further verification
    # format seems to be "cpe:\a:<vendor>:<name>:version-info(following)"
    conf_list = entry.split (":")
    if len (conf_list) >= 4:
        vendor = conf_list[2]
        cve_package = conf_list[3]
        for elem in conf_list[4:]:
            cve_package_version = cve_package_version + elem  # Append all the version information together      

    # Do not encode the strings in unicode, it screws things up when using them
    return (cve_package.encode ('ascii'), cve_package_version.encode ('ascii'), vendor.encode ('ascii'), cve.encode ('ascii'))


def _parse_data_nvd (data):
    '''
    Function that determines if the data passed by the XML parser is what we need, if so
    it is added to the vulnerabilities dictionary
    '''

    global valid
    global vuln_list

    if valid:
        cve_entry = _validate_data (data)

        if len (cve_entry[0]) and len (cve_entry[1]):

            # If the dictionary already contains a list for the given package name, just append the new cve entry to the list
            if cve_entry[0] in vuln_list:
                if cve_entry[1] in vuln_list[cve_entry[0]]:
                    vuln_list[cve_entry[0]][cve_entry[1]].append (cve_entry[3])
                else:
                    vuln_list[cve_entry[0]][cve_entry[1]] = [cve_entry[3]]

            else:
                # Create a new list for the package name if a list does not exist
                vuln_list[cve_entry[0]] = {}
                vuln_list[cve_entry[0]]["vendor"] = cve_entry[2]
                vuln_list[cve_entry[0]][cve_entry[1]] = [cve_entry[3]]

        valid = False


def _parse_nvd_file (input_file):
    '''
    Function to parse the data in the nvd file to find the appropriate cve entries and the program name and version
    '''
    nvd_parser = xml.parsers.expat.ParserCreate ()
    nvd_parser.StartElementHandler = _parse_helper_nvd
    nvd_parser.CharacterDataHandler = _parse_data_nvd
    nvd_parser.ParseFile (input_file)
