# Copyright 2013

# Pramod Dematagoda <pmd.lotr.gandalf@gmail.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import os
import urllib2
import hashlib

'''
http://rubygems.org/downloads/<package-name>-<package-version>.gem - ruby download url template

https://pypi.python.org/packages/source/<first-letter-of-package-name>/<package-name>/<package-name>-<package-version>.tar.gz - python download url template

'''

def  download_file (url):
    ''' 
    function to try and download the file in the given url
    '''

    # try and download the file given in the url, throw up an error if not possible
    try:
        ret = urllib2.urlopen (url)
    except urllib2.HTTPError as h:
        print h.reason
        return None
    except urllib2.URLError as u:
        print u.reason
        return None

    print "Downloaded " + url

    return ret

def _make_package_url (package_name, package_version, lang):
    '''
    function to generate a url based on the package name, version and language
    '''

    ruby_template = "http://rubygems.org/downloads/{!s}-{!s}.gem"
    python_template = "https://pypi.python.org/packages/source/{!s}/{!s}/{!s}-{!s}.tar.gz"

    if lang == 0:
        return ruby_template.format (package_name, package_version)
    else:
        return python_template.format (package_name[0], package_name, package_name, package_version)

def _get_package (package_name, package_version, lang):
    '''
    a function linking the required functions to download a required package
    '''

    url = _make_package_url (package_name, package_version, lang)
    victim_file = download_file (url)

    return victim_file

''' prospective function to be implemented that hashes the given files '''
def _hash_file (victims_file):
    return 0

class VictimsFile:
    '''
    class that represents a vulnerable package
    '''

    file_name = None
    download_file = None
    cve_id = ""
    vendor = ""
    version = ""
    name = ""

    def __init__ (self, package_name, package_version, vendor_name=None, cve=None, lang=None):

        if lang is None: # if no language is specified, try and find out for ourselves
            ret = _get_package (package_name, package_version, 0)

            if ret is None:
                ret = _get_package (package_name, package_version, 1)

                if ret is None:
                    return

        else:
            ret = _get_package (package_name, package_version, lang)
            if ret is None:
                return

        self.download_file = ret
        self.cve_id = cve
        self.vendor = vendor_name
        self.name = package_name
        self.version = package_version

    def get_file (self):
        return self.download_file

    def get_file_name (self):
        return self.file_name
