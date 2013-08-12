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

https://pypi.python.org/packages/source/<first-letter-of-package-name>/<package-name>/<package-name>-<package-version>.zip - python download url template

'''
def download_file (url):
    """
    Function to try and download the file in the given url.

    Inputs :
    url - URL of the file to be downloaded

    Outputs :
    Returns a reference to the downloaded file
    Returns None on failure
    """

    '''
    Try and download the file given in the url,
    throw up an error if not possible.
    '''
    try:
        ret = urllib2.urlopen (url)
    except urllib2.HTTPError:
        return None
    except urllib2.URLError:
        return None

    print "Downloaded " + url

    return ret

def make_package_url (package_name, package_version, lang):
    """
    Function to generate a url based on the package name,
    version and language.

    Inputs :
    package_name - name of the package to be downloaded
    package_version - version of the package to be downloaded
    lang - language of the package being downloaded

    Outputs :
    Returns a string containing the URL of the package
    """

    ruby_template = "http://rubygems.org/downloads/{0}-{1}.gem"
    python_template_tar = "https://pypi.python.org/packages/source/{0}/{1}/{2}-{3}.tar.gz"
    python_template_zip = "https://pypi.python.org/packages/source/{0}/{1}/{2}-{3}.zip"

    if lang == 0:
        return ruby_template.format (package_name, package_version)
    elif lang == 1:
        return python_template_tar.format (package_name[0], package_name, package_name, package_version)
    elif lang == 2:
        return python_template_zip.format (package_name[0], package_name, package_name, package_version)

def package_exists (package_name, package_version, lang):
    """
    A function linking the required functions to check
    for the existence of a package

    Inputs :
    package_name - name of the package to be downloaded
    package_version - version of the package to be downloaded
    lang - language of the package being downloaded

    Outputs :
    Returns True on package availability
    Returns False on package unavailability
    """

    url = make_package_url (package_name, package_version, lang)
    victim_file = download_file (url)

    if victim_file is None:
        return False
    else:
        return True
