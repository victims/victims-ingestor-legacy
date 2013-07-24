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

import nist_nvd_v1
import nist_nvd_v2

# TODO - cache the results after a run, it currently takes ages for a single run
# - Implement threading in the library to make runs faster
# - May be use CVE v1 files as these are much smaller? (Are they good enough?)

sources = [nist_nvd_v2.get_entries]

DEBUG_MODE = True # Is debug mode on?


def get_entries (lang=None):
    '''
    Function parses and aggregates _all_ vulnerability information from the predefind sources,
    if lang is specified then the information from vulnerability databases for that particular
    lang are also parsed and added on to the list of vulnerable packages
    '''

    vuln_list = {}

    for src in sources:
        src (vuln_list)

    return vuln_list
