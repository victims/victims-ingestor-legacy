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

sources = [nist_nvd_v2.get_entries]

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
