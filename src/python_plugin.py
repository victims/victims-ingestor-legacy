# Copyright 2013

# Pramod Dematagoda <pmd.lotr.gandalf@gmail.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import optparser
import os

import sources
import victim_file
import victim_db_file

def find_similar_binary_by_name (package_name, lang=None):
    entries = sources.get_entries (lang)

    if len (entries[package_name]):
        # do stuff
        for vuln_package in entries[pack_name]:
            victim_file.VictimsFile (vuln_package[0], vuln_package[1], vuln_package[2], vuln_package[3])

    else:
        return


def find_similar_binary_by_code (package, lang=None):
    return

def main ():



if __name__ == 'main':
    main ()
