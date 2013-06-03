# Copyright 2013

# Pramod Dematagoda <pmd.lotr.gandalf@gmail.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import argparse
import os

import sources
import victim_file
import victim_db_manager

def find_similar_binary_by_name (package_name):
    entries = sources.get_entries ()

    if package_name in entries:
        # do stuff
        for vuln_package in entries[pack_name]:
            victim_file.package_exists ()
            # Add entry to database

    else:
        print "Error : Package not found in sources"

    return

def setup_args ():
    parser = argparse.ArgumentParser (description="Download similar python packages for vict.ims")



def main ():
    setup_args ()

    find_similar_binary_by_name ()


if __name__ == '__main__':
    main ()
