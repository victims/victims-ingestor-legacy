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

db_conn = None

def find_similar_binary_by_name (package_name):
    entries = sources.get_entries ()

    if package_name in entries:
        # do stuff
        for vuln_ver in entries[package_name].keys ():
          if victim_file.package_exists (package_name, vuln_ver, 0):
              victim_db_manager.add_entry (package_name,
                                           vuln_ver,
                                           entries[package_name]['vendor'],
                                           entries[package_name][vuln_ver],
                                           "ruby",
                                           victim_file.make_package_url (package_name, vuln_ver, 0))
            # Add entry to database

    else:
        print "Error : Package not found in sources"

    return

def setup_args ():
    parser = argparse.ArgumentParser (description="Download similar python packages for vict.ims")

    # Only add the agrument for the name of the victims package we are looking for
    parser.add_argument ("-n", "--name", nargs=1,
                         required=True,
                         help="Name of the victim package to be searched for")
    return parser.parse_args ()

def main ():
    args = setup_args ()

    # Create a connection to the victims DB with default values
    db_conn = victim_db_manager.VictimDB ()

    find_similar_binary_by_name (args.name)


if __name__ == '__main__':
    main ()
