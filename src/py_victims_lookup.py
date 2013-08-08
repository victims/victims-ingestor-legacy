# Copyright 2013

# Pramod Dematagoda <pmd.lotr.gandalf@gmail.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

from optparse import OptionParser
import os

import sources
import victim_file
import victim_db_manager

db_conn = None

def find_similar_binary_by_name (package_name):
    entries = sources.get_entries ()
    db_conn = victim_db_manager.VictimDB ()

    if package_name in entries:
        # do stuff
        for vuln_ver in entries[package_name].keys ():
          if victim_file.package_exists (package_name, vuln_ver, 1):
              db_conn.add_victim (package_name,
                                  vuln_ver,
                                  entries[package_name]['vendor'],
                                  entries[package_name][vuln_ver],
                                  "python",
                                  victim_file.make_package_url (package_name, vuln_ver, 1))

          elif victim_file.package_exists (package_name, vuln_ver, 2):
              db_conn.add_victim (package_name,
                                  vuln_ver,
                                  entries[package_name]['vendor'],
                                  entries[package_name][vuln_ver],
                                  "python",
                                  victim_file.make_package_url (package_name, vuln_ver, 2))

    else:
        print "Error : Package not found in sources"

    return

def setup_args ():
    parser = OptionParser ()

    # Only add the agrument for the name of the victims package we are looking for
    parser.add_option ("-n", "--name",
                       dest="name",
                       help="Name of the victim package to be searched for")

    (options, args) = parser.parse_args ()

    return (options, parser)

def main ():
    (options, args) = setup_args ()

    # Create a connection to the victims DB with default values
    db_conn = victim_db_manager.VictimDB ()

    if (options.name):
        find_similar_binary_by_name (options.name)
    else:
        args.parser.print_help ()

if __name__ == '__main__':
    main ()
