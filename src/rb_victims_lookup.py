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
    """
    Function that gathers the list of sources from the sources
    library, searches for the package name specified and adds
    it to the Victim DB submissions collection if vulnerable
    versions are found.

    Inputs :
    package_name - name of the package to be searched for.
    """
    entries = sources.get_entries ()

    '''
    Create a connection to the victims DB with
    a connection to the hashes collection.
    '''
    db_conn = victim_db_manager.VictimDB (victim_conn=True)

    if package_name in entries:
        for vuln_ver in entries[package_name].keys ():
            if vuln_ver == "vendor":
                continue

            if victim_file.package_exists (package_name, vuln_ver, 0):
                db_conn.add_victim (package_name,
                                    vuln_ver,
                                    entries[package_name]['vendor'],
                                    entries[package_name][vuln_ver],
                                    "ruby",
                                    victim_file.make_package_url (package_name, vuln_ver, 0))

    else:
        print "Error : Package not found in sources"

    return

def setup_args ():
    """
    Function to set up the OptionParser used to parse
    the arguments provided to the lookup tool.

    Outputs :
    Returns a tuple of the options and parser object.
    """

    parser = OptionParser ()

    '''
    Only add the agrument for the name of the
    victims package we are looking for.
    '''
    parser.add_option ("-n", "--name",
                       dest="name",
                       help="Name of the victim package to be searched for")

    (options, args) = parser.parse_args ()

    return (options, parser)

def main ():
    (options, parser) = setup_args ()

    if (options.name):
        find_similar_binary_by_name (options.name)
    else:
        parser.print_help ()

if __name__ == '__main__':
    main ()
