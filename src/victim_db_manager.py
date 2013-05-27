# Copyright 2013

# Pramod Dematagoda <pmd.lotr.gandalf@gmail.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
'''
Module that provides a class that helps working with the victims hash collection
'''

import pymongo

class VictimHashDB:
    '''
    Class to provide an easy connection to the victims database
    '''

    __hash_table = None

    def __init__ (self, db_name='victims', host='localhost', port=27017):
        client = pymongo.MongoClient (host, port)
        db = client[db_name]

        self.__hash_table = db['hashes']

    def add_victim_hash (self, cve_list, vendor, package_name, package_version, package_format, hash_id, state='PENDING'):
        self.__hash_table.insert ({'name' : package_name, 'version' : package_version, 'vendor' : vendor, 'hash' : hash_id})

    def get_victim_entry (self, package_name, package_version):
        return self.__hash_table.findOne ({'name' : package_name, 'version' : package_version})

    def get_victim_entries (self, package_name, package_version):
        return self.__hash_table.find ({'name' : package_name, 'version' : package_version})
