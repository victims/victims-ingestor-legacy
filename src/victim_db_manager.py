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
Module that provides a class that helps working with the
victims hash collection
'''

import pymongo
import os

class VictimDB:
    """
    Class to provide an easy connection to the victims database
    """

    __hash_table = None

    def __init__ (self, db_name='victims',
                  host=os.getenv ("OPENSHIFT_MONGODB_DB_HOST"),
                  port=int (os.getenv ("OPENSHIFT_MONGODB_DB_PORT")),
                  table='hashes'):

        try:
            '''
            If pymongo is version 2.3 or less we need
            to get a Connection object
            '''
            if float (pymongo.version) <= 2.3:
                client = pymongo.Connection (host, port)
            else:
                client = pymongo.MongoClient (host, port)

        except ConnectionFailure:
            raise

        try:
            db = client[db_name]

            if (os.getenv ("OPENSHIFT_MONGODB_DB_USERNAME") and
                os.getenv ("OPENSHIFT_MONGODB_DB_PASSWORD")):
                '''
                Authenticate against the given database
                using the credentials in the environment
                '''
                db.authenticate (os.getenv ("OPENSHIFT_MONGODB_DB_USERNAME"),
                                 os.getenv ("OPENSHIFT_MONGODB_DB_PASSWORD"))

        except InvalidName:
            raise ConnectionFailure ()

        self.__hash_table = pymongo.collection.Collection (db, table)


    def add_victim (self, cve_list,
                    vendor,
                    package_name,
                    package_version,
                    package_format,
                    state='PENDING'):
        """
        Adds a potential victim entry to the victims database
        """

        if self.__hash_table.find ({'name' : package_name,
                                    'version' : package_version}) is not None:
            return -1
        else:
            self.__hash_table.insert ({'name' : package_name,
                                       'version' : package_version,
                                       'vendor' : vendor,
                                       'format' : package_format,
                                       'hash' : hash_id,
                                       'state' : state})

        return 0

    def get_victim_entry (self, package_name, package_version):
        """
        Get a single victim entry that
        corresponds to the given parameters
        """

        return self.__hash_table.findOne ({'name' : package_name, 'version' : package_version})

    def get_victim_entries (self, package_name, package_version):
        """
        Get a list of all victim entries that
        correspond to the given parameters
        """

        return self.__hash_table.find ({'name' : package_name, 'version' : package_version})
