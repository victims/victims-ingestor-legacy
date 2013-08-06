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
from datetime import datetime, timedelta

mtime_fmt = "%j:%Y:%H:%M:%S"
CTIME_FMT = "%d:%m:%Y"
day_seconds = 86400

class VictimDB:
    """
    Class to provide an easy connection to the victims database
    """

    __hash_table = None # Reference to the table in use
    __hash_table_name = None # Name of the table in use
    __hash_db = None # Reference to the DB in use

    def __init__ (self, db_name='victims',
                  host=os.getenv ("OPENSHIFT_MONGODB_DB_HOST"),
                  port=int (os.getenv ("OPENSHIFT_MONGODB_DB_PORT")),
                  table='submissions'):

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
        if self.__hash_table == None:
            print "ERROR"

        # Save the table name and DB reference in case the table needs to be renewed
        self.__hash_table_name = table
        self.__hash_db = db


    def add_victim (self, package_name,
                    package_version,
                    vendor,
                    cves,
                    package_format,
                    package_url,
                    state='REQUESTED'):
        """
        Adds a potential victim entry to the victims database
        """

        if self.__hash_table.find ({'name' : package_name,
                                    'version' : package_version}) is not None:
            return -1
        else:
            date = datetime.strftime (datetime.utcnow (),
                                      CTIME_FMT)

            self.__hash_table.insert ({
                    'submitter' :
                        {'name' : "victims-ingestor"},
                    'name' : package_name,
                    'version' : package_version,
                    'vendor' : vendor,
                    'cves' : cve_list,
                    'format' : package_format,
                    'source' : package_url,
                    'approval' :
                        {'date' : date, 'status' : state},
                    'entry' : {}
                    })

        return 0

    def get_victim_entry (self, package_name, package_version):
        """
        Get a single victim entry that
        corresponds to the given parameters
        """

        return self.__hash_table.find_one ({'name' : package_name, 'version' : package_version})

    def get_victim_entries (self, package_name, package_version):
        """
        Get a list of all victim entries that
        correspond to the given parameters
        """

        return self.__hash_table.find ({'name' : package_name, 'version' : package_version})

    def create_cache (self, data):

        for p_name in data.keys ():
            for p_version in data[p_name].keys ():
                self.__hash_table.insert ({'name' : p_name,
                                           'version' : p_version,
                                           'cves' : data[p_name][p_version],
                                           'vendor' : data[p_name]['vendor']})

    def get_cache (self):
        entries = {}

        data = self.__hash_table.find ({'cache_att' : None})
        for entry in data:
            if entry['name'] not in entries:
                entries[entry['name']] = {}
                entries[entry['name']]['vendor'] = entry['vendor']

            entries[entry['name']][entry['version']] = entry['cves']

        return entries

    def renew_table (self):
        """
        Renew the table in use by recreating it from scratch
        """
        self.__hash_table.drop ()
        self.__hash_table = pymongo.collection.Collection (self.__hash_db,
                                                           self.__hash_table_name)

    def add_mtime_stamp (self):
        """
        Check if the cache is up to date
        """
        #Insert a new modified timestamp in to the cache collection
        mtimestr = datetime.strftime (datetime.utcnow (), mtime_fmt)
        self.__hash_table.insert ({'cache_att' : True, 'mtime' : mtimestr})

    def check_mtime_within (self, d_seconds=day_seconds):
        """
        Check if the cache is up to date
        """

        if self.__hash_table.find_one ({'cache_att' : True}):
            mtimestr = self.__hash_table.find_one ({'cache_att' : True})['mtime']
            mtime = datetime.strptime (mtimestr, mtime_fmt)

            if mtime >= (datetime.utcnow () - timedelta (seconds=d_seconds)):
                return True

        return False
