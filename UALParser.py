import coloredlogs
import datetime
import errno
import ipaddress
import logging
import maxminddb
import os
from numpy import source
import pandas as pd
import getpass
import pyesedb as esedb
import sqlite3
import sys
import traceback
import uuid
import binascii
import struct
import time
from argparse import ArgumentParser
from configparser import ConfigParser
from datetime import datetime, timedelta
from binascii import unhexlify
from pandas.core.frame import DataFrame
from pandas.io.parsers import ParserError
from struct import unpack

__author__ = 'Tim Taylor'
__version__ = '20211106'
__credit__ = 'Inspired by BriMor Labs/KStrike'

"""
BSD 3-Clause License

Copyright (c) 2021, Tim Taylor
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Requirements:
* Python3
* Colorlogs (pip install colorlog)
* maxminddb (pip install maxminddb)
* Pandas (pip install pandas)
* libesedb (pyesedb) (compile from source:  https://github.com/libyal/libesedb)  (pip install libesedb-python failed for 3.8 and 3.9, YMMVH)
* GeoLite2-City.mmdb (https://www.maxmind.com)

Artifact References:
https://www.crowdstrike.com/blog/user-access-logging-ual-overview/
https://advisory.kpmg.us/blog/2021/digital-forensics-incident-response.html
https://en.wikipedia.org/wiki/Extensible_Storage_Engine

"""

class LogClass:
    def __init__(self, logname, debug_level=20):

        """
        Critical == 50
        Error == 40
        Warning == 30
        Info == 20
        Debug == 10
        Notset = 0
        """
        current_user = getpass.getuser()

        # log_format = '%(asctime)s:%(levelname)s:%(message)s'
        # date_fmt = '%m/%d/%Y %I:%M:%S'
        # logging.basicConfig(filename=logname, format=log_format, level=debug_level, filemode='a', datefmt=date_fmt)
        # console = logging.StreamHandler()
        # console.setLevel(debug_level)

        # formatter = logging.Formatter(log_format)
        
        # console.setFormatter(formatter)
        # logging.getLogger('').addHandler(console)

        clr_log_format = '%(asctime)s:%(hostname)s:%(programname)s:%(username)s[%(process)d]:%(levelname)s:%(message)s'
        coloredlogs.install(level=debug_level, fmt=clr_log_format)


    @staticmethod
    def log(level='info', message=''):
        if level.lower() == 'debug':
            logging.debug(message)
        if level.lower() == 'info':
            logging.info(message)
        if level.lower() == 'warning':
            logging.warning(message)
        if level.lower() == 'error':
            logging.error(message)
        if level.lower() == 'critical':
            logging.critical(message)


class PrepClass:
    def __init__(self, raw_output_path):
        self.raw_output_path = raw_output_path
        self.log_file = os.path.join(self.raw_output_path, 'Script Processing.log')
        self.sql_db = os.path.join(self.raw_output_path, 'UAL_DB.sqlite')
        self.sql_file = ''
        self.db_setup = ''
        self.p_log = ''
        self.config = ''

    
    def setup_logging(self, debug_mode=False):  
        log_level = 'info'
        if debug_mode: 
            log_level = 'debug'

        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % log_level)

        self.p_log = LogClass(self.log_file, numeric_level)
        return self.p_log



    def setup_output_directory(self):
        if not os.path.exists(self.raw_output_path):
            try:
                os.makedirs(self.raw_output_path)
            except OSError as error:
                if error.errno != errno.EEXIST:
                    raise


class UALClass:
    def __init__(self, config_dict):

        self.config_dict = config_dict
        self.source_path =  config_dict['raw_input_path']
        self.ese_dbs = self.get_ese_files(self.source_path)
        self.out_path =  config_dict['raw_output_path']
        self.maxmind_db = config_dict['maxminddb']
        self.ftype = config_dict['ftype']
        self.plog = config_dict['p_log']
        self.sql_db = os.path.join(self.out_path, 'UAL.db')
        self.GUID = list()
        self.chained_databases = dict()
        self.system_identity = list()
        self.series_list = list()
        self.chain_db_df = pd.DataFrame() 
        self.role_ids_df = pd.DataFrame()
        self.system_identity_df = pd.DataFrame() 
        self.client_df = pd.DataFrame()
        self.dns_df = pd.DataFrame()
        self.role_access_df = pd.DataFrame()
        self.virtualmachine_df = pd.DataFrame()
        self.timeline_df = pd.DataFrame()

        # This will be overwritten if the SystemIdentity file is processed.
        self.role_ids = {
            '{C50FCC83-BC8D-4DF5-8A3D-89D7F80F074B}': 'Active Directory Certificate Services', 
            '{AD495FC3-0EAA-413D-BA7D-8B13FA7EC598}': 'Active Directory Domain Services',
            '{B4CDD739-089C-417E-878D-855F90081BE7}': 'Active Directory Rights Management Service', 
            '{910CBAF9-B612-4782-A21F-F7C75105434A}': 'BranchCache', 
            '{48EED6B2-9CDC-4358-B5A5-8DEA3B2F3F6A}': 'DHCP Server', 
            '{7CC4B071-292C-4732-97A1-CF9A7301195D}': 'FAX Server', 
            '{10A9226F-50EE-49D8-A393-9A501D47CE04}': 'File Server', 
            '{C23F1C6A-30A8-41B6-BBF7-F266563DFCD6}': 'FTP Server',
            '{DDE30B98-449E-4B93-84A6-EA86AF0B19FE}': 'MSMQ', 
            '{BBD85B29-9DCC-4FD9-865D-3846DCBA75C7}': 'Network Policy and Access Services', 
            '{7FB09BD3-7FE6-435E-8348-7D8AEFB6CEA3}': 'Print and Document Services', 
            '{952285D9-EDB7-4B6B-9D85-0C09E3DA0BBD}': 'Remote Access', 
            '{8CC0AC85-40F7-4886-9DAB-021519800418}': 'Reporting Services',
            '{2414BC1B-1572-4CD9-9CA5-65166D8DEF3D}': 'SQL Server Analysis Services',
            '{BD7F7C0D-7C36-4721-AFA8-0BA700E26D9E}': 'SQL Server Database Engine',
            '{D6256CF7-98FB-4EB4-AA18-303F1DA1F770}': 'Web Server', 
            '{4116A14D-3840-4F42-A67F-F2F9FF46EB4C}': 'Windows Deployment Services', 
            '{D8DC1C8E-EA13-49CE-9A68-C9DCA8DB8B33}': 'Windows Server Update Services',
            '{1479A8C1-9808-411E-9739-2D3C5923E86A}': 'Windows Server 2016 DatacenterRemote Desktop Gateway',  
            '{90E64AFA-70DB-4FEF-878B-7EB8C868F091}': 'Windows ServerRemote Desktop Services', 
            }

        self.main()

    def main(self):
        self.process_system_identity()
        self.process_chained_databases()
        self.write_system_identity()
        self.write_chain_db()


    def get_ese_files(self,source_path):
       ese_dbs = list()
       all_files = os.listdir(source_path)
       for file in all_files:
           if file.endswith('.mdb'):
               ese_dbs.append(os.path.join(source_path, file))
    
       return ese_dbs


    def process_chained_databases(self):
        
        for current_mdb in self.ese_dbs:
            if not (current_mdb.endswith('SystemIdentity.mdb')):
                self.plog.log('info', 'Processing DB File: {} '.format(current_mdb))
                table = ''
                table_list = list()
                
                try:
                    file_object = open(current_mdb, "rb")
                    esedb_file = esedb.file() 
                    esedb_file.open_file_object(file_object)

                except OSError as error:
                    self.plog.log('Critical', 'Invalid ESE database: {}'.format(error))
                    self.plog.log('Critical', 'Exception class is: {}'.format(error.__class__))
                    self.plog.log('Critical', 'Exception is: {}'.format(error.args))
                    exc_type, exc_value, exc_tb = sys.exc_info()
                    self.plog.log('Critical', traceback.format_exception(exc_type, exc_value, exc_tb)) 
                    self.plog.log('Critical', '{} was not parsed'.format(current_mdb))
                    pass


                number_of_tables = esedb_file.get_number_of_tables() 

                for i in range(0, number_of_tables):
                    table_dict = dict()
                    table_dict['number'] = i
                    table_dict['name'] = esedb_file.get_table(i).name
                    table = esedb_file.get_table(i)
                    table_dict['num_columns'] = table.get_number_of_columns()
                    table_dict['num_records'] = table.get_number_of_records()
                    table_list.append(table_dict)

                # Need to ensure DNS is processed first.
                for item in table_list:
                    if item['name'] ==  'DNS':
                        self.plog.log('info', 'Processing {} '.format(item['name']))
                        dns_dict = self.process_dns_table(current_mdb, esedb_file, item)

                for item in table_list:
                    if item['name'] ==  'CLIENTS':
                        self.plog.log('info', 'Processing {} '.format(item['name']))
                        self.process_clients_table(current_mdb, esedb_file, item)

                    if item['name'] ==  'ROLE_ACCESS':
                        self.plog.log('info', 'Processing {} '.format(item['name']))
                        self.process_role_access_table(current_mdb, esedb_file, item)

                    if item['name'] ==  'VIRTUALMACHINES':
                        self.plog.log('info', 'Processing {} '.format(item['name']))
                        self.process_virtualmachines_table(current_mdb, esedb_file, item)


    def process_dns_table(self, current_mdb, esedb_file,table_info):
        if table_info['num_records'] > 0:
            self.plog.log('info', 'Processing {} records in the DNS table'.format(table_info['num_records']))
            table = esedb_file.get_table(table_info['number'])
            c = 0
            for t in range(0, table_info['num_records']):
                c+=1
                r = table.get_record(t)
                dns = dict()
                ip_address = self.get_raw_data(r, r.get_column_type(1), 1).decode('utf-16').rstrip('\x00')
                dns[r.get_column_name(0)] = self.binary_to_datetime(self.get_raw_data(r, r.get_column_type(0), 0))
                dns[r.get_column_name(1)] = str(ip_address) 
                dns[r.get_column_name(2)] = self.get_raw_data(r, r.get_column_type(2), 2).decode('utf-16').rstrip('\x00')
                
                ipversion = ipaddress.ip_address(ip_address).version
                if ipversion == 4:
                    ip_address = ipaddress.IPv4Address(ip_address)
                else:
                    ip_address = ipaddress.IPv6Address(ip_address)

                if ip_address.is_private:
                    dns['Country'] = 'Private'

                else: 
                    dns['Country'] = self.maxminddb_lookup(ip_address)  

                if ip_address.version == 6:
                    link_local = ip_address.is_link_local
                    if link_local:
                        dns['Country'] = ', '.join([dns['Country'], 'Link Local'])

                dns['Source_File'] = os.path.basename(current_mdb)
                self.dns_df = self.dns_df.append(dns, ignore_index=True)  
                if c % 250 == 0:
                    self.plog.log('info', 'Added {} Records of {}'.format(str(c), table_info['num_records']))
            self.plog.log('info', 'Added {} Records of {}'.format(str(c), table_info['num_records']))

        else:
            self.plog.log('info', 'There were no records in the DNS table')


    def process_clients_table(self, current_mdb, esedb_file, table_info):
    
        if table_info['num_records'] > 0:
            self.plog.log('info', 'Processing {} records in the Client table'.format(table_info['num_records']))
            table = esedb_file.get_table(table_info['number'])
            c=0
            for t in range(0, table_info['num_records']):
                c+=1
                r = table.get_record(t)
                client = dict()
    
                role_guid = self.get_raw_data(r, r.get_column_type(0), 0)
                client[r.get_column_name(0)] = role_guid
                client['RoleName'] = self.role_ids.get(role_guid, 'Not Found')
                client[r.get_column_name(1)] = self.get_raw_data(r, r.get_column_type(1), 1)
                client[r.get_column_name(2)] = self.get_raw_data(r, r.get_column_type(2), 2)
                client[r.get_column_name(3)] = self.binary_to_datetime(self.get_raw_data(r, r.get_column_type(3), 3)) 
                client[r.get_column_name(4)] = self.binary_to_datetime(self.get_raw_data(r, r.get_column_type(4), 4))
            
                ip_address = self.hex_to_ip(self.get_raw_data(r, r.get_column_type(5), 5))
                client[r.get_column_name(5)] = str(ip_address) 
                
                if ip_address.is_private:
                    client['Country'] = 'Private'
                else: 
                    client['Country'] = self.maxminddb_lookup(ip_address)  

                if ip_address.version == 6:
                    link_local = ip_address.is_link_local
                    if link_local:
                        client['Country'] = ', '.join([client['Country'], 'Link Local'])

                # Add dns_dict data here
                if self.dns_df.empty:
                    client['DNSLookup'] = 'No DNS Data Found'
                
                else:
                    
                    ip = str(ip_address)    
                    source_file = os.path.basename(current_mdb)  

                    host_name_row_df = self.dns_df.query('Address == @ip and Source_File == @source_file')
                    
                    if host_name_row_df.empty:
                        client['DNSLookup'] = 'Not found'

                    else:
                        max_row, max_col = host_name_row_df.shape
                        if max_row > 1:
                            dns_lookup_dict = host_name_row_df.to_dict(orient='records')
                            t = list()
                            for item in dns_lookup_dict:
                                hn = item['HostName']
                                ls = item['LastSeen']
                                t.append(''.join([item['HostName'], ' : ', item['LastSeen'], ' ']))
                            
                            client['DNSLookup'] = ','.join(t)

                        else:
                            hn = host_name_row_df['HostName'].values
                            ls = host_name_row_df['LastSeen'].values

                            client['DNSLookup'] = ' : '.join([hn[0], ls[0]])

                client[r.get_column_name(6)] = self.get_raw_data(r, r.get_column_type(6), 6).decode('utf-16').rstrip('\x00')
                client[r.get_column_name(7)] = self.get_raw_data(r, r.get_column_type(7), 7)
                
                # Noted in research there is a guid.mdb for the current year.
                # Since I don't know how the guids are derived each new year, I'm not hard coding the guid to year mapping
                # Best Effort to get the correct year is attempted

                current_year = ''
                if source_file == 'Current.mdb':
                    current_year = client['LastAccess'][:4]
                
                else:
                    current_year = self.get_year(source_file)
                    if not current_year:
                        current_year = client['LastAccess'][:4]

                access_dates = list()
                for c_num in range (8, table_info['num_columns']):
                    c_name =r.get_column_name(c_num)
                    c_value = self.get_raw_data(r, r.get_column_type(c_num), c_num)

                    if c_value > 0:
                        c_name = c_name.replace('Day','')

                        converted_j_date = self.convert_julian_date(''.join([current_year[-2:], str(c_name)]))
                        access_dates.append('{}: {}'.format(converted_j_date, c_value))
                        
                    client[r.get_column_name(c_num)] = self.get_raw_data(r, r.get_column_type(c_num), c_num)
                    # ''.join(access_dates).strip(', ')  
                    client['OtherAccessCount'] = ', '.join(access_dates).strip(', ')  

                client['Source_File'] = source_file
                
                self.client_df = self.client_df.append(client, ignore_index=True)  

                if c % 250 == 0:
                    self.plog.log('info', 'Added {} Records of {}'.format(str(c), table_info['num_records']))
            self.plog.log('info', 'Added {} Records of {}'.format(str(c), table_info['num_records']))
        else:
            self.plog.log('info', 'There were no records in the Client table')


    def process_role_access_table(self, current_mdb, esedb_file, table_info):
        if table_info['num_records'] > 0:
            self.plog.log('info', 'Processing {} records in the ROLE_ACCESS table'.format(table_info['num_records']))
            table = esedb_file.get_table(table_info['number'])
            for t in range(0, table_info['num_records']):
                r = table.get_record(t)
                ra = dict()
                ra[r.get_column_name(0)] = self.get_raw_data(r, r.get_column_type(0), 0)
                ra[r.get_column_name(1)] = self.binary_to_datetime(self.get_raw_data(r, r.get_column_type(1), 1))
                ra[r.get_column_name(2)] = self.binary_to_datetime(self.get_raw_data(r, r.get_column_type(2), 2))
                ra['Source_File'] = os.path.basename(current_mdb)
                self.role_access_df = self.role_access_df.append(ra, ignore_index=True)  
        else:
            self.plog.log('info', 'There were no records in the ROLE_ACCESS table')   


    def process_virtualmachines_table(self, current_mdb, esedb_file, table_info):
        if table_info['num_records'] > 0:
            self.plog.log('info', 'Processing {} records in the VirtualMachines table'.format(table_info['num_records']))
            table = esedb_file.get_table(table_info['number'])
            for t in range(0, table_info['num_records']):
                r = table.get_record(t)
                vm = dict()
                vm[r.get_column_name(0)] = self.get_raw_data(r, r.get_column_type(0), 0)
                vm[r.get_column_name(1)] = self.get_raw_data(r, r.get_column_type(1), 1)
                vm[r.get_column_name(2)] = self.get_raw_data(r, r.get_column_type(2), 2)
                vm[r.get_column_name(3)] = self.get_raw_data(r, r.get_column_type(3), 3)
                vm[r.get_column_name(4)] = self.get_raw_data(r, r.get_column_type(4), 4)
                vm['Source_File'] = os.path.basename(current_mdb)
                
            self.virtualmachine_df = self.virtualmachine_df.append(vm, ignore_index=True)  
        else:
            self.plog.log('info', 'There were no records in the VIRTUALMACHINES table')


    def process_system_identity(self):
    
        system_identity_file = os.path.join(self.source_path, 'SystemIdentity.mdb')
        if os.path.isfile(system_identity_file):

            self.plog.log('info', 'Processing {} '.format(os.path.basename(system_identity_file)))

            if system_identity_file:
                table = ''
                table_list = list()
                try:
                    file_object = open(system_identity_file, "rb")
                    esedb_file = esedb.file() 
                    esedb_file.open_file_object(file_object)

                except OSError as error:
                    self.plog.log('Critical', 'Invalid ESE database: {}'.format(error))
                    self.plog.log('Critical', 'Exception class is: {}'.format(error.__class__))
                    self.plog.log('Critical', 'Exception is: {}'.format(error.args))
                    exc_type, exc_value, exc_tb = sys.exc_info()
                    self.plog.log('Critical', traceback.format_exception(exc_type, exc_value, exc_tb)) 
                    self.plog.log('Critical', '{} was not parsed'.format(system_identity_file))
                    pass

                number_of_tables = esedb_file.get_number_of_tables() 

                for i in range(0, number_of_tables):
                    table_dict = dict()
                    table_dict['number'] = i
                    table_dict['name'] = esedb_file.get_table(i).name
                    table = esedb_file.get_table(i)
                    table_dict['num_columns'] = table.get_number_of_columns()
                    table_dict['num_records'] = table.get_number_of_records()
                    table_list.append(table_dict)

                for item in table_list:
    
                    if item['name'] == 'ROLE_IDS':
                        table = esedb_file.get_table(item['number'])
                        self.plog.log('info', 'Processing {} records in the ROLE_IDS table'.format(item['num_records']))
                        for t in range(0, item['num_records']):
                            GUID_dict = dict()
                            record = table.get_record(t)

                            GUID_dict['RoleGUID'] = self.get_raw_data(record, record.get_column_type(0), 0)
                            GUID_dict['ProductName'] = self.get_raw_data(record, record.get_column_type(1), 1).decode('utf-16').rstrip('\x00')
                            GUID_dict['RoleName'] = self.get_raw_data(record, record.get_column_type(2), 2).decode('utf-16').rstrip('\x00')
                            self.GUID.append(GUID_dict)
                        self.role_ids_df = self.role_ids_df.append( self.GUID, ignore_index=True)         

                        # re-setting the dictionary since we have a better data from this table
                        self.role_ids = dict()
                        for index, row in self.role_ids_df.iterrows():
                            self.role_ids[row['RoleGUID']] = row['RoleName']


                    elif item['name'] == 'CHAINED_DATABASES':
                        table = esedb_file.get_table(item['number'])
                        self.plog.log('info', 'Processing {} records in the CHAINED_DATABASES table'.format(item['num_records']))
                        chained_databases = dict()
                        for t in range(0, item['num_records']):
                            record = table.get_record(t)
                            chained_databases['Year'] = str(record.get_value_data_as_integer(0))
                            chained_databases['FileName'] = record.get_value_data(1).decode('utf-16', 'ignore').rstrip('\x00')

                            self.chain_db_df = self.chain_db_df.append(chained_databases, ignore_index=True) 
                
                    elif item['name'] == 'SYSTEM_IDENTITY':
                        
                        table = esedb_file.get_table(item['number'])
                        self.plog.log('info', 'Processing {} records in the SYSTEM_IDENTITY table'.format(item['num_records']))
                        
                        for t in range(0, item['num_records']):
                            system_identity = dict()
                            r = table.get_record(t)

                            system_identity['CreationTime'] = self.binary_to_datetime(self.get_raw_data(r, r.get_column_type(0), 0))
                            system_identity['PhysicalProcessorCount'] = self.get_raw_data(r, r.get_column_type(1), 1)
                            system_identity['CoresPerPhysicalProcessor'] = self.get_raw_data(r, r.get_column_type(2), 2)
                            system_identity['LogicalProcessorsPerPhysicalProcessor'] = self.get_raw_data(r, r.get_column_type(3), 3)
                            system_identity['MaximumMemory'] = self.get_raw_data(r, r.get_column_type(4), 4)
                            system_identity['OSMajor'] = self.get_raw_data(r, r.get_column_type(5), 5)
                            system_identity['OSMinor'] = self.get_raw_data(r, r.get_column_type(6), 6)
                            system_identity['OSBuildNumber'] = self.get_raw_data(r, r.get_column_type(7), 7)
                            system_identity['OSPlatformId'] = self.get_raw_data(r, r.get_column_type(8), 8)
                            system_identity['ServicePackMajor'] = self.get_raw_data(r, r.get_column_type(9), 9)
                            system_identity['ServicePackMinor'] = self.get_raw_data(r, r.get_column_type(10), 10)
                            system_identity['OSSuiteMask'] = self.get_raw_data(r, r.get_column_type(11), 11)
                            system_identity['OSProductType'] = self.get_raw_data(r, r.get_column_type(12), 12)
                            system_identity['OSCurrentTimeZone'] = self.get_raw_data(r, r.get_column_type(13), 13)
                            try:
                                system_identity['OSDaylightInEffect'] = self.get_raw_data(r, r.get_column_type(14), 14).decode('utf-16').rstrip('\x00')

                            except UnicodeDecodeError:
                                value = self.get_raw_data(r, r.get_column_type(14), 14)
                                if value in (b'\xff', b'\x00' ):
                                    system_identity['OSDaylightInEffect'] = ""
                                else:
                                    system_identity['OSDaylightInEffect'] = value

                            system_identity['SystemManufacturer'] = self.get_raw_data(r, r.get_column_type(15), 15).decode('utf-16').rstrip('\x00')
                            system_identity['SystemProductName'] = self.get_raw_data(r, r.get_column_type(16), 16).decode('utf-16').rstrip('\x00')
                            system_identity['SystemSMBIOSUUID'] = self.get_raw_data(r, r.get_column_type(17), 17).decode('utf-16').rstrip('\x00')
                            system_identity['SystemSerialNumber'] = self.get_raw_data(r, r.get_column_type(18), 18).decode('utf-16').rstrip('\x00')
                            system_identity['SystemDNSHostName'] = self.get_raw_data(r, r.get_column_type(19), 19).decode('utf-16').rstrip('\x00')
                            system_identity['SystemDomainName'] = self.get_raw_data(r, r.get_column_type(20), 20).decode('utf-16').rstrip('\x00')
                            system_identity['OSSerialNumber'] = self.get_raw_data(r, r.get_column_type(21), 21).decode('utf-16').rstrip('\x00')
                            system_identity['OSCountryCode'] = self.get_raw_data(r, r.get_column_type(22), 22).decode('utf-16').rstrip('\x00')
                            system_identity['OSLastBootUpTime'] = self.get_raw_data(r, r.get_column_type(23), 23).decode('utf-16').rstrip('\x00')
                            self.system_identity.append(system_identity)
                        self.system_identity_df = self.system_identity_df.append(self.system_identity, ignore_index=True) 

                    else:
                        self.plog.log('WARN', 'No Tables processed in SystemIdentity.mdb')      

        else:
            self.plog.log('warn', '{} Was not found in {}'.format(os.path.basename(system_identity_file), self.source_path))


    def get_table_data(self):

       # record = pd.Series(series_list, index=header) 
       # df = df.append(record, ignore_index=True) 


       for file in self.get_ese_files:
           print(file)
           table = ''
           table_list = list()
           table_num_columns  = 0
           table_num_records = 0

           file_object = open(file, "rb")

           esedb_file = esedb.file() 
           esedb_file.open_file_object(file_object) 
           num_of_tables = esedb_file.get_number_of_tables()

           for i in range (0, num_of_tables):
               table_dict = dict()
               table_dict['number'] = i
               table_dict['name'] = esedb_file.get_table(i).name
               table = esedb_file.get_table(i)
               table_dict['num_columns'] = table.get_number_of_columns()
               table_dict['num_records'] = table.get_number_of_records()
               table_list.append(table_dict)

           for item in table_list:
               print(item['name'])
               table = esedb_file.get_table(item['number'])

               for t in range(0, item['num_records']):
                   for x in range(0, table_dict['num_columns']-2):
                       table_record = table.get_record(t)
                       column_name = table_record.get_column_name(x)
                       column_type = table_record.get_column_type(x)
                       column_data = table_record.get_value_data(x)
                        
                       print('Column Name: {}'.format(column_name))
                       print('Column Type: {}'.format(column_type))
                       print(column_data)


    def binary_to_datetime(self, date_binary): 

       decimal_value = int(struct.unpack("<Q",date_binary)[0]) 

       try:
           hr_datetime = datetime(1601,1,1,0,0,0) + timedelta(microseconds=decimal_value/10) #Yay math!
    
       except:
           hr_datetime = "UNRECOGNIZED TIMESTAMP"

       return str(hr_datetime)


    def hex_to_ip(self, data_binary):
        ip_address ='Invalid Address'

        if len(data_binary) == 8:
            try:
                ip_address = ipaddress.IPv4Address(int(data_binary, 16))

            except ipaddress.AddressValueError as e:
                pass

        elif len(data_binary) == 32:
            data_string = data_binary.decode('utf-8')
            format_ipv6 = ':'.join(data_string[i:i + 4] for i in range(0, len(data_string), 4))
            try:
                ip_address = ipaddress.IPv6Address(format_ipv6)
            
            except ipaddress.AddressValueError as e:
                pass
            
        else:
            ip_address = 'Invalid IP Address: {}'.format(data_binary)

        return ip_address
  

    def get_year(self, source_file):
        return self.chain_db_df.query('FileName == @source_file')['Year'].values[0]


    def convert_julian_date(self, j_date):
        return datetime.strptime(j_date, '%y%j').date().strftime('%Y-%m-%d')
       

    def maxminddb_lookup(self, ip_address):
        self.plog.log('debug', 'Lookup {} '.format(str(ip_address)))
        result = ''
        
        with maxminddb.open_database(self.maxmind_db) as reader:
            geo_dict = reader.get(str(ip_address)) 
            self.plog.log('debug', 'Geo Record for IP {} was {}:'.format(str(ip_address), geo_dict))
            if geo_dict:
                result = geo_dict['country'].get('iso_code', 'Country Not Found')                
                if result == 'Country Not Found':                     
                    result = geo_dict['registered_country'].get('iso_code', 'Registered Country Not Found') 
            else:
                result = 'No Maxmind record found for {}'.format(str(ip_address))
                
        self.plog.log('debug', '{}'.format(result))
        return result


    def get_raw_data(self, record, c_type, c_num):
        if c_type == 0:    # Null
            return 'None'

        elif c_type == 1:  #Boolean
            if (record.get_value_data(c_num) == None):
                return 'None'
            else:
                return record.get_value_data(c_num)

        elif c_type == 2:   #INTEGER_8BIT_UNSIGNED
            if (record.get_value_data_as_integer(c_num) == None):
                return 'None'
            else:
                return record.get_value_data_as_integer(c_num)
        
        elif c_type == 3:  #INTEGER_16BIT_SIGNED
            if (record.get_value_data_as_integer(c_num) == None):
                return 'None'
            else:
                return record.get_value_data_as_integer(c_num)

        elif c_type == 4: #INTEGER_32BIT_SIGNED
            if (record.get_value_data_as_integer(c_num) == None):
                return 'None'
            else:
                return record.get_value_data_as_integer(c_num)

        elif c_type == 5:  #CURRENCY
            if (record.get_value_data_as_integer(c_num) == None):
               return 'None'
            else:
                return record.get_value_data_as_integer(c_num)

        elif c_type == 6:   #DOUBLE_64BIT
            if (record.get_value_data_as_floating_point(c_num) == None):
                return 'None'
            else:
                return str(record.get_value_data_as_floating_point(c_num))
            
        elif c_type ==  7: #DOUBLE_64BIT
            if (record.get_value_data_as_floating_point(c_num) == None):
                return 'None'
            else:
                return str(record.get_value_data_as_floating_point(c_num))

        elif c_type == 8:  #DATETIME	
            if (record.get_value_data(c_num) == None):
                return 'None'
            else:
                return record.get_value_data(c_num)

        elif c_type == 9: #BINARY_DATA_TO_HEX
            value = record.get_value_data(c_num)
            if value == None:
                return 'None'

            else:
                return binascii.hexlify(value)

        elif c_type == 10: #TEXT	
            if (record.get_value_data(c_num) == None):
                return 'None'
            else:
                return record.get_value_data(c_num)
        
        elif c_type == 11:  #LARGE_BINARY_DATA
            if (record.get_value_data(c_num) == None):
                return 'None'
            else:
                return record.get_value_data(c_num)
        
        elif c_type == 12: #LARGE_TEXT
            if (record.get_value_data(c_num) == None):
                return 'None'
            else:
                return record.get_value_data(c_num)
    
        elif c_type == 13: #SUPER_LARGE_VALUE
            if (record.get_value_data_as_integer(c_num) == None):
                return 'None'
            else:
                return record.get_value_data_as_integer(c_num)
       
        elif c_type == 14:  #INTEGER_32BIT_UNSIGNED	
            if (record.get_value_data_as_integer(c_num) == None):
                return 'None'
            else:
                return record.get_value_data_as_integer(c_num)
    
        elif c_type == 15:  #INTEGER_64BIT_SIGNED
            if (record.get_value_data_as_integer(c_num) == None):
                return 'None'
            else:
                return record.get_value_data_as_integer(c_num)
    
        elif c_type == 16:  #GUID	
            if (record.get_value_data(c_num) == None):
                return 'None'
            else:
                value = record.get_value_data(c_num)
                orgguid = uuid.UUID(bytes_le=value) 
                urnguid=orgguid.urn
                rawguid = urnguid[9:]
                ucrawguid=rawguid.upper() 
                fullguid='{'+ucrawguid+'}' 
                return fullguid
    
        elif c_type == 17: #INTEGER_16BIT_UNSIGNED
            value = record.get_value_data_as_integer(c_num)
            if (record.get_value_data_as_integer(c_num) == None):
                return 'None'
            else:
                return record.get_value_data_as_integer(c_num)


    def write_system_identity(self):
        
        self.plog.log('info', 'Writing System Identity to xlsx')
        xlsx_file = os.path.join(self.out_path, 'System_Identity.xlsx')

        chained_db_csv_file = os.path.join(self.out_path, 'CHAINED_DATABASES.csv')
        roles_ids_csv_file = os.path.join(self.out_path, 'ROLE_IDS.csv')
        system_identity_csv_file = os.path.join(self.out_path, 'SYSTEM_IDENTITY.csv')

        chain_db_header = ['FileName', 'Year']
        RoleID_header = ['Role_GUID', 'ProductName', 'RoleName']
        system_identity_header = ['CreationTime', 'PhysicalProcessorCount', 'CoresPerPhysicalProcessor', 'LogicalProcessorsPerPhysicalProcessor', 'MaximumMemory', 
                    'OSMajor', 'OSMinor', 'OSBuildNumber', 'OSPlatformId', 'ServicePackMajor', 'ServicePackMinor', 'OSSuiteMask', 'OSProductType', 
                    'OSCurrentTimeZone', 'OSDaylightInEffect', 'SystemManufacturer', 'SystemProductName', 'SystemSMBIOSUUID', 'SystemSerialNumber', 
                    'SystemDNSHostName', 'SystemDomainName', 'OSSerialNumber', 'OSCountryCode', 'OSLastBootUpTime']
        
        chain_db_max_rows, chain_db_max_columns = self.chain_db_df.shape
        role_ids_max_rows, role_ids_max_columns = self.role_ids_df.shape
        system_identity_max_rows, system_identity_max_columns = self.system_identity_df.shape

        if self.ftype.lower() == 'csv':
           
            if chain_db_max_rows > 0:
                self.chain_db_df.to_csv(chained_db_csv_file, header=True, index=False, na_rep='')
                
            if role_ids_max_rows > 0:
                self.role_ids_df.to_csv(roles_ids_csv_file, header=True, index=False, na_rep='')

            if system_identity_max_rows > 0:
                self.system_identity_df.to_csv(system_identity_csv_file, header=True, index=False, na_rep='')


        elif self.ftype.lower() == 'json':
            
            if chain_db_max_rows > 0:
                json_file = chained_db_csv_file.replace('csv','json')
                self.chain_db_df.to_json(json_file, orient='records', date_format='iso', lines=True,index=True)

            if role_ids_max_rows > 0:
                json_file = roles_ids_csv_file.replace('csv','json')
                self.role_ids_df.to_json(json_file, orient='records', date_format='iso', lines=True,index=True)
            
            if system_identity_max_rows > 0:
                json_file = system_identity_csv_file.replace('csv','json')
                self.system_identity_df.to_json(json_file, orient='records', date_format='iso', lines=True,index=True)


        elif self.ftype.lower() == 'sqlite':
            conn = sqlite3.connect(self.sql_db)

            self.chain_db_df.to_sql('chain_dbs', con=conn, if_exists='replace', index=False)
            self.role_ids_df.to_sql('role_ids', con=conn, if_exists='replace', index=False)
            self.system_identity_df.to_sql('system_identitiy', con=conn, if_exists='replace', index=False)
            conn.commit()
            conn.close()


        else:

            with pd.ExcelWriter(xlsx_file, date_format='YYYY-MM-DD HH:MM:SS') as writer:
                # chain_db
 
                self.chain_db_df.to_excel(writer, sheet_name='ChainDB', startrow=0, header=True, index=False)
                
                workbook  = writer.book

                header_format = workbook.add_format({
                    'bold': True,
                    'text_wrap': True,
                    'valign': 'top',
                    'fg_color': '#0070C0',
                    'border': 1})
                        
                body_format = workbook.add_format({
                    'text_wrap': True,
                    'align': 'left',
                    'valign': 'top'
                    })

                worksheet = writer.sheets['ChainDB']
                worksheet.set_column('A:C', 50, body_format)
                worksheet.write_row(0,0, chain_db_header, header_format)
                worksheet.autofilter(0, 0, chain_db_max_rows, chain_db_max_columns-1)
                worksheet.freeze_panes(1, 0)

                # ROLE_IDS
                
                self.role_ids_df.to_excel(writer, sheet_name='Role IDs', startrow=0, header=True, index=False)
                
                worksheet = writer.sheets['Role IDs']
                worksheet.set_column('A:C', 50, body_format)
                worksheet.write_row(0, 0, RoleID_header, header_format)
                worksheet.autofilter(0, 0, role_ids_max_rows, role_ids_max_columns-1)
                worksheet.freeze_panes(1, 0)

                # SYSTEM_IDENTITY

                self.system_identity_df.to_excel(writer, sheet_name='SYSTEM_IDENTITY', startrow=0, header=True, index=False)
                
                worksheet = writer.sheets['SYSTEM_IDENTITY']
                worksheet.set_column('A:C', 25, body_format)
                worksheet.set_column('D:D', 40, body_format)
                worksheet.set_column('E:E', 20, body_format)
                worksheet.set_column('F:F', 11, body_format)
                worksheet.set_column('G:G', 11, body_format)
                worksheet.set_column('H:H', 20, body_format)
                worksheet.set_column('I:I', 15, body_format)
                worksheet.set_column('J:J', 20, body_format)
                worksheet.set_column('K:K', 20, body_format)
                worksheet.set_column('L:L', 15, body_format)
                worksheet.set_column('M:M', 20, body_format)
                worksheet.set_column('N:N', 21, body_format)
                worksheet.set_column('O:O', 20, body_format)
                worksheet.set_column('P:P', 22, body_format)
                worksheet.set_column('Q:Q', 30, body_format)
                worksheet.set_column('R:R', 40, body_format)
                worksheet.set_column('S:S', 35, body_format)
                worksheet.set_column('T:T', 25, body_format)
                worksheet.set_column('U:U', 25, body_format)
                worksheet.set_column('V:V', 25, body_format)
                worksheet.set_column('W:W', 17, body_format)
                worksheet.set_column('X:X', 26, body_format)
                worksheet.write_row(0, 0, system_identity_header, header_format)
                worksheet.autofilter(0, 0, system_identity_max_rows, system_identity_max_columns-1)
                worksheet.freeze_panes(1, 0)


    def write_chain_db(self):
        self.plog.log('info', 'Writing Chain databases to xlsx')
        xlsx_file = os.path.join(self.out_path, 'Chain_DBs.xlsx')
        csv_file = os.path.join(self.out_path, 'CLIENTS.csv')
        dns_csv_file = os.path.join(self.out_path, 'DNS.csv')
        role_access_csv_file = os.path.join(self.out_path, 'ROLE_ACCESS.csv')
        vm_csv_file = os.path.join(self.out_path, 'VirtualMachines.csv')

        # Format DF's
        client_header = self.format_chain_df()
        dns_header = self.format_dns_df()
        role_access_header = self.format_role_access_df()
        vm_header = self.format_vm_df()

        client_max_rows, client_max_columns = self.client_df.shape
        dns_max_rows, dns_max_columns = self.dns_df.shape
        ra_max_rows, ra_max_columns = self.role_access_df.shape
        vm_max_rows, vm_max_columns = self.virtualmachine_df.shape

        if self.ftype.lower() == 'csv': 
            
            if client_max_rows > 0:
                self.client_df.to_csv(csv_file, header=True, index=False, na_rep='')

            if dns_max_rows > 0:
                self.dns_df.to_csv(dns_csv_file, header=True, index=False, na_rep='')
            
            if ra_max_rows > 0:
                self.role_access_df.to_csv(role_access_csv_file, header=True, index=False, na_rep='')

            if vm_max_rows > 0:
                self.virtualmachine_df.to_csv(vm_csv_file, header=True, index=False, na_rep='')


        elif self.ftype.lower() == 'json':

            if client_max_rows > 0:
                json_file = csv_file.replace('csv','json')
                self.client_df.to_json(json_file, orient='records', date_format='iso', lines=True,index=True)

            if dns_max_rows > 0:
                json_file = dns_csv_file.replace('csv','json')
                self.dns_df.to_json(json_file, orient='records', date_format='iso', lines=True,index=True)
            
            if ra_max_rows > 0:
                json_file = role_access_csv_file.replace('csv','json')
                self.role_access_df.to_json(json_file, orient='records', date_format='iso', lines=True,index=True)

            if vm_max_rows > 0:
                json_file = vm_csv_file.replace('csv','json')
                self.virtualmachine_df.to_json(json_file, orient='records', date_format='iso', lines=True,index=True)
           

        elif self.ftype.lower() == 'sqlite':
            conn = sqlite3.connect(self.sql_db)
            self.client_df.to_sql('clients', con=conn, if_exists='replace', index=False, method=None)
            self.dns_df.to_sql('dns', con=conn, if_exists='replace', index=False, method=None)
            self.role_access_df.to_sql('role_acccess', con=conn, if_exists='replace', index=False, method=None)
            self.virtualmachine_df.to_sql('virtual_machine', con=conn, if_exists='replace', index=False, method=None)
            conn.close()

        else:
            with pd.ExcelWriter(xlsx_file, date_format='YYYY-MM-DD HH:MM:SS') as writer:
                workbook = writer.book
                header_format = workbook.add_format({
                    'bold': True,
                    'text_wrap': True,
                    'valign': 'top',
                    'fg_color': '#0070C0',
                    'border': 1})

                body_format = workbook.add_format({'text_wrap': True,'align': 'left','valign': 'top'})
                body_format.set_num_format('@')
        
                # Clients Db

                if client_max_rows > 0:

                    self.client_df.to_excel(writer, sheet_name='Clients', startrow=1, header=False, index=False)
                    worksheet = writer.sheets['Clients']
                    worksheet.write_row(0, 0, client_header, header_format)
                    worksheet.set_column('A:A', 35, body_format)
                    worksheet.set_column('B:B', 50, body_format)
                    worksheet.set_column('C:E', 40, body_format)
                    worksheet.set_column('F:G', 17, body_format)
                    worksheet.set_column('H:I', 25, body_format)
                    worksheet.set_column('J:J', 16, body_format)
                    worksheet.set_column('K:K', 40, body_format)
                    worksheet.set_column('L:L', 15, body_format)
                    worksheet.set_column('M:M', 45, body_format)

                    worksheet.autofilter(0, 0, client_max_rows, client_max_columns-1)
                    worksheet.freeze_panes(1, 0)

                #DNS
                
                if dns_max_rows > 0:

                    self.dns_df.to_excel(writer, sheet_name='DNS', startrow=1, header=False, index=False)
                    worksheet = writer.sheets['DNS']
                    worksheet.write_row(0, 0, dns_header, header_format)
                    worksheet.set_column('A:A', 25, body_format)
                    worksheet.set_column('B:B', 25, body_format) 
                    worksheet.set_column('C:C', 25, body_format)
                    worksheet.set_column('D:D', 25, body_format)
                    worksheet.set_column('E:E', 50, body_format)
                    worksheet.write_row(0, 0, dns_header, header_format)
                    worksheet.autofilter(0, 0, dns_max_rows, dns_max_columns-1)
                    worksheet.freeze_panes(1, 0)

                # ROLE_ACCESS
                
                if ra_max_rows > 0:
                    
                    self.role_access_df.to_excel(writer, sheet_name='ROLE_ACCESS', startrow=1, header=False, index=False)
                    worksheet = writer.sheets['ROLE_ACCESS']
                    worksheet.write_row(0, 0, role_access_header, header_format)
                    worksheet.set_column('A:A', 40, body_format)
                    worksheet.set_column('B:B', 25, body_format)
                    worksheet.set_column('C:C', 25, body_format)
                    worksheet.set_column('D:D', 50, body_format)
                    worksheet.write_row(0, 0, role_access_header, header_format)
                    worksheet.autofilter(0, 0, ra_max_rows, ra_max_columns-1)
                    worksheet.freeze_panes(1, 0)

                # VirtualMachines

                if vm_max_rows > 0:
                    
                    self.virtualmachine_df.to_excel(writer, sheet_name='VirtualMachines', startrow=1, header=False, index=False)
                    worksheet = writer.sheets['VirtualMachines']
                    worksheet.write_row(0, 0, dns_header, header_format)
                    worksheet.set_column('A:A', 40, body_format)
                    worksheet.set_column('B:B', 20, body_format)
                    worksheet.set_column('C:C', 20, body_format)
                    worksheet.set_column('D:D', 20, body_format)
                    worksheet.set_column('E:E', 20, body_format)
                    worksheet.set_column('F:F', 150, body_format)
                    worksheet.write_row(0, 0, vm_header, header_format)
                    worksheet.autofilter(0, 0, vm_max_rows, vm_max_columns-1)
                    worksheet.freeze_panes(1, 0)


    def format_chain_df(self):
        header = ['RoleName','RoleGuid', 'AuthenticatedUserName','Address','DNSLookup','Country',
                    'TotalAccesses','InsertDate','LastAccess','OtherAccessCount','TenantId','ClientName','Source_File']
        if self.ftype.lower() == 'sqlite':
            header = header + list([a for a in self.client_df.columns if a not in header])
    
        self.client_df = self.client_df.reindex(columns=(header))
        return header


    def format_dns_df(self):
        header = ['LastSeen','Address','HostName','Country','Source_File']
        self.dns_df = self.dns_df.reindex(columns=(header))
        return header


    def format_role_access_df(self):
        header = ['RoleGuid','FirstSeen','LastSeen','Source_File']
        self.role_access_df = self.role_access_df.reindex(columns=(header))
        return header


    def format_vm_df(self):
        header = ['VmGuid','BIOSGuid','CreationTime','LastSeenActive','SerialNumber','Source_File']
        self.virtualmachine_df = self.virtualmachine_df.reindex(columns=(header))
        return header 



def main():
    parser = ArgumentParser(prog='UAL Processing', description='Parsing and Processing of the UAL ese databases.', usage='%(prog)s [options]', epilog='Version: {}'.format(__version__))
    parser.add_argument('-d', help='Path to directory contianing the database "\Windows\System32\LogFiles\SUM\" (Required)', action='store', dest='raw_input_path')
    parser.add_argument('-o', help='Path to write the output files (Required)', action='store', dest='raw_output_path') 
    parser.add_argument('-t', help='Output Type,Supported csv, json, sqlite and xlsx (Optional, default xlsx)', action='store', dest='ftype')                  
    parser.add_argument('--debug', help='Debug mode (More output to logs for troubleshooting)', action="store_true")
    parser.add_argument('-v', help='Show Version and exit.', action="store_true")
    args = parser.parse_args()

    if args.v:
        print('Version: {}'.format(__version__))
        sys.exit(0)

    script_start = time.time()
    script_path = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0])))

    config_file_path = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), 'settings.cfg'))
    if not os.path.isfile(config_file_path):
        print('Configuration file {} does not exist!'.format(config_file_path))
        sys.exit(-1)

    config = ConfigParser(allow_no_value=True)
    config.read([config_file_path])
        
    config.maxmind_config = dict(config.items("MAXMINDDB"))
    maxminddb = os.path.join(script_path, config.maxmind_config['maxminddb'])

    if not args.raw_input_path or not args.raw_output_path:
        parser.print_help()
        sys.exit(-1)

    if os.path.isdir(args.raw_input_path):
        prep = PrepClass(args.raw_output_path)
        p_log = prep.setup_logging(args.debug)
        prep.setup_output_directory()

        ftype = ''
        if not args.ftype:
            ftype = 'xlsx'
        else:
            ftype = args.ftype
        
        config_dict = {
            'raw_input_path':args.raw_input_path, 
            'raw_output_path': args.raw_output_path, 
            'maxminddb': maxminddb, 
            'ftype': ftype,
            'p_log': p_log
        }

        parser = UALClass(config_dict)

        end_time = time.time()
        total_minutes = ((end_time - script_start)/60)
        p_log.log('info', 'Script run time was {} minutes'.format("{0:,.2f}".format(total_minutes)))
        p_log.log('info', 'Script Finished, Version: {}'.format(__version__))


    else:
        print('Input path was invalid (-d):  {}'.format(args.raw_output_path))

    
if __name__ == "__main__":

    if sys.version_info[0] == 3:
        main()

    else:
        print('Python 3 is required')
        print('Detected Python {}.{}.{}'.format(sys.version_info[0], sys.version_info[1], sys.version_info[2])) 
            
