import argparse
from datetime import datetime,timedelta
import glob
import json
import logging.config
import os
import pprint
import re
import shlex
import signal
import subprocess
import sys
import time
import requests
requests.packages.urllib3.disable_warnings()

from sysmon_more import SysMonMore

from configparser import ConfigParser
from dateutil import tz
from queue import Queue
from threading import Thread

# logging 
LOGGER = logging.getLogger('sme')
LOGGER.setLevel(logging.DEBUG)
LOGGER.propagate = False
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
handler.setLevel(logging.DEBUG)
LOGGER.addHandler(handler)

# MAX number of threads performing splunk searches
#MAX_SEARCHES = 4

# Configuration file
HOME_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_PATH = os.path.join(HOME_DIR, 'etc', 'config.ini')


def clean_exit(signal, frame):
    print("\nExiting ..")
    sys.exit(0)
signal.signal(signal.SIGINT, clean_exit)


# custom ConfigParser to keep case sensitivity
class CaseConfigParser(ConfigParser):
    def optionxform(self, optionstr):
        return optionstr

class SysMonElasticsearch(object):
    def __init__(self):
        self.config = CaseConfigParser()
        # load configuration
        try:
            self.config.read('etc/config.ini')
        except Exception as e:
            logging.fatal("unable to load configuration from {0}: {1}".format(
                'etc/config.ini', str(e)))
            sys.exit(1)
        # initialize logging
        try:
            logging.config.fileConfig('etc/logging.ini')
        except Exception as e:
            sys.stderr.write("ERROR: unable to load logging config from {0}: {1}".format(
                'etc/logging.ini', str(e)))
            sys.exit(1)

    def search_to_json(self,search,index,filter_script,fields,earliest,latest,use_index_time,max_result_count):
        
        search_json = {
            'query': {
                'bool': {
                    'filter': [
                    {
                        'query_string': {
                            'query': search
                        }
                    },
                    self.get_time_spec_json(earliest,latest,use_index_time)
                    ]
                }
            }
        }
        if fields:
            search_json['_source'] = fields.split(',')
        #allow for index to not be set, many companies will create a field for the index alias instead of using elasticsearch's index pattern and just alias *
        if index:
            search_uri = "{}{}/_search".format(CONFIG['elk']['uri'],index)
        else:
            search_uri = "{}{}/_search".format(CONFIG['elk']['uri'],"*")
        if filter_script:
            script = {
                'script': {
                    'script' : filter_script
                }
            }
            search_json['query']['bool']['filter'].append(script)

        # set max result count
        if max_result_count is None:
            max_result_count = self.config['rule'].getint('max_result_count')
        search_json['size'] = max_result_count

        return search_json,search_uri

    def simple_search_json(self,search,host=None,earliest='now-365d',latest='now'):
        if 'log_source_identifier' in self.config['elk'].keys() and 'log_source_identifier_value' in self.config['elk'].keys():
            index = "{}:{}".format(self.config['elk']['log_source_identifier'],self.config['elk']['log_source_identifier_value'])
            if index not in search:
                search = "{} AND ({})".format(index,search)
        if host:
            search = "{}:{} AND {}".format(self.config['event_id_1']['Computer'],host,search)
        search_json = {
            'query': {
                'bool': {
                    'filter': [
                    {
                        'query_string': {
                            'query': search
                        }
                    }
                    ,
                    { "range": { self.config['elk']['event_time_field']: { "gt": earliest, "lte": latest } } }
                    ]
                }
            }
        }
        search_json['size'] = 10000
        return search_json

    def perform_query(self,search_json):
        # perform query
        search_uri = "{}{}/_search".format(self.config['elk']['uri'],self.config['elk']['index'])
        logging.info("executing search {}".format(json.dumps(search_json)))
        logging.debug("{}".format(json.dumps(search_json)))
        headers = {'Content-type':'application/json'}
        search_result = requests.get(search_uri,data=json.dumps(search_json),headers=headers,verify=False)
        if search_result.status_code != 200:
            logging.error("search failed for {0}".format(json.dumps(search_json)))
            logging.error(search_result.text)
            return False
        logging.debug("result messages: timed_out:{} - took:{} - _shards:{}".format(search_result.json()['timed_out'],search_result.json()['took'],search_result.json()['_shards']))
        return search_result

    def print_query(self, search):
        jsonsearch = self.simple_search_json(search,earliest='now-30d')
        print("executing search ...")
        results = self.perform_query(jsonsearch)
        hits = results.json()["hits"]["hits"]
        total = results.json()['hits']['total']
        answer = 'Y' 
        print("{} process segments found.".format(total))
        if total > 100:
            answer = input("Print process segments? (Y/N):")
        if answer.lower() == 'y' and total > 0:
            for event in hits: 
                self.print_critical_process_data(event['_source'])

    def print_critical_process_data(self,event):
        spaces = "     "
        print()
        print("{}-------------------------".format(spaces))
        for conf,val in self.config.items('process_segment'):
            #print("{}:{}".format(conf,val))
            if val in event.keys():
                print("{}{}: {}".format(spaces,val,event[val]))

    def print_config_section(self,event,config_section_name):
        spaces = "     "
        output = ""
        for conf,val in self.config.items(config_section_name):
            if val in event.keys():
                if len(output) == 0:
                    output = "{}{} |".format(spaces,event[val])
                else:
                    output = "{} {} |".format(output,event[val])
        # remove last |
        output = output[0:len(output)-2]
        print(output)
            
    def sanitize_guid(self,guid):
        guid = guid.replace("\\","")
        guid = guid.replace("}","")
        guid = guid.replace("{","")
        if len(guid) != 36:
            logging.error("ERROR: {} is not a guid. GUID format is as follows {}".format(guid,"{1D9C98A5-B153-5C1A-0000-0010E11F850A}"))
            sys.exit(1)
        guid = "\\{"+guid+"\\}"
        return guid
        
    def print_tree(self,guid,yarascan=False):
        # get all related info from elasticsearch for this guid
        smm = self.get_es_data(guid)
        smm.print_guid(guid,alldata=True)
        if yarascan:
            smm.scan_all()

    def walk_entire_tree(self,guid,yarascan=False):
        smm = self.get_es_data(guid)
        guid = self.sanitize_guid(guid)
        guid = guid.replace("\\","")
        smm.print_entire_process_tree(smm.get_host(guid),guid,"details")
        
        print()
        if yarascan:
            smm.scan_all()

  
    def child_crawler(self,smm,guid,depth,host,earliest=None,latest=None):
        if depth > int(self.config['main']['max_level_walk']):
            return
        else:
            depth += 1
        print("searching for child {}".format(guid))
        search = "{}:{}".format(self.config['event_id_1']['ParentProcessGuid'],self.sanitize_guid(guid))
        results = None
        if earliest and latest:
            results = self.perform_query(self.simple_search_json(search,host,earliest=earliest,latest=latest))
        else:
            results = self.perform_query(self.simple_search_json(search,host))
        hits = results.json()["hits"]["hits"]
        total = results.json()['hits']['total']
        logging.debug("{} results.".format(total))
        # add the events to sysmon_more
        for event in hits:
            print("adding child: {}".format(event['_source']))
            smm.add_event(event['_source']) 
        for event in hits:
            self.child_crawler(smm,event['_source'][self.config['event_id_1']['ProcessGuid']],depth,host,earliest=earliest,latest=latest)
        return

    # query elasticsearch, pull ancestry info for all types of events
    def get_es_data(self,guid):
        smm = SysMonMore()
        # find all events for this process guid
        search = self.findAllProcesses(self.sanitize_guid(guid))
        logging.debug("executing search {}".format(search))
        results = self.perform_query(self.simple_search_json(search))
        hits = results.json()["hits"]["hits"]
        total = results.json()['hits']['total']
        logging.debug("{} results.".format(total))
        parent_guid = None
        host = None
        latest = earliest = None
        # add the events to sysmon_more
        print(hits)
        for event in hits:
            data = event['_source']
            if self.config['elk']['event_time_field'] in data.keys():
                # only searching across a specific period of time should help performance for children/parent queries
                event_time = datetime.strptime(data[self.config['elk']['event_time_field']],"%Y-%m-%dT%H:%M:%S.%fZ")
                earliest = str((event_time - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3])
                latest = str((event_time + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3])
            if self.config['event_id_1']['Computer'] in data.keys():
                host = data[self.config['event_id_1']['Computer']]
            if self.config['event_id_1']['ParentProcessGuid'] in data.keys():
                parent_guid = data[self.config['event_id_1']['ParentProcessGuid']]
                print("has parent: {}".format(parent_guid))
            print("adding process data")
            smm.add_event(data)

        # find all children's children's etc processes of the guid
        self.child_crawler(smm,guid,1,host,earliest=earliest,latest=latest)

        # get Parents - we should already have the Parent from the initial query
        while parent_guid is not None:
            #search = "{}:{}".format(self.config['event_id_1']['ProcessGuid'],self.sanitize_guid(parent_guid))
            search = self.findAllProcesses(self.sanitize_guid(parent_guid))
            results = self.perform_query(self.simple_search_json(search,host,earliest,latest))
            hits = results.json()["hits"]["hits"]
            total = results.json()['hits']['total']           
            logging.debug("{} results.".format(total))
            parent_guid = None
            for event in hits:
                print("adding parent data")
                print(event['_source'])
                smm.add_event(event['_source'])

                # a process should have 1 unique parent guid
                if self.config['event_id_1']['ParentProcessGuid'] in event['_source'].keys():
                    parent_guid = event['_source'][self.config['event_id_1']['ParentProcessGuid']]
                    print("parent of parent is {}".format(parent_guid))

        return smm

        
    def findAllProcesses(self, guid):
        # take into account that process id is potentially in a few different fields
        search = "{}:{}".format(self.config['event_id_1']['ProcessGuid'],guid)
        search = "{} OR {}:{}".format(search,self.config['event_id_8']['SourceProcessGuid'],guid)

        return search

    def print_process(self, guid):
        guid = self.sanitize_guid(guid)
        # take into account that process id is potentially in a few different fields
        search = self.findAllProcesses(guid)
        logging.debug("executing search {}".format(search))
        jsonsearch = self.simple_search_json(search)
        results = self.perform_query(jsonsearch)
        hits = results.json()["hits"]["hits"]
        total = results.json()['hits']['total']
        print(total)
        logging.debug("{} results.".format(total))
        process = {}
        for event in hits:
            eventid = event['_source'][self.config['sysmon']['EventID']] 
            if eventid not in process.keys():
                process[eventid] = []
            process[eventid].append(event['_source']) 
        
        for eventid in process.keys():
            print(eventid)
            if eventid == 1:
                print("  ==== PROCESS ====")
                for item in process[eventid]:
                    self.print_critical_process_data(item)
            if eventid == 2:
                print("  ==== FILE CREATION CHANGED ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_2')
            if eventid == 3:
                print("  ==== NETCONNS ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_3')
            if eventid == 6:
                print("  ==== DRIVER LOADED ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_6')
            if eventid == 7:
                print("  ==== IMAGE LOADED ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_7')  
            if eventid == 8:
                print("  ==== CREATEREMOTETHREAD ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_8')
            if eventid == 9:
                print("  ==== RAWACCESSREAD ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_9')
            if eventid == 10:
                print("  ==== PROCESSACCESS ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_10')
            if eventid == 11:
                print("  ==== FILECREATE ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_11')
            if eventid == 12 or eventid == 13 or eventid == 14:
                print("  ==== REGMOD ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_12')
            if eventid == 17 or eventid == 18:
                print("  ==== PIPEMOD ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_17')
            if eventid == 19:
                print("  ==== WMIEVENTFILTER ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_19')
            if eventid == 20:
                print("  ==== WMIEVENTCONSUMER ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_20')
            if eventid == 21:
                print("  ==== WMIEVENTCONSUMERTOFILTER ====")
                for item in process[eventid]:
                    self.print_config_section(item,'event_id_21')
            print()

def main():

    parser = argparse.ArgumentParser(description="An interface to sysmon data in elasticsearch")

    #profiles = auth.CredentialStore("response").get_profiles()
    #parser.add_argument('-e', '--environment', choices=auth.CredentialStore("response").get_profiles(),
    #                    help='specify an environment you want to work with. Default=All \'production\' environments')
    #parser.add_argument('--debug', action='store_true', help='print debugging info')
    #parser.add_argument('--warnings', action='store_true',
    #                         help="Warn before printing large executions")

    subparsers = parser.add_subparsers(dest='command') #title='subcommands', help='additional help')
    cbinterface_commands = [ 'query', 'proc']


    parser_proc = subparsers.add_parser('proc', help="analyze a process GUID. 'proc -h' for more")
    parser_proc.add_argument('process', help="the process GUID to analyze")
    #parser_proc.add_argument('--warnings', action='store_true',
    #                         help="Warn before printing large executions")
    parser_proc.add_argument('-a', '--ancestry', action='store_true',
                             help="show children, process, parent, grandparent, and greatgrandparent full analysis")
    parser_proc.add_argument('-w', '--walk-tree', action='store_true',
                             help="show children, process, parent, grandparent, and greatgrandparent full analysis")
    parser_proc.add_argument('-y', '--yara', action="store_true", dest='yarascan',
        help="scan ancestry with yara (rules directory configuration is required)")
    #parser_proc.add_argument('-wp', '--walk-parents', action='store_true',
    #                         help="print details on the process ancestry")
    #parser_proc.add_argument('-d', '--detection', action='store_true',
    #                         help="show detections that would result in ACE alerts")
    #parser_proc.add_argument('-i', '--proc-info', action='store_true',
    #                         help="show binary and process information")
    #parser_proc.add_argument('-c','--show-children', action='store_true',
    #                         help="only print process children event details")
    #parser_proc.add_argument('-nc', '--netconns', action='store_true',
    #                         help="print network connections")
    #parser_proc.add_argument('-fm', '--filemods', action='store_true',
    #                         help="print file modifications")
    #parser_proc.add_argument('-rm', '--regmods', action='store_true',
    #                         help="print registry modifications")
    #parser_proc.add_argument('-um', '--unsigned-modloads', action='store_true',
    #                         help="print unsigned modloads")
    #parser_proc.add_argument('-ml', '--modloads', action='store_true',
    #                         help="print modloads")
    #parser_proc.add_argument('-cp', '--crossprocs', action='store_true',
    #                         help="print crossprocs")
    #parser_proc.add_argument('-intel', '--intel-hits', action='store_true',
    #                         help="show intel (feed/WL) hits that do not result in ACE alerts")
    #parser_proc.add_argument('--no-analysis', action='store_true',
    #                         help="Don't fetch and print process activity")
    #parser_proc.add_argument('--json', action='store_true', help='output process summary in json')

    facet_args = [
        'process_name', 'childproc_name', 'username', 'parent_name', 'path', 'hostname',
        'parent_pid', 'comms_ip', 'process_md5', 'start', 'group', 'interface_ip',
        'modload_count', 'childproc_count', 'cmdline', 'regmod_count', 'process_pid',
        'parent_id', 'os_type', 'rocessblock_count', 'crossproc_count', 'netconn_count',
        'parent_md5', 'host_type', 'last_update', 'filemod_count'
        ]
 
    parser_query = subparsers.add_parser('query',
                                         help="execute a process search query. 'query -h' for more")
    parser_query.add_argument('query', help="the process search query you'd like to execute")
    parser_query.add_argument('-s', '--start-time', action='store',
                              help="Only return processes with events after given date/time stamp\
 (server’s clock). Format:'Y-m-d H:M:S' eastern time")
    parser_query.add_argument('-e', '--end-time', action='store',
                              help="Set the maximum last update time. Format:'Y-m-d H:M:S' eastern time")
    parser_query.add_argument('--facet', action='store', choices=facet_args,
                              help='stats info on single field accross query results (ex. process_name)')
    parser_query.add_argument('--no-warnings', action='store_true',
                             help="Don't warn before printing large query results")
    parser_query.add_argument('-lh', '--logon-history', action='store_true', help="Display available logon history for given username or hostname")

    args = parser.parse_args()

    if args.command is None:
        print("\n\n*****")
        print("You must specify one of the following commands:\n")
        print(cbinterface_commands)
        print("\n*****\n\n")
        parser.parse_args(['-h'])

    #args.debug = True
    #if args.debug:
    # configure some more logging
    #root = logging.getLogger()
    #root.addHandler(logging.StreamHandler())
    #logging.getLogger("cbapi").setLevel(logging.ERROR)
    #logging.getLogger("lerc_api").setLevel(logging.WARNING)
    logging.getLogger("sme").setLevel(logging.INFO)

    # ignore the proxy
    if 'https_proxy' in os.environ:
        del os.environ['https_proxy']

    # Process Quering #
    if args.command == 'query':
        es = SysMonElasticsearch()
        es.print_query(args.query)
        return 0

    # lerc install arguments can differ by company/environment
    # same lazy hack to define in cb config
    config = {}
    try:
        default_profile = auth.default_profile
        default_profile['lerc_install_cmd'] = None
        config = auth.CredentialStore("response").get_credentials(profile=profile)
    except:
        pass


    # Process Investigation #
    process_tree = None
    if args.command == 'proc':
        # search where proccess_guid = guid
        es = SysMonElasticsearch()
        if args.ancestry:
            if args.yarascan:
                es.print_tree(args.process,yarascan=True)
            else:
                es.print_tree(args.process)
        elif args.walk_tree:
            if args.yarascan:
                es.walk_entire_tree(args.process,yarascan=True) 
            else:
                es.walk_entire_tree(args.process)
        else:
            es.print_process(args.process)
        
    print()
    return True

if __name__ == "__main__":
    print(time.ctime() + "... starting")
    result = main()
    if result:
        print(time.ctime() + "... Done.")
    sys.exit(result)
