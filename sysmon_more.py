#!/usr/bin/env python3

import signal
import json
from datetime import datetime, timedelta
import logging
import logging.config
import os
import os.path
import sys
from configparser import ConfigParser
from pprint import pprint
import time
import argparse
import pickle
import atexit
import yara
import uuid
import YaraLib

# NOTE: https://www.ultimatewindowssecurity.com is a great source for understanding windows event logs, incuding sysmon events!!
# custom ConfigParser to keep case sensitivity
class CaseConfigParser(ConfigParser):
    def optionxform(self, optionstr):
        return optionstr

class SysMonMore():
    def __init__(self,config=None):
        # load configuration
        if not config:
            self.config = CaseConfigParser()
            self.config.read('etc/smm.ini')
            self.output_dir = self.config['smm']['output_dir']
        else:
            self.config = config
        # store process data for each host - key is the host name, value is a dictionary for each process
        # hosts[pcn005005.local][{1D9C98A5-B6E7-5BC8-0000-001074AF7600}]['data'] = {} //dictionary of the important event_data
        # hosts[pcn005005.local][{1D9C98A5-B6E7-5BC8-0000-001074AF7600}]['status']['written'] = True/False //has the process been written out yet
        # hosts[pcn005005.local][{1D9C98A5-B6E7-5BC8-0000-001074AF7600}]['status']['insert_time'] = 1541610286.5432205  //epoch time of when we inserted this item into memory
        # hosts[pcn005005.local][{1D9C98A5-B6E7-5BC8-0000-001074AF7600}]['children'] = []  //list of guids that are children of this process
        # hosts[pcn005005.local][{1D9C98A5-B6E7-5BC8-0000-001074AF7600}]['remotethread'] = [] //list of remotethreads
        self.hosts = {}
        self.event_counts = { '1':0, '2':0, '3':0, '4':0, '5':0, '6':0, '7':0, '8':0, '9':0, '10':0, '11':0, '12':0, '13':0, '14':0 }
        self.enable_yara = self.config['main']['enable_yara']
        if bool(self.enable_yara):
            self.yarascanner = YaraLib.YaraScanner()

    # run yara on the tree
    def run_yara(self,Tree):
        # if repo has changed, re-compile it
        # create a string with the items from each tree to write
        lst = []
        lines = ""
        # the tree should only consist of key/string and key/lists
        for item in Tree.keys():
            if type(Tree[item]) == list:
                for i in Tree[item]:
                    lst.append("{}{}={}".format(lines,item,i))
            if type(Tree[item]) == str:
                lst.append("{}{}={}".format(lines,item,Tree[item]))

        lst = sorted(lst)
        for i in lst:
            lines = "{}{}{}".format(lines,i,'\n')

        # Scan
        matches,rulenames, tags, strings = self.yarascanner.Scan(lines)

        if len(matches) > 0:
            logging.debug("matches #: {}".format(len(matches)))
            Tree['rule_names'] = rulenames
            Tree['rule_tags'] = tags
            Tree['rule_strings'] = strings
            if 'hit_directory' in self.config['yara'].keys():
                output_filename = "{}_{}_{}".format(Tree['computer_name'],int(time.time()),uuid.uuid1())
                output_filepath = os.path.join(self.config['yara']['hit_directory'],output_filename)
                f = open(output_filepath,'w')
                json.dump(Tree,f)
                f.write('\n')
                f.write(lines)
                f.close()
                logging.info("Rules: {} Matched Contents {}".format(rulenames,output_filepath))
            else:
                print(rulenames)
                print(strings)

        if 'output_text_file_directory' in self.config['main']:
            if self.config['main']['output_text_file_directory']:
                procguid = Tree['proc_guid'].replace("}","")
                procguid = procguid.replace("{","")
                filename = "{}_{}_{}".format(Tree['computer_name'],procguid,time.time())
                basepath = os.path.join(self.config['main']['output_text_file_directory'],Tree['computer_name'])
                filepath = os.path.join(basepath,filename)
                if not os.path.exists(basepath):
                    os.mkdir(basepath)

                with open(filepath,'w') as f:
                    f.write(lines)

    # this function assumes that all processes are in memory that you want to run yara on
    # get all the trees and run yara on them
    def scan_all(self):
        for host in self.hosts.keys():
            for guid in self.hosts[host].keys():
                self.run_yara(self.getTree(host,guid,alldata=True))


    # write parent/children for items that haven't been written since the last interval
    def write_all(self,out_file,write_interval):
        items_written = 0
        for host in self.hosts.keys():
            for proc in self.hosts[host].keys():
                data = self.hosts[host][proc]['data']
                status = self.hosts[host][proc]['status']
                if not status['written']:
                    seconds = time.time() - status['insert_time']
                    #print("proc to write: {} - {} - {} - {} > {}".format(proc,seconds,time.time(),status['insert_time'],int(write_interval)))
                    # if proc store time vs now is greater than the interval
                    if (time.time() - status['insert_time'])  > int(write_interval):
                        seconds = time.time() - status['insert_time']
                        #print("proc to write: {} - {} - {} - {} > {}".format(proc,seconds,time.time(),status['insert_time'],int(write_interval)))
                        # write it and its grand/parent/children
                        #print("writing proc levels for: {}".format(self.hosts[host][proc]))
                        self.write_levels(host,proc,out_file)
                        # mark it as written
                        self.hosts[host][proc]['status']['written'] = True
                        items_written += 1
        if items_written != 0:
            logging.info("Wrote {} trees".format(items_written))

    def getHashes(self,hashes):
        #Windows event has hashes in the following format
        #MD5=A583A436699DC37EF6A70A9F2C7D33E3,SHA256=11D67D7BF824D250783566ECC100736A5FEE97D3405C4D250ABCA905ECE50E12"
        md5 = None
        sha256 = None
        if not hashes:
            return None, None
        if "," not in hashes:
            # this field must not have multiple hashes in the hash field, use the config 
            if len(hashes) == 65:
                sha256 = hashes
            if len(hashes) == 33:
                md5 = hashes
        else: 
            for hash in hashes.split(","):
                key,value = hash.split("=")
                if 'md5' == key.lower():
                    md5 = value.lower()
                if 'sha256' == key.lower():
                    sha256 = value.lower()
        return md5,sha256


    def add_parent_child_data(self,host,ed):
        child = None
        parent = None
        if self.config['smm']['ProcessGuid'] in ed.keys():
            child = ed[self.config['smm']['ProcessGuid']]

        if self.config['smm']['ParentProcessGuid'] in ed.keys():
            parent = ed[self.config['smm']['ParentProcessGuid']]

        # if parent proc info exists in the event data for this event, add the process with child info
        if parent:
            # if parent does not exist in our process dictionary  yet, create it from the data we have, add the process info as its child
            if parent not in self.hosts[host].keys():
                self.hosts[host][parent] = {}
                self.hosts[host][parent]['data'] = {}
                L = {}
                L['proc_id'] = ed[self.config['smm']['ParentProcessId']]
                L['proc_path'] = ed[self.config['smm']['ParentImage']]
                L['proc_cmdline'] = ed[self.config['smm']['ParentCommandLine']]
                L['proc_guid'] = parent
                self.hosts[host][parent]['data'] = L
                self.hosts[host][parent]['children'] = []
                self.hosts[host][parent]['children'].append(child)
                self.add_status(host,parent)
            # parent exists already, update children
            else:
                if 'children' in self.hosts[host][parent].keys():
                    if child not in self.hosts[host][parent]['children']:
                        self.hosts[host][parent]['children'].append(child)
                else:
                     self.hosts[host][parent]['children'] = []
                     self.hosts[host][parent]['children'].append(child)
        # event type that only has process information, it only has a subset of info and does not have a parent
        elif child:
            if child not in self.hosts[host].keys():
                self.hosts[host][child] = {}
                self.hosts[host][child]['data'] = {}
                L = {}
                L['proc_id'] = ed[self.config['smm']['ProcessId']]
                L['proc_path'] = ed[self.config['smm']['Image']]
                L['proc_guid'] = child
                self.hosts[host][child]['data'] = L
                self.add_status(host,child)

    def add_process_data(self,host,process,ed):
        # store the details for each process
        L = {}
        #L1 is the "Parent" level, we only have path, cmd, guid from the proc event for parent in a create process event
        L['parent_id'] = ed[self.config['smm']['ParentProcessId']]
        L['parent_path'] = ed[self.config['smm']['ParentImage']]
        L['parent_guid'] = ed[self.config['smm']['ParentProcessGuid']]
        L['parent_cmdline'] = ed[self.config['smm']['ParentCommandLine']]
        L['proc_id'] = ed[self.config['smm']['ProcessId']]
        #MD5=A583A436699DC37EF6A70A9F2C7D33E3,SHA256=11D67D7BF824D250783566ECC100736A5FEE97D3405C4D250ABCA905ECE50E12"
        md5,sha256 = self.getHashes(ed[self.config['smm']['Hashes']])
        if md5:
           L['proc_md5'] = md5
        if sha256:
           L['proc_sha265'] = sha256
        L['proc_path'] = ed[self.config['smm']['Image']]
        L['proc_guid'] = ed[self.config['smm']['ProcessGuid']]
        L['proc_cd'] = ed[self.config['smm']['CurrentDirectory']]
        L['proc_cmdline'] = ed[self.config['smm']['CommandLine']]
        L['proc_user'] = ed[self.config['smm']['User']]
        L['proc_time'] = ed[self.config['smm']['UtcTime']]
        L['computer_name'] = host

        if process not in self.hosts[host].keys():
            self.hosts[host][process] = {}
            self.hosts[host][process]['data'] = L
            self.add_status(host,process)
        else:
            if 'data' not in self.hosts[host][process].keys():
                self.hosts[host][process]['data'] = L
            else:
                self.hosts[host][process]['data'].update(L)
        return

    def add_status(self,host,guid):
        status = {}
        status['written'] = False
        status['insert_time'] = time.time()
        self.hosts[host][guid]['status'] = status

    def event1_store(self,host,ed):
        if host not in self.hosts.keys():
            self.hosts[host] = {}

        process_guid = ed[self.config['smm']['ProcessGuid']]
        parent_guid = ed[self.config['smm']['ParentProcessGuid']]
        self.add_parent_child_data(host,ed)
        self.add_process_data(host,process_guid,ed)
        self.add_status(host,process_guid)

        return

    # write all the levels of the ancestry (tree)
    def write_levels(self,host,guid,output_file):
        Tree = self.getTree(host,guid)

        if self.enable_yara:
            # run yara on everything we are writing (pass alldata to use all the data we have available)
            self.run_yara(self.getTree(host,guid,alldata=True))

        f = open(output_file,'a')
        json.dump(Tree,f)
        f.write('\n')
        f.close()

    def get_host(self,guid):
        for host in self.hosts.keys():
            if guid in self.hosts[host].keys():
                return host

    def print_guid(self,guid,alldata=False):
        for host in self.hosts.keys():
            if guid in self.hosts[host].keys():
                self.print_tree(host,guid,alldata)
                return
        print("guid: {} - Not Found".format(guid))

    def print_trees(self):
        for host in self.hosts.keys():
            print("########## {} ##########".format(host))
            for proc in self.hosts[host].keys():
                print("########## {}".format(proc))
                self.print_tree(host,proc)

    # print ancestry for every process in memory to stdout, in a pretty way
    def print_tree(self,host,proc,alldata=False):
        Tree = self.getTree(host,proc,alldata)
        # This could be more efficient for sure
        # using items so the keys will be sorted the same way for each print
        hasGGrand = False
        for k, v in Tree.items():
            if k.startswith("ggrand_"):
                print("- {}: {}".format(k,v))
                hasGGrand = True
        hasGrand = False
        for k, v in Tree.items():
            if k.startswith("grand_"):
                if hasGGrand:
                    print("  - {}: {}".format(k,v))
                else:
                    print("- {}: {}".format(k,v))
                hasGrand = True
        hasParent = False
        for k, v in Tree.items():
            if k.startswith("parent_"):
                if hasGGrand:
                    print("    - {}: {}".format(k,v))
                    hasGrand = True
                elif hasGrand:
                    print("  - {}: {}".format(k,v))
                else:
                    print("- {}: {}".format(k,v))
                hasParent = True
        for k, v in Tree.items():
            if k.startswith("proc_"):
                if hasGGrand:
                    print("      - {}: {}".format(k,v))
                    hasGrand = True
                elif hasGrand:
                    print("    - {}: {}".format(k,v))
                elif hasParent:
                    print("  - {}: {}".format(k,v))
                else:
                    print("- {}: {}".format(k,v))
        for k, v in Tree.items():
            if k.startswith("child_"):
                if hasGGrand:
                    print("        - {}: {}".format(k,v))
                    hasGrand = True
                elif hasGrand:
                    print("      - {}: {}".format(k,v))
                elif hasParent:
                    print("    - {}: {}".format(k,v))
                else:
                    print("  -{}: {}".format(k,v))

    def print_entire_process_tree(self,host,guid,mode="summary"):
        modes = []
        modes.append(mode)
        if mode is not "summary":
            modes = ['summary','details']
        for mode in modes:
            tree = []
            tree.append(self.hosts[host][guid]['data'])
            hasParent = False
            if 'parent_guid' in self.hosts[host][guid]['data'].keys():
                parent_guid = self.hosts[host][guid]['data']['parent_guid']
                hasParent = True
            while hasParent:
                tree.insert(0, self.hosts[host][parent_guid]['data'])
                hasParent = False
                if 'parent_guid' in self.hosts[host][parent_guid]['data'].keys():
                    parent_guid = self.hosts[host][parent_guid]['data']['parent_guid']
                    hasParent = True
            indent = ""
            for item in tree:
                self.print_process_item(item,indent,mode)
                indent = "{}{}".format(indent,"    ")
            self.crawl_child(guid,host,indent,mode)         
            print()
            

    def crawl_child(self,guid,host,indent,mode):
        if 'children' in self.hosts[host][guid].keys():
            children_guids = self.hosts[host][guid]['children']
            for child in children_guids:
                if child in self.hosts[host].keys():
                    item = self.hosts[host][child]['data']
                    self.print_process_item(item,indent,mode)
                    self.crawl_child(child,host,indent,mode)
            indent = "{}{}".format(indent,"    ")
        
    def print_process_item(self,item,indent,mode="summary"):
        if mode is "summary":
            '''
            if 'parent_guid' in item.keys():
                if 'proc_cmdline' in item.keys():
                    print("{}---> {} - {} - {}/{}".format(indent,item['proc_path'],item['proc_cmdline'],item['parent_guid'],item['proc_guid']))
                else:
                    print("{}---> {} - {} - {}/{}".format(indent,item['proc_path'],item['parent_guid'],item['proc_guid']))
            elif 'proc_cmdline' in item.keys():
                print("{}---> {} - {} - {}".format(indent,item['proc_path'],item['proc_cmdline'],item['proc_guid']))
            else:
                print("{}---> {} - {}".format(indent,item['proc_path'],item['proc_guid']))
            '''
            print("{}---> {} - {}".format(indent,item['proc_path'],item['proc_guid']))
        else:
            print("{}#### {} ####".format(indent,item['proc_guid']))
            for k in item.keys():
                if 'parent_' not in k and 'child_' not in k and '_count' not in k:
                    print("{} - {}: {}".format(indent,k,item[k]))
            
    def print_child_tree_object(self,tree,indent):
        for item in tree:
            if type(item) == dict:
                print("{}{} - {}".format(indent,item['proc_path'],item['proc_guid']))
            if type(item) == list:
                self.print_child_tree_object(item,indent)
        
    def crawler(self,guid_list, host, depth):
        if depth > int(self.config['main']['max_level_walk']):
            return
        else:
            depth += 1
        children = []
        for guid in guid_list:
            # if we have the child data add it to the list 
            if guid in self.hosts[host].keys():
                print(self.hosts[host][guid]['data'])
                children.append(self.hosts[host][guid]['data'])
        if len(children) > 0:
            new_guid_list = []
            new_level = []
            for item in children:
                if 'children' in item.keys():
                    new_guid_list.append(item['children'])
            tmpchildren = self.crawler(new_guid_list,host,depth)
            if tmpchildren:
                children.append(tmpchildren)
        if children:
            return children

    # get the ancestry for this process
    def getTree(self,host,guid,alldata=False):
        # selectively add items to the tree to return (writing everything for each process started to get large and redundant)
        include_field_list = [ 'filemod_count','netconn_count','modload_count','remotethread_count','rawaccess_count','procaccess_count','regmod_count','regmod_rename_count' ]
        Child = {}
        Process = self.hosts[host][guid]['data']
        Parent = {}
        GrandParent = {}
        Tree = {}
        Tree['computer_name'] = host

        for key in Process.keys():
            if not key.startswith('parent_') and not key.startswith('proc_') and not key.startswith('computer_name'):
                Tree["{}{}".format('proc_',key)] = Process[key]
            else:
                Tree[key] = Process[key]
        # add Child level if we have it, this will allow easy traversal to children at least, along with some context of what the children are
        if 'children' in self.hosts[host][guid].keys():
            Tree['child_path'] = []
            Tree['child_guid'] = self.hosts[host][guid]['children']
            Tree['child_count'] = len(self.hosts[host][guid]['children'])
            for guid in self.hosts[host][guid]['children']:
                path = self.hosts[host][guid]['data']['proc_path']
                if path not in Tree['child_path']:
                    Tree['child_path'].append(self.hosts[host][guid]['data']['proc_path'])
        # if this process has a parent and we have its data, add it to the tree to print
        if 'parent_guid' in Process.keys():
            if Process['parent_guid'] in self.hosts[host].keys():
                parent_guid = Process['parent_guid']
                Parent = self.hosts[host][parent_guid]['data']
                # copy items to tree, update the key name with parent_
                for key in Parent.keys():
                    if not key.startswith('parent_') and not key.startswith('proc_') and not key.startswith('computer_name'):
                        # only write the items we specify for non-process level items
                        if alldata:
                            Tree["{}{}".format('parent_',key)] = Parent[key]
                        else:
                            for field in include_field_list:
                                if field in Parent.keys():
                                    Tree["{}{}".format('parent_',field)] = Parent[field]

                    elif key.startswith('parent_'):
                        Tree["{}".format(key.replace('parent_','grand_'))] = Parent[key]
                    elif key.startswith('proc_'):
                        Tree["{}".format(key.replace('proc_','parent_'))] = Parent[key]
                # if this process has a grandparent
                if 'parent_guid' in Parent.keys():
                    if Parent['parent_guid'] in self.hosts[host].keys():
                        grandparent_guid = Parent['parent_guid']
                        GrandParent = self.hosts[host][grandparent_guid]['data']
                        # make sure we have info on the parent of this process
                        for key in GrandParent.keys():
                            if not key.startswith('parent_') and not key.startswith('proc_') and not key.startswith('computer_name'):
                                # only write the items we specify for non-process level items
                                if alldata:
                                    Tree["{}{}".format('grand_',key)] = GrandParent[key]
                                else:
                                    for field in include_field_list:
                                        if field in GrandParent.keys():
                                            Tree["{}{}".format('grand_',field)] = GrandParent[field]
                            elif key.startswith('parent_'):
                                Tree["{}".format(key.replace('parent_','ggrand_'))] = GrandParent[key]
                            elif key.startswith('proc_'):
                                Tree["{}".format(key.replace('proc_','grand_'))] = GrandParent[key]

        return Tree

    def event3_netconn(self,host,ed):
        guid = ed[self.config['smm']['ProcessGuid']]
        if guid not in self.hosts[host].keys():
            self.add_parent_child_data(host,ed)
        if 'netconn_count' not in self.hosts[host][guid]['data'].keys():
            self.hosts[host][guid]['data']['netconn_count'] = 0
            self.hosts[host][guid]['data']['netconn'] = []

        # add netcon dst (dst_ip/DestinationIP) to netconn key for process
        # limit to max_netconns from config
        if int(self.config['smm']['max_netconn']) > self.hosts[host][guid]['data']['netconn_count']:
            # only add unique netconn values
            if ed[self.config['smm']['DestinationIp']] not in self.hosts[host][guid]['data']['netconn']:
                self.hosts[host][guid]['data']['netconn_count'] += 1
                self.hosts[host][guid]['data']['netconn'].append(ed[self.config['smm']['DestinationIp']])
                # pprint(self.hosts[host][guid])
            # add destination hostname if available, and only unique hostnames
            if self.config['smm']['DestinationHostname'] in ed.keys():
                if ed[self.config['smm']['DestinationHostname']] not in self.hosts[host][guid]['data']['netconn']:
                    self.hosts[host][guid]['data']['netconn'].append(ed[self.config['smm']['DestinationHostname']])
            if self.config['smm']['SourceIp'] in ed.keys():
                self.hosts[host][guid]['data']['proc_src_ip'] = ed[self.config['smm']['SourceIp']]

    def event2_filemod(self,host,ed):
        guid = ed[self.config['smm']['ProcessGuid']]
        # if we do not have info on the process prior to this event, add the process info we can get
        if  guid not in self.hosts[host].keys():
            self.add_parent_child_data(host,ed)
        if 'filemod_count' not in self.hosts[host][guid]['data'].keys():
            self.hosts[host][guid]['data']['filemod_count'] = 0
            self.hosts[host][guid]['data']['filemod'] = []

        # limit to max_filemod from config
        if int(self.config['smm']['max_filemod']) > self.hosts[host][guid]['data']['filemod_count']:
            # only add unique values
            if ed[self.config['smm']['TargetFilename']] not in self.hosts[host][guid]['data']['filemod']:
                self.hosts[host][guid]['data']['filemod_count'] += 1
                self.hosts[host][guid]['data']['filemod'].append(ed[self.config['smm']['TargetFilename']])
                #pprint(self.hosts[host][guid])

    def event7_modload(self,host,ed):
        guid = ed[self.config['smm']['ProcessGuid']]
        if  guid not in self.hosts[host].keys():
            self.add_parent_child_data(host,ed)
        if 'modload_count' not in self.hosts[host][guid]['data'].keys():
            self.hosts[host][guid]['data']['modload_count'] = 0
            self.hosts[host][guid]['data']['modload'] = []

        # limit to max_modloads from config
        if int(self.config['smm']['max_modload']) > self.hosts[host][guid]['data']['modload_count']:
            # only add unique values
            if ed[self.config['smm']['ImageLoaded']] not in self.hosts[host][guid]['data']['modload']:
                self.hosts[host][guid]['data']['modload_count'] += 1
                self.hosts[host][guid]['data']['modload'].append(ed[self.config['smm']['ImageLoaded']])
                #pprint(self.hosts[host][guid])

    def event8_remotethread(self,host,ed):
        guid = ed[self.config['smm']['SourceProcessGuid']]
        dst_guid = ed[self.config['smm']['TargetProcessGuid']]
        if  guid not in self.hosts[host].keys():
            self.hosts[host][guid] = {}
            self.hosts[host][guid]['data'] = {}
            L = {}
            L['proc_id'] = ed[self.config['smm']['SourceProcessId']]
            L['proc_path'] = ed[self.config['smm']['SourceImage']]
            L['proc_guid'] = guid
            self.hosts[host][guid]['data'] = L
            self.add_status(host,guid)
        if dst_guid not in self.hosts[host].keys():
            self.hosts[host][dst_guid] = {}
            self.hosts[host][dst_guid]['data'] = {}
            L = {}
            L['proc_id'] = ed[self.config['smm']['TargetProcessId']]
            L['proc_path'] = ed[self.config['smm']['TargetImage']]
            L['proc_guid'] = dst_guid
            self.hosts[host][dst_guid]['data'] = L
            self.add_status(host,dst_guid)

        if 'remotethread_count' not in self.hosts[host][guid]['data'].keys():
            self.hosts[host][guid]['data']['remotethread_count'] = 0
            self.hosts[host][guid]['data']['remotethread'] = []
            self.hosts[host][guid]['data']['remotethread_guid'] = []

        # limit to max_remotethreads from config
        if int(self.config['smm']['max_remotethread']) > self.hosts[host][guid]['data']['remotethread_count']:
            # only add unique values
            if ed[self.config['smm']['TargetImage']] not in self.hosts[host][guid]['data']['remotethread']:
                self.hosts[host][guid]['data']['remotethread_count'] += 1
                self.hosts[host][guid]['data']['remotethread'].append(ed[self.config['smm']['TargetImage']])
                self.hosts[host][guid]['data']['remotethread_guid'].append(ed[self.config['smm']['TargetProcessGuid']])
                #pprint(self.hosts[host][guid])

    def event9_rawaccess(self,host,ed):
        #this event contains a device where the raw access event is triggered
        guid = ed[self.config['smm']['ProcessGuid']]
        if  guid not in self.hosts[host].keys():
            self.add_parent_child_data(host,ed)
        if 'rawaccess_count' not in self.hosts[host][guid]['data'].keys():
            self.hosts[host][guid]['data']['rawaccess_count'] = 0
            self.hosts[host][guid]['data']['rawaccess'] = []

        if int(self.config['smm']['max_rawaccess']) > self.hosts[host][guid]['data']['rawaccess_count']:
            # only add unique values
            if ed[self.config['smm']['Device']] not in self.hosts[host][guid]['data']['rawaccess']:
                self.hosts[host][guid]['data']['rawaccess_count'] += 1
                self.hosts[host][guid]['data']['rawaccess'].append(ed[self.config['smm']['Device']])
                #pprint(self.hosts[host][guid])

    def event10_procaccess(self,host,ed):
        guid = ed[self.config['smm']['SourceProcessGUID']]
        dst_guid = ed[self.config['smm']['TargetProcessGUID']]
        if  guid not in self.hosts[host].keys():
            self.hosts[host][guid] = {}
            self.hosts[host][guid]['data'] = {}
            L = {}
            L['proc_id'] = ed[self.config['smm']['SourceProcessId']]
            L['proc_path'] = ed[self.config['smm']['SourceImage']]
            L['proc_guid'] = guid
            self.hosts[host][guid]['data'] = L
            self.add_status(host,guid)
        if dst_guid not in self.hosts[host].keys():
            self.hosts[host][dst_guid] = {}
            self.hosts[host][dst_guid]['data'] = {}
            L = {}
            L['proc_id'] = ed[self.config['smm']['TargetProcessId']]
            L['proc_path'] = ed[self.config['smm']['TargetImage']]
            L['proc_guid'] = dst_guid
            self.hosts[host][dst_guid]['data'] = L
            self.add_status(host,dst_guid)

        if 'procaccess_count' not in self.hosts[host][guid]['data'].keys():
            self.hosts[host][guid]['data']['procaccess_count'] = 0
            self.hosts[host][guid]['data']['procaccess'] = []
            self.hosts[host][guid]['data']['procaccess_guid'] = []

        # limit to max from config
        if int(self.config['smm']['max_procaccess']) > self.hosts[host][guid]['data']['procaccess_count']:
            # only add unique values
            if ed[self.config['smm']['SourceImage']] not in self.hosts[host][guid]['data']['procaccess']:
                self.hosts[host][guid]['data']['procaccess_count'] += 1
                self.hosts[host][guid]['data']['procaccess'].append(ed[self.config['smm']['SourceImage']])
                #pprint(self.hosts[host][guid])

    # handles both eventid 12 & 13 & 14 currently
    def regmod(self,host,ed):
        guid = ed[self.config['smm']['ProcessGuid']]
        if  guid not in self.hosts[host].keys():
            self.add_parent_child_data(host,ed)
        if 'regmod_count' not in self.hosts[host][guid]['data'].keys():
            self.hosts[host][guid]['data']['regmod_count'] = 0
            self.hosts[host][guid]['data']['regmod'] = []

        if int(self.config['smm']['max_regmod']) > self.hosts[host][guid]['data']['regmod_count']:
            # only add unique remote thread values
            #print(ed)
            if ed[self.config['smm']['TargetObject']] not in self.hosts[host][guid]['data']['regmod']:
                self.hosts[host][guid]['data']['regmod_count'] += 1
                self.hosts[host][guid]['data']['regmod'].append(ed[self.config['smm']['TargetObject']])
                #pprint(self.hosts[host][guid])

    def regmod_rename(self,host,ed):
        guid = ed[self.config['smm']['ProcessGuid']]
        if  guid not in self.hosts[host].keys():
            self.add_parent_child_data(host,ed)
        if 'regmod_rename_count' not in self.hosts[host][guid]['data'].keys():
            self.hosts[host][guid]['data']['regmod_rename_count'] = 0
            self.hosts[host][guid]['data']['regmod_rename'] = []

        if int(self.config['smm']['max_regmod']) > self.hosts[host][guid]['data']['regmod_rename_count']:
            # only add unique remote thread values
            #print(ed)
            if ed[self.config['smm']['NewName']] not in self.hosts[host][guid]['data']['regmod_renamge']:
                self.hosts[host][guid]['data']['regmod_rename_count'] += 1
                self.hosts[host][guid]['data']['regmod_rename'].append(ed[self.config['smm']['NewName']])
                #pprint(self.hosts[host][guid])

    def add_event(self,event):
        eventid = host = ed = None
        if self.config['smm']['event_data'] in event.keys():
            # expecting a beats syslog format
            eventid = event[self.config['smm']['id']]
            host = event[self.config['smm']['host']].lower()
            ed = event[self.config['smm']['event_data']] #event_data (sysmon has a nested structure where process data exists)
        elif self.config['smm']['EventID'] in event.keys():
            # expecting sysmon event data only
            eventid = event[self.config['smm']['EventID']]
            host = event[self.config['smm']['Computer']].lower()
            ed = event
        else:
            logging.error("Unknown Event Format. JSON does not seem to be beats format or sysmon format: {}".format(event))
            return
        try:

            #1: Process Create
            if eventid == 1:
                self.event1_store(host,ed)
                self.event_counts['1'] += 1
            elif host not in self.hosts.keys():
                # we have a new host to track
                self.hosts[host] = {}

            #2: Process Changed File Creation Time
            if eventid == 2:
                self.event2_filemod(host,ed)
                self.event_counts['2'] += 1

            #3: Network Connection
            if eventid == 3:
                self.event3_netconn(host,ed)
                self.event_counts['3'] += 1

            #4: Sysmon Service State Changed
            if eventid == 4:
                self.event_counts['4'] += 1
            #5: Process Terminated
            if eventid == 5:
                # just keep track of the processes that have been terminated
                # it is possible we see the termination and did not see the creation
                if ed[self.config['smm']['ProcessGuid']] in self.hosts[host].keys():
                    #self.write_levels(host,ed[self.config['smm']['ProcessGuid']])
                    self.hosts[host][ed[self.config['smm']['ProcessGuid']]]['status']['terminated_time'] = time.time()
                    #del self.hosts[host][ed[self.config['smm']['ProcessGuid']]]
                self.event_counts['5'] += 1

            #6: Driver Loaded
            if eventid == 6:
                # driver loaded event is not tied to a process, not sure what to enrich with this right now
                self.event_counts['6'] += 1

            #7: Image Loaded (module loaded)
            if eventid == 7:
                self.event7_modload(host,ed)
                self.event_counts['7'] += 1

            #8: CreateRemoteThread
            if eventid == 8:
                self.event8_remotethread(host,ed)
                self.event_counts['8'] += 1

            #9: RawAccessRead
            if eventid == 9:
                self.event9_rawaccess(host,ed)
                self.event_counts['9'] += 1

            #10: ProcessAccess
            if eventid == 10:
                self.event10_procaccess(host,ed)
                self.event_counts['10'] += 1

            #11: File Create
            if eventid == 11:
                #combining file create and file modify into one thing (same as event 2)
                self.event2_filemod(host,ed)
                self.event_counts['11'] += 1

            #12: RegistryEvent (Object create and delete)
            if eventid == 12:
                self.regmod(host,ed)
                self.event_counts['12'] += 1

            #13: RegistryEvent (Value Set)
            if eventid == 13:
                # similar enough to event12, reuse "regmod" to capture this event
                self.regmod(host,ed)
                self.event_counts['13'] += 1

            #14: RegistryEvent (Key and Value Rename)
            if eventid == 14:
                # capture both new key and value in regmod, re-using event12_regmod function again
                self.regmod_rename(host,ed)
                self.event_counts['14'] += 1
        except Exception as err:
            logging.error("Exception in add_event, data: {}, error: {}".format(ed,err))

    def cleanup(self,max_items_per_host):
        max_items_per_host = int(max_items_per_host)
        # remove terminated items first (process stop items)
        for host in self.hosts.keys():
            if len(self.hosts[host]) > max_items_per_host:
                remove_quantity = len(self.hosts[host]) - max_items_per_host
                term_time_list = []
                insert_time_list = []
                for proc in self.hosts[host].keys():
                    if 'terminated_time' in self.hosts[host][proc]['status'].keys():
                        term_time_list.append("{}_{}".format(int(self.hosts[host][proc]['status']['terminated_time']),proc))
                    else:
                        insert_time_list.append("{}_{}".format(int(self.hosts[host][proc]['status']['insert_time']),proc))
                term_time_list.sort()
                insert_time_list.sort()

                logging.info("Total items for {}: {}. Max Setting {}. Number of Terminated Processes {}. Number of all other processes {}.".format(host,len(self.hosts[host]),max_items_per_host,len(term_time_list),len(insert_time_list)))
                term_remove_quantity = 0
                if len(term_time_list) < remove_quantity:
                    # 3 = 10 -7
                    # remove as many terminated items that we have
                    for x in range(0,len(term_time_list)-1):
                        proc_to_del = term_time_list[x].split("_")[1]
                        del self.hosts[host][proc_to_del]
                    remaining_remove_quantity = remove_quantity - len(term_time_list)
                    # depending on what config items are provided, this could be an unexpected number
                    if len(insert_time_list) > remaining_remove_quantity:
                        for x in range(0,remaining_remove_quantity-1):
                            proc_to_del = insert_time_list[x].split("_")[1]
                            del self.hosts[host][proc_to_del]
                    # somehow we don't have enough items remaining to remove to the max_items_per_host (not expected, but handling)
                    # remove what we can
                    else:
                        logging.warning("In Cleanup, somehow we do not have enough processes to cleanup. Processes {}, Max Items Per Host: {}".format(len(self.hosts[host]),max_items_per_host))
                        for x in range(0,len(insert_time_list)-1):
                            proc_to_del = insert_time_list[x].split("_")[1]
                            del self.hosts[host][proc_to_del]
                    logging.info("Removed {} items from memory for {}. Max Items Setting: {}. New Number of total items {}".format(remove_quantity,host,max_items_per_host,len(self.hosts[host])))


                # Remove items from terminated processes only (this will get us back to under the max items per host)
                else:
                    for x in range(0,remove_quantity):
                        proc_to_del = term_time_list[x].split("_")[1]
                    del self.hosts[host][proc_to_del]
                    logging.info("Removed {} terminated items from memory for {}".format(remove_quantity,host))

    def stats(self):
        if len(self.hosts.keys()) == 0:
            return
        logging.info("process:{}".format(len(self.hosts.keys())))
        #for host in self.hosts:
        #    print("host:{} - processes:{}".format(host,len(self.hosts[host].keys())))
        logging.info("################### Stats ######################")
        logging.info("Host Count: {}".format(len(self.hosts.keys())))
        logging.info("1.                       Process Create: {}".format(self.event_counts[str('1')]))
        logging.info("2. filemod    Change File Creation Time: {}".format(self.event_counts[str('2')]))
        logging.info("3. netconn           Network Connection: {}".format(self.event_counts[str('3')]))
        logging.info("4.         Sysmon Service State Changed: {}".format(self.event_counts[str('4')]))
        logging.info("5.                   Process Terminated: {}".format(self.event_counts[str('5')]))
        logging.info("6.                        Driver Loaded: {}".format(self.event_counts[str('6')]))
        logging.info("7. modload          Image/Module Loaded: {}".format(self.event_counts[str('7')]))
        logging.info("8. remotethread    Create Remote Thread: {}".format(self.event_counts[str('8')]))
        logging.info("9. rawaccess            Raw Access Read: {}".format(self.event_counts[str('9')]))
        logging.info("10.procaccess            Process Access: {}".format(self.event_counts[str('10')]))
        logging.info("11.filemod                  File Create: {}".format(self.event_counts[str('11')]))
        logging.info("12.regmod     Reg Event (Create/Delete): {}".format(self.event_counts[str('12')]))
        logging.info("13.regmod                 Reg Set Value: {}".format(self.event_counts[str('13')]))
        logging.info("14.regmod      Reg Key and Value Rename: {}".format(self.event_counts[str('14')]))
        self.last_stats_time = time.time()

    def save(self,output_dir,fformat):
        if os.path.exists(output_dir):
            for host in self.hosts:
                if os.path.exists(output_dir):
                    # remove the old file if it exists
                    logging.info("replacing previous persistence files")
                    if os.path.exists("{}/{}".format(output_dir,host)):
                        os.remove("{}/{}".format(output_dir,host))
                else:
                    os.mkdir(output_dir)

                if len(self.hosts[host]) > 0:
                    logging.info("saving memory for: {}, {} items".format(host,len(self.hosts[host])))
                    f = open("{}/{}".format(output_dir,host),'w')
                    if fformat is 'json':
                        json.dump(self.hosts[host],f)
                    if fformat is 'pickle':
                        pickle.dump(self.host[host],f)
                    f.close()
                else:
                    logging.info("no memory to save for: {}".format(host))
        else:
            logging.info("path for persistence does not exist".format(output_dir))

    def resume(self,output_dir,fformat):
        if os.path.exists(output_dir):
            for host in os.listdir(output_dir):
                if os.path.exists("{}/{}".format(output_dir,host)):
                    # remove the old file if it exists
                    logging.info("replacing previous persistence files")
                    if os.path.exists("{}/{}".format(output_dir,host)):
                        start = time.time()
                        with open("{}/{}".format(output_dir,host),'r') as data:
                            logging.info("loading memory for: {}".format(host))
                            if fformat is 'json':
                                self.hosts[host] = json.load(data)
                            if fformat is 'pickle':
                                self.hosts[host] = pickle.load(data)
                        os.remove("{}/{}".format(output_dir,host))
                        end = time.time()
                        logging.info("loading memory for: {} - {} seconds".format(host,end - start))
        else:
            logging.info("path for persistence does not exist: {}".format(output_dir))

    def print_samples(self,num_samples):
        x = 0
        for host in self.hosts:
            for proc in self.hosts[host].keys():
                print("################### {} ##################".format(host))
                pprint(self.hosts[host][proc])
                x += 1
                if x == num_samples:
                    break;
            break;

    def dump_to_file(self,path):
        f = open(path,"a")
        #json.dump(self.hosts,f)
        for host in self.hosts:
            print("host:{}".format(host))
            for proc in self.hosts[host].keys():
                print("proc:{}".format(proc))
                json.dump(self.hosts[host][proc],f)
                f.write('\n')

    # read new files to consume from stdin, keep going until stopped
    def daemon(self,name):

        output_dir = os.path.join(self.config['smm']['output_dir'],name)
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)

        # have a specific output file for each process
        output_file = "{}/{}.log".format(self.output_dir,name)
        self.resume(self.config["smm"]["save_state_location"],self.config['smm']['persist_format'])

        write_interval = self.config['main']['write_interval']
        last_write_time = time.time()
        stats_interval = self.config['main']['stats_interval']
        last_stats_time = time.time()
        cleanup_interval = self.config['main']['cleanup_interval']
        last_cleanup_time = time.time()
        max_event_mem_storage_per_host = self.config['main']['max_event_mem_storage_per_host']
        last_persist_time = time.time()
        persist_interval = self.config['main']['persist_interval']

        try:
            for infile in sys.stdin:
                infile = infile.rstrip()
                if 'heartbeat_check' not in infile:
                    infile_name = os.path.basename(infile)
                    os.rename(infile,"{}/{}".format(output_dir,infile_name))
                    infile = os.path.join(output_dir,infile_name)
                    with open(infile,'r') as fp:
                        logging.info("{} - processing {}".format(name,infile))
                        for line in fp:
                            o = json.loads(line)
                            self.add_event(o)
                    logging.info("{} - removing processed file {}".format(name,infile))
                    os.remove(infile)

                if (time.time() - last_stats_time) > int(stats_interval):
                    self.stats()
                    last_stats_time = time.time()
                if (time.time() - last_write_time) > int(write_interval):
                    self.write_all(output_file,write_interval)
                    last_write_time = time.time()
                if (time.time() - last_cleanup_time) > int(cleanup_interval):
                    self.cleanup(int(max_event_mem_storage_per_host))
                    last_cleanup_time = time.time()
                if (time.time() - last_persist_time) > int(persist_interval):
                    self.save(self.config["smm"]["save_state_location"],self.config['smm']['persist_format'])
                    last_persist_time = time.time()
        except KeyboardInterrupt as e:
            # shutdown when KeyboardInterrupt is raised
            # save memory so we can pickup where we left off
            logging.error("Unhandled exception\n{}".format(e))
            logging.error("Unhandled exception\n{}".format(traceback.format_exc()))
            logging.info("Saving State: {}".format(name))
            self.save(self.config["smm"]["save_state_location"],self.config['smm']['persist_format'])
            logging.info("Stopped: {}".format(name))
        except Exception as e:
            # save memory so we can pickup where we left off
            logging.error("Unhandled exception\n{}".format(e))
            logging.error("Unhandled exception\n{}".format(traceback.format_exc()))
            logging.info("Saving State: {}".format(name))
            self.save(self.config["smm"]["save_state_location"],self.config['smm']['persist_format'])
            logging.info("Stopped: {}".format(name))

        # once stdin is closed, save latest state before exiting
        logging.info("Saving State: {}".format(name))
        self.save(self.config["smm"]["save_state_location"],self.config['smm']['persist_format'])
        logging.info("Stopped: {}".format(name))

if __name__ == '__main__':

    # it a file filled with sysmon events
    parser = argparse.ArgumentParser(description="Sysmon More - Enriched Sysmon Events")
    parser.add_argument('-f', '--file', required=False, default=None, dest='sysmon_events_file',
        help="The file or directory path containing sysmon event data to enrich")
    parser.add_argument('-p', '--print', action="store_true", dest='print_trees',
        help="Print More Data - in pretty form")
    parser.add_argument('-i', '--stdin', required=False, default=None, dest='read_stdin',
        help="Reads file paths from a pipe, pass the name of the daemon (used for log file names, subdirectory usage,etc)")
    parser.add_argument('-r', '--resume', required=False, default=None, dest='resume',
        help="Resume from saved files - specify directory of saved files")
    parser.add_argument('-s', '--save', required=False, default=None, dest='save',
        help="Save Sysmon_More memory data to specified file")
    parser.add_argument('-pf', '--persist-format', required=False, default='json', dest='persist_format',
        help="Save Sysmon_More memory data to specified format")
    parser.add_argument('-w', '--write', required=False, default=None, dest='write_trees',
        help="Append/Write Sysmon_More memory to json file")
    parser.add_argument('-c', '--config', required=False, default="etc/logging.ini", dest='config',
        help="Path to config file")
    parser.add_argument('-g', '--guid', required=False, default=None, dest='guid',
        help="guid to print full tree for")
    parser.add_argument('-m', '--more-file', required=False, default=None, dest='more',
        help="Read in the persistent saved memory file back into memory")
    parser.add_argument('-y', '--yara', action="store_true", dest='yarascan',
        help="scan with yara (rules directory configuration is required)")

    args = parser.parse_args()

    # initialize logging
    try:
        logging.config.fileConfig(args.config)
    except Exception as e:
        sys.stderr.write("ERROR: unable to load logging config from {0}: {1}".format(
            args.config, str(e)))
        sys.exit(1)

    sm = SysMonMore()
    if args.read_stdin:
        sm.daemon(args.read_stdin)

    if args.resume:
        sm.resume(args.resume,args.persist_format)

    if args.sysmon_events_file:
        if os.path.isdir(args.sysmon_events_file):
            for f in os.listdir(args.sysmon_events_file):
                # only files in the directory are to be read
                if os.path.isdir(os.path.join(args.sysmon_events_file,f)):
                    break
                with open(os.path.join(args.sysmon_events_file,f),'r') as fp:
                    for line in fp:
                        o = json.loads(line)
                        sm.add_event(o)

        else:
            with open(args.sysmon_events_file,'r') as fp:
                for line in fp:
                    o = json.loads(line)
                    sm.add_event(o)

    if args.yarascan:
        if not args.sysmon_events_file:
            print("-f required for scanning")
            sys.exit(1)
        sm.scan_all()


    if args.print_trees:
        sm.print_trees()

    if args.guid:
        if args.sysmon_events_file or args.resume:
            sm.print_guid(args.guid)
        else:
            print("-f or -r required with -g option")
            sys.exit()

    if args.write_trees:
        time.sleep(3)
        sm.write_all(args.write,1)

    if args.save:
        time.sleep(3) # need to wait a little for the write interval to pass
        sm.save(args.save,args.persist_format)

    sm.stats()
    #sm.print_guid('{1018D5A4-5DE6-5BFC-0000-0010E0030200}')
    sm.cleanup(1)
