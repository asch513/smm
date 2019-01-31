#!/usr/bin/env python3
import logging
import logging.config
import os
import signal
import subprocess
import traceback
from configparser import ConfigParser
import time
import json
import argparse
import sys
import subprocess
from subprocess import Popen,PIPE,STDOUT

# custom ConfigParser to keep case sensitivity
class CaseConfigParser(ConfigParser):
    def optionxform(self, optionstr):
        return optionstr

config = CaseConfigParser()
config.read('etc/config.ini')
logging.config.fileConfig('etc/logging.ini')

def close_workers(workers):
    for x in workers.keys():
        logging.info("closing worker {}".format(x))
        workers[x].stdin.close()
    time.sleep(5)
    logging.info("Workers Closed.")
        

def save(sysmap):
    output_dir = config["main"]["save_state_location"]
    output_name = config['main']['save_file_name']
    fformat = config['main']['persist_format']
    if len(sysmap.keys()) > 0:
        logging.info("saving memory for: {}".format(output_name))
        f = open(os.path.join(output_dir,output_name),'w')
        if fformat == 'json':
            json.dump(sysmap,f)
        if fformat == 'pickle':
            pickle.dump(sysmap,f)
        f.close()
    else:
        logging.info("no memory to save for: {}/{}".format(output_dir,output_name))
    return

# sends keyboard interrupt to shutdown
def Shutdown(signal, frame):
    logging.info("attempting shutdown of smm")
    save(sysmap)
    close_workers(workers)

# handle sigterm so service stop shutdowns nicely
signal.signal(signal.SIGTERM, Shutdown)

src_location = config['main']['src_location']
dst_dir = config['main']['event_file_directory']
heartbeat_interval = config['main']['heartbeat_interval']
last_heartbeat = time.time()
if not os.path.exists(dst_dir):
    logging.info("Event File Directory \"event_file_directory\" does not exist: {}".format(dst_dir))
    sys.exit()

tmp_dir = config['main']['tmp_rsync_dir']
if not os.path.exists(tmp_dir):
    logging.info("Temp Directory \"tmp_rsync_dir\" does not exist: {}".format(tmp_dir))
    sys.exit()

worker_count = int(config['main']['worker_count'])
worker_base_directory = config['main']['worker_base_directory']
worker_program = config['main']['worker_program']
if not os.path.exists("{}/{}".format(worker_base_directory,worker_program)):
    logging.info("Worker path not found: {}/{}".format(worker_base_directory,worker_program))
    sys.exit()

save_state_location = config["main"]["save_state_location"]
if not os.path.exists(save_state_location):
    logging.info("Save State Location \"save_state_location\"  not found: {}".format(save_state_location))
    sys.exit()

# keep track of which process is responsible for what host
map_file_path = "{}/{}".format(config['main']['save_state_location'],config['main']['save_file_name'])
sysmap = {}

if os.path.exists(map_file_path):
    fformat = config['main']['persist_format']
    with open(map_file_path,'r') as data:
        if fformat == 'json':
            sysmap = json.load(data)
        if fformat == 'pickle':
            sysmap = pickle.load(data)
    s = set()
    for val in sysmap.values():
        s.add(val)
    # not yet sure how to handle when worker numbers change (distribute to new value?...take care of it later)
    if len(s) != int(worker_count):
        logging.info("The configuration for number of workers has changed. Detected {} directories, Config Item: {}, Config specifies {}".format(len(s),'output_count',output_count))
        sys.exit()

# start processes
workers = {}
next_worker = 0
for x in range(0,worker_count):
    # python3 sysmon_more.py -i -m path/x.json -r
    logging.info("starting process: {}".format(x))
    worker_path = os.path.join(worker_base_directory,worker_program)
    workers[x] = subprocess.Popen([worker_path,"-i",str(x)],cwd=worker_base_directory,stdin=PIPE,universal_newlines=True)
    time.sleep(3)



# process files until shutdown
while True:
    try:

        # get list of files that are open by logstash
        open_files = []
        #print(["rsync","-avzuh","-e","ssh","{}/".format(src_location),"{}/.".format(dst_dir),"--remove-source-files","{}={}".format("--temp-dir",tmp_dir)])
        try:
            result = subprocess.call(["rsync","-avzuh","-e","ssh","{}/".format(src_location),"{}/.".format(dst_dir),"--remove-source-files","{}={}".format("--temp-dir",tmp_dir)])
            if result > 0:
                logging.error("Attempting to rsync failed: src: {}, dst: {}, tmpdir: {}, error: {}".format(src_location,dst_dir,tmp_dir,result))
                time.sleep(10)
                break
        except Exception as e:
            # report unhandled exception and continue
            logging.error("rsync error, continuing: {}".format(e))
         
        
        # process all job files that are no longer open by logstash
        newjobs =  False
        for job in os.listdir(dst_dir):
            # directory should have files in format pc1.domain.com___DD_HH_MM
            filename = job.split('___')[0]
            jobPath = os.path.join(dst_dir, job)
            # skip non-files
            if not os.path.isfile(jobPath):
                continue

            newJobs = True
            result = None
            command = "{}\n".format(jobPath)
            if filename in sysmap.keys():
                workers[sysmap[filename]].stdin.write(command)
                workers[sysmap[filename]].stdin.flush()
            else:
                workers[next_worker].stdin.write(command)
                workers[next_worker].stdin.flush()
                sysmap[filename] = next_worker
                # save new mapping
                save(sysmap)
                if next_worker == len(workers.keys())-1:
                    next_worker = 0
                else:
                    next_worker += 1

        if not newjobs:
            # if no new jobs, take a rest
            time.sleep(10)

        # sysmon_more will only do stats/cleanup/writing of items in the loop of waiting for stdin
        # if there are not many logs, the intervals could be extremely long, send a heartbeat so that it writes close to the intervals it should
        if (time.time() - last_heartbeat) > int(heartbeat_interval):
            for x in range(0,worker_count): 
                workers[x].stdin.write("heartbeat_check\n")
                workers[x].stdin.flush()
                time.sleep(2)
            last_heartbeat = time.time()

    except KeyboardInterrupt as e:
        # shutdown when KeyboardInterrupt is raised
        # save memory so we can pickup where we left off
        close_workers(workers)
        break
    except Exception as e:
        # report unhandled exception and continue
        logging.error("Unhandled exception\n{}".format(e))
        logging.error("Unhandled exception\n{}".format(traceback.format_exc()))
        close_workers(workers)
