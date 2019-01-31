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

# NOTE: https://www.ultimatewindowssecurity.com is a great source for understanding windows event logs, incuding sysmon events!!
# custom ConfigParser to keep case sensitivity
class CaseConfigParser(ConfigParser):
    def optionxform(self, optionstr):
        return optionstr

config = CaseConfigParser()
config.read('etc/config.ini')

# initialize logging
try:
    logging.config.fileConfig('etc/distributor_logging.ini')
except Exception as e:
    sys.stderr.write("ERROR: unable to load logging config from {0}: {1}".format(
           'etc/distributor_logging.ini', str(e)))
    sys.exit(1)

# sends keyboard interrupt to shutdown
def Shutdown(signal, frame):
    raise KeyboardInterrupt()

# handle sigterm so service stop shutdowns nicely
signal.signal(signal.SIGTERM, Shutdown)

# directory to move files to
output_dir = config['distributor']['output_dir']
# a comma separated list of system names (usually set to the hostname of the system that will be consuming the data inside the directory)
output_dir_names = config['distributor']['output_dir_names']
output_dir_names = output_dir_names.split(',')
output_count = len(output_dir_names)
print("output_count {}".format(output_count))
round_robin = {}
round_robin_count = 1
stats = {}
for dirname in output_dir_names:
    round_robin[round_robin_count] = dirname
    stats[dirname] = 0
    round_robin_count += 1
# the path to the file to store persistence of the sysmap (need to persist the hostname file to the directory after reboot so workers have the right events to work off of)
map_file_path = config['distributor']['map_file_path']
# print stats at this interval
stats_interval = config['distributor']['stats_interval']
last_stats_time = time.time()
# used to round robin which directory to write new hostname files to
next_output_dir = 1
# map the filename (which should be the hostname from logstash) to the directory (to keep files for each host going to the same directory)
sysmap = {}
if os.path.exists(map_file_path):
    print("loading {}".format(map_file_path))
    with open(map_file_path,'r') as data:
        sysmap = json.load(data)
    # is our count the same as what is in the sysmap or different?
    # did the number of outputs change?
    # right now, we are going to just exit, but we can add default functionality if this happens for future
    s = set()
    for val in sysmap.values():
        s.add(val)
    if len(s) != len(round_robin.keys()):
        print("The configuration of distribution directories has changed. Detected {} directories, Config Item: {}, Config specifies {}".format(len(s),'output_count',output_count))
        sys.exit()

if not os.path.isdir(output_dir):
    print("Output directory: {} - DOES NOT EXIST. Exiting.".format(output_dir))
    sys.exit()

print("round robin {}".format(round_robin))
for x in range(1,output_count+1):
    # is this the first time creating this output dir?
    if not os.path.isdir(os.path.join(output_dir,round_robin[x])):
        os.mkdir(os.path.join(output_dir,round_robin[x]))
        print("mkdir {}".format(os.path.join(output_dir,round_robin[x])))
    # it exists, see if host files exist, create the map for them
    #for filename in os.listdir(os.path.join(output_dir,round_robin[x])):
    #    sysmap[filename] = round_robin[x]

print(sysmap)

# process files until shutdown
while True:
    try:
        # process jobs in order
        jobs = sorted([job for job in os.listdir(config["distributor"]["input_dir"])])

        # get list of files that are open by logstash
        open_files = []
        process = subprocess.Popen("systemctl status logstash | grep PID | awk '{print $3}'", stdout=subprocess.PIPE, shell=True)
        pid, err = process.communicate()
        pid = pid.decode("utf-8").strip()
        if len(pid) > 0:
            proc_dir = "/proc/{}/fd".format(pid)
            for fd in os.listdir(proc_dir):
                link = os.path.join(proc_dir, fd)
                try:
                    path = os.readlink(link)
                    if path.startswith(config["distributor"]["input_dir"]):
                        open_files.append(path)
                except KeyboardInterrupt as e:
                    raise(e)
                except:
                    continue
        # process all job files that are no longer open by logstash
        newjobs =  False
        for job in jobs:
            newjobs = True
            jobPath = os.path.join(config["distributor"]["input_dir"], job)
            filename = job.split('___')[0]
            if round_robin[next_output_dir] not in stats.keys():
                stats[round_robin[next_output_dir]] = 0
            print("jobPath: {}".format(jobPath))
            if filename in sysmap.keys():
                print("renaming {} : sysmap: {}, round_robin: {}, job: {}".format(jobPath,sysmap,round_robin,job)) 
                os.rename(jobPath,os.path.join(config['distributor']['output_dir'],sysmap[filename],job))
                logging.info("finished processing {}".format(jobPath))
                stats[round_robin[next_output_dir]] += 1
            else:
                os.rename(jobPath,os.path.join(config['distributor']['output_dir'],round_robin[next_output_dir],job))
                sysmap[filename] = round_robin[next_output_dir]
                with open(map_file_path, 'w') as outfile:
                    json.dump(sysmap, outfile)
                stats[round_robin[next_output_dir]] += 1
                # round robin setup for next time
                if next_output_dir == len(round_robin.keys()):
                    next_output_dir = 1
                else:
                    next_output_dir += 1
                print("next_output_dir {}".format(next_output_dir))

        if not newjobs:
            # if no new jobs, take a rest
            time.sleep(5)

        if (time.time() - last_stats_time) > int(stats_interval):
            print("{}".format(stats))
            total = 0
            for item in stats.keys():
                total += stats[item] 
            print("processed {} files in {} seconds".format(total,stats_interval))
            stats = {}
            last_stats_time = time.time()

    except KeyboardInterrupt:
        # shutdown when KeyboardInterrupt is raised
        # save memory so we can pickup where we left off
        logging.info("Stopped")
        break

    except:
        # report unhandled exception and continue
        logging.error("Unhandled exception\n{}".format(traceback.format_exc()))
