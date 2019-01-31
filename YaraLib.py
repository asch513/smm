from configparser import ConfigParser
import json
import logging
import mmap
import os
import requests
import sys
import time
import traceback
import yara
from subprocess import Popen, PIPE

# custom ConfigParser to keep case sensitivity
class CaseConfigParser(ConfigParser):
    def optionxform(self, optionstr):
        return optionstr

class YaraScanner:
    def __init__(self):
        self.last_commit = ""
        self.rules = {}
        self.all_rules = None

        config = CaseConfigParser()
        config.read('etc/config.ini')
        self.rulesDir = config['yara']['repo_directory']
        # we keep track of when the rules change and (optionally) automatically re-load the rules
        self.tracked_files = {} # key = file_path, value = last modification time
        self.tracked_dirs = {} # key = dir_path, value = {} (key = file_path, value = last mtime)
        self.tracked_repos = {} # key = dir_path, value = current git commit
        
        # set max string limit
        yara.set_config(max_strings_per_rule=20000)
        self.UpdateRules()

    def Scan(self, datas):
        # recompile rules if they have changed
        #if self.RepoHasChanged():
        if self.check_rules():
            self.UpdateRules()

        # scan the log
        matches = self.all_rules.match(data=datas, timeout=60)
        if len(matches) > 0:
            logging.info("HITS: {}".format(matches))
        rulenames = []
        tags = []
        strings = []
        for match in matches:
            rulenames.append(match.rule)
            tags.append("".join(match.tags))
            for offset, mid, mstring in match.strings:
                strings.append("{}={}".format(mid,str(mstring,'utf-8')))
             

        return matches, rulenames, tags, strings

    def get_current_repo_commit(self,repo_dir):
        """Utility function to return the current commit hash for a given repo directory.  Returns None on failure."""
        p = Popen(['git', '-C', repo_dir, 'log', '-n', '1', '--format=oneline'], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        commit, stderr= p.communicate()
        p.wait()

        if len(stderr.strip()) > 0:
            logging.error("git reported an error: {}".format(stderr.strip()))

        if len(commit) < 40:
            logging.error("got {} for stdout with git log".format(commit.strip()))
            return None

        return commit[0:40]

    def track_yara_dir(self, dir_path):
        """Adds all files in a given directory that end with .yar when converted to lowercase.  All files are monitored for changes to mtime, as well as new and removed files."""
        if not os.path.isdir(dir_path):
            logging.error("{} is not a directory".format(dir_path))
            return

        self.tracked_dirs[dir_path] = {}

        for file_path in os.listdir(dir_path):
            file_path = os.path.join(dir_path, file_path)
            if file_path.lower().endswith('.yar') or file_path.lower().endswith('.yara'):
                self.tracked_dirs[dir_path][file_path] = os.path.getmtime(file_path)
                logging.debug("tracking file {} @ {}".format(file_path, self.tracked_dirs[dir_path][file_path]))

        logging.debug("tracking directory {} with {} yara files".format(dir_path, len(self.tracked_dirs[dir_path])))

    def track_yara_repository(self, dir_path):
        """Adds all files in a given directory that end with .yar when converted to lowercase.  Only changes to the current commit trigger rule reload."""
        if not os.path.isdir(dir_path):
            logging.error("{} is not a directory".format(dir_path))
            return False

        if not os.path.exists(os.path.join(dir_path, '.git')):
            logging.error("{} is not a git repository (missing .git)".format(dir_path))
            return False

        # get the initial commit of this directory
        self.tracked_repos[dir_path] = self.get_current_repo_commit(dir_path)
        logging.debug("tracking git repo {} @ {}".format(dir_path, self.tracked_repos[dir_path]))

    def check_rules(self):
        """Returns True if the rules need to be recompiled, False otherwise."""
        reload_rules = False # final result to return

        for file_path in self.tracked_files.keys():
            if self.tracked_files[file_path] is not None and not os.path.exists(file_path):
                logging.info("detected deleted yara file {}".format(file_path))
                self.track_yara_file(file_path)
                reload_rules = True

            elif os.path.getmtime(file_path) != self.tracked_files[file_path]:
                logging.info("detected change in yara file {}".format(file_path))
                self.track_yara_file(file_path)
                reload_rules = True

        for dir_path in self.tracked_dirs.keys():
            reload_dir = False # set to True if we need to reload this directory
            existing_files = set() # keep track of the ones we see
            for file_path in os.listdir(dir_path):
                file_path = os.path.join(dir_path, file_path)
                if not ( file_path.lower().endswith('.yar') or file_path.lower().endswith('.yara') ):
                    continue

                existing_files.add(file_path)
                if file_path not in self.tracked_dirs[dir_path]:
                    logging.info("detected new yara file {} in {}".format(file_path, dir_path))
                    reload_dir = True
                    reload_rules = True

                elif os.path.getmtime(file_path) != self.tracked_dirs[dir_path][file_path]:
                    logging.info("detected change in yara file {} dir {}".format(file_path, dir_path))
                    reload_dir = True
                    reload_rules = True

            # did a file get deleted?
            for file_path in self.tracked_dirs[dir_path].keys():
                if file_path not in existing_files:
                    logging.info("detected deleted yara file {} in {}".format(file_path, dir_path))
                    reload_dir = True
                    reload_rules = True

            if reload_dir:
                self.track_yara_dir(dir_path)

        for repo_path in self.tracked_repos.keys():
            current_repo_commit = self.get_current_repo_commit(repo_path)
            #log.debug("repo {} current commit {} tracked commit {}".format(
                #repo_path, self.tracked_repos[repo_path], current_repo_commit))

            if current_repo_commit != self.tracked_repos[repo_path]:
                logging.info("detected change in git repo {}".format(repo_path))
                self.track_yara_repository(repo_path)
                reload_rules = True

        return reload_rules

    def UpdateRules(self):
        logging.info("compiling rules")

        # dictionary containing rule sources
        sources = {}
        all_sources = {}

        if os.path.exists(os.path.join(self.rulesDir, '.git')):
            self.track_yara_repository(self.rulesDir)
        else:
            self.track_yara_dir(self.rulesDir)

        # for each rule in indicator_mappings
        for rule_name in os.listdir(self.rulesDir):
            # get path to rule file
            rulePath = os.path.join(self.rulesDir, rule_name)

            if 'yar' in rulePath and os.path.isfile(rulePath):
                # add rule to master list of rules
                all_sources[rule_name] = rulePath
            else:
                logging.info("file in rule directory does not have .yara or .yar name, skipping: {}".format(rulePath))
            
        # compile rule sources
        try:
            self.all_rules = yara.compile(filepaths=all_sources)
        except:
            logging.error("failed to compile master rules: {}".format(traceback.format_exc()))

        logging.info("finished compiling rules")


if __name__ == '__main__':
    ys = YaraScanner()
    ys.UpdateRules()
    datas = "something\nsomething.exe\nproc_path=me.exe"
    
    matches = ys.Scan(datas)

    print(matches)
    #print(matches.strings)
