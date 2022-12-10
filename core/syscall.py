from core.utils import Utils
from core.logger import get_logger

import ctags
import os
import re

class Syscall(object):

        syscall_tbl_regex = re.compile(r"([0-9]+)[\t|\s]+(common|64|x32)[\t|\s]+([a-z_0-9]+)\t+[sys_|compat_]+[a-z_0-9]*")
        crashing_files = ['socket.c']   # C2XML cannot process these .i files

        def __init__(self, sysobj):
                self.sysobj = sysobj
                self.target = self.sysobj.target
                self.compile_commands = self.sysobj.compile_commands
                self.verbosity = self.sysobj.log_level
                self.syscalls = []
                self.defines_dict = {}

                self.logger = get_logger("Syscall", self.verbosity)
                self.output_path = os.path.join(os.getcwd(), "out/", self.sysobj.os, "preprocessed/")
        
        def add_to_dict(self, entry):
                regex_match = re.compile(r"(.*)SYSCALL_DEFINE[0-9][\(]([a-z_0-9]*)")

                if entry['kind'] == bytes('f', "utf-8"):
                        pattern = entry['pattern'].decode("utf-8")
                        entryfile = entry['file'].decode("utf-8")
                        regmatch = regex_match.match(pattern)
                        if regmatch and (regmatch.group(2) in self.syscalls) and (entryfile.split('/')[-1] not in self.crashing_files):
                                self.defines_dict[regmatch.group(2)] = entryfile

        def fetch_defines(self, ctagfile) -> dict:
                tags = ctags.CTags(ctagfile)
                entry = ctags.TagEntry()
                defines = {}

                # find first match
                tags.find(entry, bytes("SYSCALL_DEFINE", "utf-8"), ctags.TAG_PARTIALMATCH)
                self.add_to_dict(entry)

                while tags.findNext(entry):
                        self.add_to_dict(entry)


        def find_files(self, ctagfile) -> bool:
                """Find the file containing the syscall definition using ctags"""
                self.logger.debug("[+] Finding syscall definition")
                
                if not os.path.exists(ctagfile):
                        self.logger.critical("[+] Tags file not found")
                        return False
                
                self.fetch_defines(ctagfile)
                return True

                
        def find_syscalls(self, syscall_tbl):
                """Parse syscalls.tbl file and fetch all syscalls"""
                self.logger.debug("[+] Finding syscall definition")

                try:
                        fd = open(syscall_tbl, "r")
                except IOError:
                        self.logger.error("Unable to read the file '%s'", syscall_tbl)
                        self.logger.critical("Skipping this file")
                        return
                
                with fd:
                        for line in fd.readlines():
                                syscall_match = self.syscall_tbl_regex.match(line)
                                if syscall_match:
                                        self.syscalls.append(syscall_match.group(3))
                
                fd.close()
                return