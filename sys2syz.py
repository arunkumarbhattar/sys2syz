# User imports
from core.Utils import Utils
from core.logger import get_logger

from core.Bear import *
from core.Extractor import Extractor, Ioctl
from core.C2xml import *
from core.Descriptions import *

# Default imports 
import argparse
import os
import sys
import string

class Sys2syz(object):
    NETBSD = 1
    supported_os = {'NetBSD': NETBSD}

    def __init__(self, target, compile_commands, os_name, log_level):
        self.target = os.path.realpath(target)
        self.compile_commands = compile_commands
        self.os = os_name
        self.os_type = None
        self.log_level = log_level
        if not self._sanity_check():
            logging.critical("[+] Sys2syz failed to init")
            sys.exit(-1)

        # initialize the sub classes    
        self.extractor = Extractor(self)
        self.bear = Bear(self)
        self.c2xml = C2xml(self)

        self.header_files = self.extractor.header_files
        logging.debug("[+] Sys2syz init completed")

    def _sanity_check(self) -> bool:
        """Perform Sanity check on the arguments passed

        Returns:
            bool: Reflect passed or failed
        """
        if not os.path.isdir(self.target):
            logging.error("[+] The target file is not found at %s", self.target)
            return False
        logging.debug("[+] The target file is %s", self.target)

        if not os.path.isfile(self.compile_commands):
            logging.error("[+] The compile commands not found at %s", self.compile_commands)
            return False
        logging.debug("[+] The compile commands file is %s", self.compile_commands)

        for os_type in self.supported_os.keys():
            if os_type.lower() == self.os.lower():
                self.os_type = self.supported_os[os_type]                
                return True
        
        logging.error("[+] Target OS not supported/found %s", self.os)
        return False

    def get_ioctls(self) -> bool:
        """ Get's the IOCTL calls as a list and does sanity check and some stats

        Returns:
            bool: True is ioctls were found
        """
        self.extractor.get_ioctls()
        self.ioctls = self.extractor.ioctls

        if len(self.ioctls) == 0:
            return False

        if self.log_level > 1:
            ioctl_string = ""
            for ioctl in self.ioctls:
                ioctl_string += str(ioctl) + "\n"
            open("test.log").write(ioctl_string)

        logging.info(f"[+] {len(self.ioctls)} IOCTL calls were found!")
        return True

    @property
    def undefined_macros(self) -> list:
        und_macros = self.extractor.fetch_flags()
        logging.info(f"[+] {und_macros)} undefined macros were found from the file!")
        return und_macros

    def get_macro_details(self):
        self.macro_details = self.extractor.flag_details(self.undefined_macros)
        logging.info(f"[+] Extracted details of {len(self.macro_details)} macros from c2xml!")

    def preprocess_files(self) -> bool:
        """ Preprocess the files
        """
        try:
            if self.bear.parse_compile_commands():
                return True
        except Exception as e:
            logging.critical("Unable to run bear and parse compile commands")
            logging.error(e)
        return False 
    
        
def main():
    global logging
    # Parse the command line arguments
    parser = argparse.ArgumentParser(description="Sys2Syz : A Utility to convert Syscalls and Ioctls to Syzkaller representation")

    parser.add_argument("-t", "--target", help="target file to generate descriptions for", type=str, required=True)
    parser.add_argument("-o", "--operating-system", help="target operating system", type=str, required=True)
    parser.add_argument("-c", "--compile-commands", help="path to compile_commands.json", type=str, required=True)
    parser.add_argument("-v", "--verbosity", help="make Griller spit more things out", action="count")
    args = parser.parse_args()

    logging = get_logger("Syz2syz", args.verbosity)

    # get the header files
    sysobj = Sys2syz(args.target, args.compile_commands, args.operating_system, args.verbosity)
    
    if len(sysobj.header_files) == 0:
        logging.error("No header files found!")
        sys.exit(-1)

    logging.debug(sysobj.header_files)

    # get the IOCTL calls
    if not sysobj.get_ioctls():
        logging.error("No IOCTL calls found!")
        sys.exit(-1)

    if sysobj.preprocess_files():
        logging.error("Can't continue.. Exiting")
        sys.exit(-1)
    
    # Extract the macros/flags 
    sysobj.get_macro_details()
    logging.info("[+] Completed the initial pre processing of the target")

    out_dir = c2xml.run_c2xml()
    logging.debug("[+] Created XML files")

    # TODO: you can create wrapper functions for all these in sysobj. 
    # TODO: change the descriptions object so that it take sysobj as constructor parameter
    # TODO: change the functions in the object so they use self.sysobj.macro_details to get the detials

    #Get syz-lang descriptions
    descriptions = Descriptions(out_dir, macro_details)
    descriptions.run(ioctl_cmd_file)

    #Store the descriptions in the syzkaller's syscall description file format
    output_path = descriptions.make_file(cmd_header_files)
    if Utils.file_exists(output_path, True):
        logging.debug("[+] Description file: " + output_path)
    

if __name__ == "__main__":
    logging = None
    main()