# Module : Extractor.py
# Description : Extracts the necessary details from the source code
import logging

from core.utils import Utils
from core.logger import get_logger

from os.path import join, basename, isdir, isfile, exists
import os
import re
import collections


class Ioctl(object):
    LNX = 5
    IO = 1
    IOW = 2
    IOR = 3
    IOWR = 4
    types = {IO: 'null', IOW: 'in', IOR: 'out', IOWR: 'inout', LNX: 'inout'}

    def __init__(self, gtype, filename, command, description=None, sysobj=None, target=None, IOCTL_TRAP=0):
        self.description = description
        self.os_name = sysobj.os_type
        self.typedefs = sysobj.typedefs
        self.type = gtype
        self.command = command
        self.filename = filename
        self.target = target
        self.sysobj = sysobj
        self.IOCTL_TRAP = IOCTL_TRAP

    def __repr__(self):
        if self.os_name == 2 and self.description is None:  # 2 is linux
            #self.description = self.get_linux_ioctl_structs(self.command)
            print("The description is : " + str(self.description))
        return str(self.types[self.type]) + ", " + str(self.command) + ", " + str(self.filename) + ", " + str(
            self.description) + ", " + str(self.IOCTL_TRAP)


    def c_files(self) -> list:
        """
        Find all the header files in device folder
        :return: list of header files
        """
        c_files = []
        for filename in os.listdir(self.target):
            # store all the filenames ending with ".h" in an array
            if filename.endswith('.c'):
                c_files.append(filename)
        return c_files

    def get_linux_ioctl_structs(self, ioctl_cmd, NeedToCheckIoctlHandler=False, ioctl_handler_func_name = "") -> str:
        # NeedToCheckIoctlHandler is a variable that is set, if no structs were found in the vicinity of the ioctl handler
        # which would allow us to generate a description for this ioctl
        # This is by default false, and is set to true if no structs are found in the vicinity of the ioctl handler
        # following which, once again all c files will be searched for this ioctl handler, and
        # structs will be looked for within the function scope of the ioctl handler
        # iterate through all the .c files
        for c_file in self.c_files():
            # Iterate through all lines in the c files
            try:
                fd = open(join(self.target, c_file), "r")
                content = fd.readlines()
                fd.close()
            except IOError:
                self.logger.error("Unable to read the file '%s'", c_file)
                self.logger.critical("Skipping this file")
                continue

            isInsideCase = False
            isDetected = False
            for line in iter(content):
                line = line.strip()
                if not isDetected and not isInsideCase:
                    if not NeedToCheckIoctlHandler:
                        if "case" in line and ioctl_cmd in line:
                            print("Found the case statement as " + str(line))
                            isDetected = True
                            continue
                    else:
                        if ioctl_handler_func_name in line and "return" not in line: #look for definitions and not calls
                            print("Found the ioctl handler as " + str(line))
                            isDetected = True
                            continue
                elif isDetected:
                    isInsideCase = True
                    # print the line
                    print(str(line))
                    if "return" in line:
                        # check if line contains ( and )
                        if "(" in line and ")" and "ioctl" in line: # this means this is a call into the ioctl handler
                            if self.description is None:
                                # split the line based on space
                                ioctl_handler = line.split(" ")
                                # get the second element of the array
                                ioctl_handler_func = ioctl_handler[1]
                                # crop ioctl_handler_func based on the second occurrence of (
                                ioctl_handler_func = ioctl_handler_func.split("(")[0]
                                # now remove "(" and ")" from the string
                                ioctl_handler_func = ioctl_handler_func.replace("(", "")
                                # strip spaces
                                ioctl_handler_func = ioctl_handler_func.strip()
                                # prompt the user if he wants to look into the ioctl handler
                                print("No struct found in the vicinity of ioctl command " + self.command)
                                print("However..Do you want to look into the ioctl handler ( " + ioctl_handler_func + " ) ? (y/n)")
                                # while the user input is not y or n, keep prompting
                                while True:
                                    user_input = input()
                                    if user_input == "y":
                                        print("Looking into the ioctl handler")
                                        self.description = self.get_linux_ioctl_structs(ioctl_cmd, True, ioctl_handler_func)
                                        break
                                    elif user_input == "n":
                                        print("Not looking into the ioctl handler")
                                        return ""
                                    else:
                                        print("Please enter y or n")
                                break
                        else:
                            isInsideCase = False
                            break
                    if "}" in line:
                        isInsideCase = False
                        if self.description is None:
                            # keep looking for another case handler.
                            # the correct case statement for the ioctl command would never break away without a self description or a call to the ioctl handler
                            continue
                        break
                    if "break" in line:
                        isInsideCase = False
                        if self.description is None:
                            # keep looking for another case handler.
                            # the correct case statement for the ioctl command would never break away without a self description or a call to the ioctl handler
                            continue
                        break
                    if "struct " in line or any(x in line for x in self.typedefs):
                        print("TYPEDEF LISTS ARE --> " + str(self.typedefs))
                        # split the line based on spaces
                        line_list = line.split(" ")
                        #print the list
                        print(str(line_list))
                        #iterate through the line_list and find the struct
                        for element in line_list:
                            print("The element is " + str(element))
                            if "struct" in element and ("(" and ")") not in element:
                                # get the index of the element
                                index = line_list.index(element)
                                # get the next element
                                struct_name = line_list[index + 1]
                                struct_name = struct_name.strip()
                            elif any(x in element for x in self.typedefs):
                                # fetch matching typedef
                                for typedef in self.typedefs:
                                    if typedef in element:
                                        struct_name = typedef
                                        print("The typedef name is " + str(struct_name))

                        print("The ioctl call " + self.command + " is using the struct : " + struct_name)
                        if self.description is None:
                            self.description = [str(struct_name)]
                        else:
                            self.description.append(struct_name)
            if isDetected and not isInsideCase:
                break

        if NeedToCheckIoctlHandler:
            return self.description
        if self.description is None:
            print("No struct found in the vicinity of ioctl command " + self.command)
            return "long"  # defaults to long

        # if the count of self.description is 1
        if len(self.description) >= 1:
            # prompt the user to select the correct struct
            res = []
            [res.append(x) for x in self.description if x not in res]
            self.description = res
            print("The ioctl command " + self.command + " is using the following structs : " + str(self.description))
            for i in range(len(self.description)):
                print(str(i) + " : " + self.description[i])
            selected_struct = input("Please enter the struct index OR (-1) to exit /(-2) default to long : ")
            while selected_struct not in [str(i) for i in range(len(self.description))] and selected_struct not in ["-1", "-2"]:
                selected_struct = input("Please enter the struct index OR (-1) to exit /(-2) default to long : ")
            if selected_struct == "-1":
                return ""
            elif selected_struct == "-2":
                return "int64"
            self.description = self.description[int(selected_struct)]
        return str(self.description)


class Extractor(object):
    # define a regex map for the ioctls corresponding to OS
    ioctl_regex_map = {
        1: "linux_type", 2: "linux_type"
    }

    # define regex for the different variations of all the ioctl commands found accross the supported OSes
    ioctl_regex_type = {
        "linux_type": {
            "io": re.compile(r"#define\s+(.*)\s+_IO\((.*)\).*"),  # regex for IO_
            "iow": re.compile(r"#define\s+(.*)\s+_IOW\((.*),\s+(.*),\s+(.*)\).*"),  # regex for IOW_
            "ior": re.compile(r"#define\s+(.*)\s+_IOR\((.*),\s+(.*),\s+(.*)\).*"),  # regex for IOR_
            "iowr": re.compile(r"#define\s+(.*)\s+_IOWR\((.*),\s+(.*),\s+(.*)\).*"),  # regex for IOWR_
            "lnx": re.compile(r"#define\s+[A-Za-z0-9_]+\s+0x[0-9]+", re.IGNORECASE),
            "lnx_amdkfd_ior": re.compile(r"\s*[A-Za-z0-9]+_IOR\(\s*0x[0-9]*\s*\\*,\s*\\*\s*(.*)", re.IGNORECASE),
            "lnx_amdkfd_iow": re.compile(r"\s*[A-Za-z0-9]+_IOW\(\s*0x[0-9]*\s*\\*,\s*\\*\s*(.*)", re.IGNORECASE),
            "lnx_amdkfd_iowr": re.compile(r"\s*[A-Za-z0-9]+_IOWR\(\s*0x[0-9]*\s*\\*,\s*\\*\s*(.*)", re.IGNORECASE)
        }
    }

    # io = re.compile(r"#define\s+(.*)\s+_IO\((.*)\).*") # regex for IO_
    # iow = re.compile(r"#define\s+(.*)\s+_IOW\((.*),\s+(.*),\s+(.*)\).*") #regex for IOW_
    # ior = re.compile(r"#define\s+(.*)\s+_IOR\((.*),\s+(.*),\s+(.*)\).*") #regex for IOR_
    # iowr = re.compile(r"#define\s+(.*)\s+_IOWR\((.*),\s+(.*),\s+(.*)\).*") #regex for IOWR_
    macros = re.compile(r"#define\s*\t*([A-Z_0-9]*)\t*\s*.*")
    more_macros = re.compile(
        r"#define(\s|\t)+([A-Z_0-9]*)[\t|\s]+(?!_IOWR|_IOR|_IOW|_IO|\()[0-9]*x?[a-z0-9]*")  # define(\s|\t)+([A-Z_0-9]*)[\t\s]+([^_IOWR{][0-9]*)")#define(\s|\t)+([^_][A-Z_0-9]*)\t*\s*.*")

    def __init__(self, sysobj):
        self.ioctls_headers = []
        if sysobj.os_type == 2:  # 2 is linux, 1 is netbsd
            self.ioctl_trap_prefix = sysobj.ioctl_trap_prefix
        self.sysobj = sysobj
        self.target = sysobj.target
        self.files = os.listdir(self.target)
        self.logger = get_logger("Extractor", sysobj.log_level)
        self.os_type = sysobj.os_type
        self.ioctl_type = self.ioctl_regex_map[self.os_type]
        # print ioctl_type
        self.ioctls = []
        self.typedefs = sysobj.typedefs
        self.target_dir = join(os.getcwd(), "out/", self.sysobj.os, "preprocessed/", basename(self.target))
        if not exists(self.target_dir):
            os.mkdir(self.target_dir)
        self.ioctl_file = ""

    def get_ioctls(self):
        """
        Fetch the ioctl commands with their arguments and sort them on the basis of their type
        :return:
        """
        lineCont = ""
        for file in self.header_files:
            try:
                fd = open(join(self.target, file), "r")
                # print filename
                print("Processing file : " + file)
                content = fd.readlines()
                fd.close()
            except IOError:
                self.logger.error("Unable to read the file '%s'", file)
                self.logger.critical("Skipping this file")
                continue

            for line in content:
                io_match = self.ioctl_regex_type[self.ioctl_type]["io"].match(line)
                if io_match:
                    self.ioctls.append(
                        Ioctl(Ioctl.IO, file, io_match.groups()[0].strip(), None, self.sysobj, self.sysobj.target))
                    self.ioctls_headers.append(file)
                    continue

                ior_match = self.ioctl_regex_type[self.ioctl_type]["ior"].match(line)
                if ior_match:
                    self.ioctls.append(
                        Ioctl(Ioctl.IOR, file, ior_match.groups()[0].strip(), ior_match.groups()[-1], self.sysobj,
                              self.sysobj.target))
                    self.ioctls_headers.append(file)
                    continue

                iow_match = self.ioctl_regex_type[self.ioctl_type]["iow"].match(line)
                if iow_match:
                    self.ioctls.append(
                        Ioctl(Ioctl.IOW, file, iow_match.groups()[0].strip(), iow_match.groups()[-1], self.sysobj,
                              self.sysobj.target))
                    self.ioctls_headers.append(file)
                    continue

                iowr_match = self.ioctl_regex_type[self.ioctl_type]["iowr"].match(line)
                if iowr_match:
                    self.ioctls.append(
                        Ioctl(Ioctl.IOWR, file, iowr_match.groups()[0].strip(), iowr_match.groups()[-1], self.sysobj,
                              self.sysobj.target))
                    self.ioctls_headers.append(file)
                    continue
                if self.os_type == 2 and self.ioctl_regex_type[self.ioctl_type]["lnx"].match(line) \
                        and self.ioctl_trap_prefix is not None:
                    # get the line as a string
                    line = line.strip()
                    trap_index = str(self.ioctl_trap_prefix)
                    self.logger.critical("trap index is %s", trap_index)
                    # check if trap_index is a substring of line
                    if trap_index in line:
                        # fetch space separated words
                        words = line.split()
                        # the last word is the IOCTL TRAP NUMBER
                        # the word containing the trap index is the IOCTL TRAP NAME
                        for word in words:
                            if trap_index in word:
                                ioctl_trap = word
                                ioctl_trap = ioctl_trap
                        # print ioctl name and trap
                        self.logger.critical("ioctl_trap %d for ioctl %s", ioctl_trap, words[1])
                        self.ioctls.append(
                        Ioctl(Ioctl.LNX, file, line.split()[1].strip(), None, self.sysobj, self.sysobj.target, ioctl_trap))
                    self.ioctls_headers.append(file)
                    continue
                if self.os_type == 2:

                    if "\\" and "#define" in line:
                        #temporarily store this line
                        #remove "#define" and "\"
                        lineCont = line.replace("#define", "")
                        lineCont = lineCont.replace("\\", "")
                        lineCont = lineCont.strip()

                    ior_match = self.ioctl_regex_type[self.ioctl_type]["lnx_amdkfd_ior"].match(line)
                    if ior_match:
                        self.ioctls.append(
                            Ioctl(Ioctl.IOR, file, lineCont, ior_match.groups()[-1].replace("\\", "").replace(")", "").strip(), self.sysobj,
                                  self.sysobj.target))
                        self.ioctls_headers.append(file)
                        continue
                    iow_match = self.ioctl_regex_type[self.ioctl_type]["lnx_amdkfd_iow"].match(line)
                    if iow_match:
                        self.ioctls.append(
                            Ioctl(Ioctl.IOW, file, lineCont, iow_match.groups()[-1].replace("\\", "").replace(")", "").strip(), self.sysobj,
                                  self.sysobj.target))
                        self.ioctls_headers.append(file)
                        continue
                    iowr_match = self.ioctl_regex_type[self.ioctl_type]["lnx_amdkfd_iowr"].match(line)
                    if iowr_match:
                        self.ioctls.append(
                            Ioctl(Ioctl.IOWR, file, lineCont, iowr_match.groups()[-1].replace("\\", "").replace(")", "").strip(), self.sysobj,
                                  self.sysobj.target))
                        self.ioctls_headers.append(file)
                        continue


    @property
    def header_files(self) -> list:
        """
        Find all the header files in device folder
        :return: list of header files
        """
        header_files = []
        for filename in self.files:
            # store all the filenames ending with ".h" in an array
            if filename.endswith('.h'):
                header_files.append(filename)
        return header_files

    @property
    def command_macros(self) -> list:
        """Finds all the commands in the Ioctls

        Returns:
            list: list of generated ioctls
        """
        commands = []
        for ioctl in self.ioctls:
            commands.append(ioctl.command)
        return commands

    @property
    def ioctl_files(self) -> list:
        """Finds all the files where Ioctls are defined

        Returns:
            list: list of files
        """
        files = set()
        for ioctl in self.ioctls:
            files.add(ioctl.filename)
        return list(files)

    def fetch_flags(self):
        """
        Fetch all the macros defined
        :return:
        """
        undefined_macros = []
        # read all the files present in target
        for file in self.header_files:
            try:
                buf = open(join(self.target, file), 'r').read()
                undefined_macros.extend(self.macros.findall(buf))
            except IOError:
                self.logger.error("Unable to open " + join(self.target, file))

        # return the macros found, except the IOCTL command macros in header files
        return list(set(undefined_macros) - set(self.command_macros))

    def fetch_typedef_structs_from_header(self):
        """
        Fetch all the typedef structs defined in the header files
        :return:
        """
        structs = []
        for file in self.header_files:
            try:
                fd = open(join(self.target, file), "r")
                # print filename
                print("Processing file : " + file)
                content = fd.readlines()
                fd.close()
            except IOError:
                self.logger.error("Unable to read the file '%s'", file)
                self.logger.critical("Skipping this file")
                continue
            isInsideTypedef = False
            for line in content:
                if "typedef " in line:
                    isInsideTypedef = True
                if isInsideTypedef and "} " in line:
                    isInsideTypedef = False
                    # this line contains the typedef of the struct or union definition
                    # print line
                    # remove "}" and ";" from the line
                    line = line.replace("}", "").replace(";", "")
                    # remove space from the line
                    line = line.replace(" ", "")
                    #strip new line specifiers
                    line = line.strip()
                    print("Discovered typedef struct/union --> " + line)
                    structs.append(line)
        return structs
    def flag_details(self, flags_defined):
        """
        Stores the macros within a particular scope of struct etc. in tuples with the corresponding line numbers.
        :return:
        """

        all_macros = dict()
        for file in filter(lambda x: x if x.endswith(".i") else None, os.listdir(self.target_dir)):
            try:
                fd = open(join(self.target_dir, file), "r")
            except IOError:
                self.logger.error("Unable to open " + join(self.target_dir, file))
                continue
            # placeholders during iteration
            prevline = None
            currset = None
            currset_start = None
            # to hold current file macros
            curr_file_macros = []
            # Iterate through all the lines in the file
            for linenum, line in enumerate(fd.readlines()):
                mobj = self.more_macros.match(line)
                if mobj:
                    # check if for new set or old set
                    define_new_set = False
                    if not prevline:
                        prevline = linenum
                        define_new_set = True
                    else:
                        if linenum - prevline != 1:
                            define_new_set = True
                    # if we need to define a new set append the older one if exists
                    # and then create a new one
                    if define_new_set:
                        if currset:
                            curr_file_macros.append((currset, currset_start, prevline))
                        currset = []
                        currset_start = linenum

                    # Append the set to the old one
                    macro_name = mobj.group(2)
                    if macro_name in flags_defined:
                        currset.append(mobj.group(2))
                        prevline = linenum

            all_macros[file] = curr_file_macros
        return all_macros

    def get_syscalls(self, source):
        # Get the syscall args
        # use regex to match the syscall file you used to use
        # get the details
        return self.syscall_details
