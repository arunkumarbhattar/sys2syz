# Module : Description.py 
# Description : Contains functions which generate descriptions.
from core.Utils import *

from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import xml.etree.ElementTree as ET
import re
import os
import string
import logging
import pylcs
import py_common_subseq as common_sub

type_dict = {
    "unsigned char": "int8",
    "char": "int8",
    "unsigned short": "int16",
    "uint32_t": "int32",
    "unsigned int": "int32",
    "int": "int32",
    "unsigned long": "intptr",
    "long": "intptr",
    "void": "void"
}

class Descriptions(object):
    def __init__(self,target, flag_descriptions):
        self.target = target
        self.flag_descriptions = flag_descriptions
        self.trees = {}
        self.gflags = {}
        self.structs_defs = {}
        self.union_defs = {}
        self.arguments = {}
        self.ptr_dir = None
        self.current_root = None
        self.current_file = None
        for file in (os.listdir(self.target)):
            tree = ET.parse(self.target+file)
            self.trees[tree] = file

    def get_root(self, ident_name):
        """
        Find root of the tree which stores an element whose ident value is <ident_name>
        :return: root
        """

        try:
            for tree in self.trees.keys():
                root = tree.getroot()
                for child in root:
                    if child.get("ident") == ident_name:
                        logging.debug("[*] Found Root ")
                        self.current_root = root
                        self.current_file = self.trees[tree].split(".")[0]
                        return root
        except Exception as e:
            logging.error(e)
            logging.debug('[*] Unable to find root')

    def resolve_id(self, root, find_id):
        """
        Find node having id value same as <find_id>, used for finding ident parameter for elements
        :return: node
        """

        try:
            for element in root:
                if element.get("id") == find_id:
                    return element
                for child in element:
                    if child.get("id") == find_id:
                        return child
        except Exception as e:
            logging.error(e)
            logging.debug("[*] Issue in resolving: %s", find_id)
        
    def get_id(self, root, find_ident):
        """
        Find node having ident value same as find_ident
        :return: 
        """

        try:
            for element in root:
                #if element is found in the tree call get_type 
                #function, to find the type of argument for descriptions
                if element.get("ident") == find_ident:
                    return self.get_type(element), element
                for child in element:
                    if child.get("ident") == find_ident:
                        return self.get_type(child), child
            logging.info("TO-DO: Find again")
            self.get_id(self.current_root, find_ident)
        except Exception as e:
            logging.error(e)
            logging.debug("[*] Issue in resolving: %s", find_ident)

    def get_type(self, child):
        """
        Fetch type of an element
        :return:
        """

        try:
            #for structures: need to define each element present in struct (build_struct)
            if child.get("type") == "struct":
                logging.debug("TO-DO: struct")
                return self.build_struct(child)
            #for unions: need to define each element present in union (build_union)
            elif child.get("type") == "union":
                logging.debug("TO-DO: union")
                return self.build_union(child)
            #for functions
            elif child.get("type") == "function":
                logging.debug("TO-DO: function")
                return
            #for pointers: need to define the pointer type and its direction (build_ptr)
            elif child.get("type") == "pointer":
                logging.debug("TO-DO: pointer")
                return self.build_ptr(child)
            #for arrays, need to define type of elements in array and size of array (if defined)
            elif child.get("type") == "array":
                logging.debug("TO-DO: array")
                desc_str = "array"
                if "base-type-builtin" in child.attrib.keys():
                    type_str = type_dict[child.get('base-type-builtin')]
                else:
                    root = self.resolve_id(self.current_root, child.get("base-type"))
                    type_str = self.get_type(root)
                size_str = child.get('array-size')
                desc_str += "[" + type_str + ", " + size_str + "]"
                return desc_str
            #for enums: predict flag for enums (build_enums)
            elif child.get("type") == "enum":
                logging.debug("TO-DO: enum")
                desc_str = "flags["
                desc_str += child.get("ident")+"_flags]"
                return self.build_enums(child)
            #for nodes: 
            #builtin types 
            elif "base-type-builtin" in child.keys():
                return type_dict.get(child.get("base-type-builtin"))            
            #custom type
            else:
                logging.debug("TO-DO: base-type")
                root = self.resolve_id(self.current_root, child.get("base-type"))
                return self.get_type(root)
        except Exception as e:
            logging.error(e)
            logging.debug("Error occured while fetching the type")

    def instruct_flags(self, strct_name, name, strt_line, end_line, flg_type):
        try:
            flg_name = name + "_flag"
            file_name = self.current_file + ".i"
            if flg_name in self.gflags:
                flg_name = name + "_" + strct_name + "_flag" 
            flags = None
            for i in range(len(self.flag_descriptions[file_name])):
                flag_tups = self.flag_descriptions[file_name][i]
                if (int(flag_tups[1])>strt_line-1 and int(flag_tups[2])< end_line-1):
                    logging.debug("[*] Found instruct flags")
                    del self.flag_descriptions[file_name][i]
                    flags = flag_tups[0]
                    break
            if flags is not None:
                self.gflags[flg_name] = ", ".join(flags)
                ret_str = "flags["+flg_name + ", " + flg_type + "]"
            else:
                ret_str = None               
            return ret_str
        except Exception as e:
            logging.error(e)
            logging.debug("Error in grabbing flags")
    
    '''def possible_flags(self, strct_name, elements=None):
        """function to find possible categories of leftover flags
        """
        small_flag = []
        len_sub = []
        possible_flags = []
        file = self.current_file + ".i"
        for i in range(len(self.flag_descriptions[file])):
            flags = self.flag_descriptions[file][i][0]
            small_flag.extend([i.lower() for i in flags])
            len_sub.extend(pylcs.lcs_of_list(strct_name, small_flag))
            for substring in strct_name.split("_"):
                print("substring: " + substring)
                for j in range(len(small_flag)):
                    if substring in small_flag[j]:
                        possible_flags.extend(self.flag_descriptions[file][i][0])
            max_len = max(len_sub)
            for k in possible_flags:
                if len(k)==max_len:
                    print(k)

        print("-"*50)
        return
        #except Exception as e:
         #   logging.error(e)
          #  print("Error in searching for potential flags for" + strct_name)
    
    def possible_flags(self, strct_name):
        small_flag = []
        file = self.current_file + ".i"
        for i in range(len(self.flag_descriptions[file])):
            flags = self.flag_descriptions[file][i][0]
            small_flag.extend([i.lower() for i in flags])
        res = process.extract(strct_name, small_flag)
        logging.info("Result for " + strct_name + ": " + str(res))'''


    def find_flags(self, name, elements, start, end):
        """Predict flags present near a struct"""
        try:
            end+=1            
            logging.debug("[+] Finding flags in vicinity of " + name )
            last_tup=len(self.flag_descriptions[self.current_file+ ".i"])
            '''max_start = 0
            min_end = 1000000000
            flags = []
            for child in self.current_root:
                #child_start = int(child.get("start-line"))
                child_end = int(child.get("start-line"))
                if (child_start < start) and (child_start > max_start):
                    max_start = child.get("start-line")
                if (child_end > end) and (child_end < min_end):
                    min_end = child.get("end-line")'''
            while(1):
                for i in range(len(self.flag_descriptions[self.current_file+ ".i"])):
                    flags_tup = self.flag_descriptions[self.current_file+ ".i"][i]
                    if flags_tup[1]>end:
                        break
                    if flags_tup[1] == end:
                        if any(substring in flg.lower() for flg in flags_tup[0] for substring in name.split("_")[1:]):
                            print("\033[31;1m[ ** ] Found flags in vicinity\033[m of " + name + ": " + str(flags_tup[0]))
                            if (self.append_flag()):
                                self.add_flag(flags_tup[0], name)
                            return
                        else:
                            for element in elements:
                                if any(element in flg.lower() for flg in flags_tup[0]):
                                    print("\033[31;1m[ ** ] Found flags in vicinity\033[m of " + name + " for " + element + ": " + str(flags_tup[0]))
                                    if (self.append_flag()):
                                        self.add_flag(flags_tup[0], name, element)
                                    return
                if end>self.flag_descriptions[self.current_file+ ".i"][last_tup-1][1]:
                    logging.debug("No flag found")
                    return
                else:
                    end+=1
        except Exception as e:
            logging.error(e)
            logging.debug("Error in finding flags present near struct " + name)
    
    def append_flag(self):
        try:
            if (input("Add the predicted flags? (y/n): ") == "y"):
                return True
            return False
        except Exception as e:
            logging.error(e)
            logging.debug("Error in function: append_flag")

    def add_flag(self, flags, strct_name, element = None):
        try:
            if element is None:
                element = input("Enter the element name from " + strct_name + " to modify: ")
            flag_name = element + "_" + strct_name + "_flag"
            self.gflags[flag_name] = ", ".join(flags)
            if strct_name in self.structs_defs.keys():
                flag_type = self.structs_defs[strct_name][1][element]
                self.structs_defs[strct_name][1][element] = "flags["+flag_name + ", " + flag_type + "]"
                logging.info("New flag type added: " + self.structs_defs[strct_name][1][element])
            elif strct_name in self.union_defs.keys():
                flag_type = self.union_defs[strct_name][1][element]
                self.union_defs[strct_name][1][element] = "flags["+flag_name + ", " + flag_type + "]"
                logging.info("New flag type added: " + self.union_defs[strct_name][1][element])
        except Exception as e:
            logging.error(e)
            logging.debug("Error in function: add_flag")

    def build_enums(self, child):
        try:
            name = child.get("ident")
            if name:
                desc_str = "flags[" + name + "_flags]"
                flags_undefined.append(desc_str)
            return desc_str
        except Exception as e:
            logging.error(e)
            logging.debug("Error occured while resolving enum")

    def build_ptr(self, child):
        """
        Build pointer
        :return: 
        """

        try:
            logging.debug("[*] Building pointer")
            name = child.get("ident")
            #pointer is a builtin type
            if "base-type-builtin" in child.attrib.keys():
                base_type = child.get("base-type-builtin")
                
                #check if pointer is buffer type i.e stores char type value
                if base_type =="void" or base_type == "char":
                    ptr_str = "buffer[" + self.ptr_dir + "]"

                else:
                    ptr_str = "ptr[" + self.ptr_dir + ", " + str(type_dict[child.get("base-type-builtin")]) + "]"
            #pointer is of custom type, call get_type function
            else:
                x = self.get_type(self.resolve_id(self.current_root,child.get("base-type")))
                ptr_str = "ptr[" + self.ptr_dir + ", " + x + "]"
            return ptr_str
        except Exception as e:
            logging.error(e)
            logging.debug("Error occured while resolving pointer")

    def build_struct(self, child):
        """
        Build struct
        :return: Struct identifier
        """

        try:
            #regex to check if name of element contains 'len' keyword
            len_regx = re.compile("(.+)len") 
            name = child.get("ident")
            if name not in self.structs_defs.keys():
                logging.debug("[*] Building struct " + name + ", id: " + str(child.get("id")))
                self.structs_defs[name] = []
                elements = {}
                prev_elem_name = "nill"
                strct_strt = int(child.get("start-line"))
                strct_end = int(child.get("end-line"))
                end_line = strct_strt
                prev_elem_type = "None"
                #get the type of each element in struct
                for element in child:
                    elem_type = self.get_type(element)
                    start_line = int(element.get("start-line"))
                    #check for flags defined in struct's scope,
                    #possibility of flags only when prev_elem_type has 'int' keyword 
                    if ((start_line - end_line) > 1) and ("int" in prev_elem_type):
                        enum_name = self.instruct_flags(name, prev_elem_name, end_line, start_line, prev_elem_type)
                        if enum_name is not None:
                            elements[prev_elem_name]= enum_name
                    end_line = int(element.get("end-line"))
                    curr_name = element.get("ident")
                    elements[curr_name] = str(elem_type)
                    prev_elem_name = curr_name
                    prev_elem_type = elem_type
                if (strct_end - start_line) > 1:
                    enum_name = self.instruct_flags(name, prev_elem_name, start_line, strct_end, elem_type)
                    if enum_name is not None:
                        elements[prev_elem_name] = enum_name

                #check for the elements which store length of an array or buffer
                for element in elements:
                    len_grp = len_regx.match(element)
                    if len_grp is not None:
                        buf_name = len_grp.groups()[0]
                        matches = [search_str for search_str in elements if re.search(buf_name, search_str)] 
                        for i in matches:
                            if i is not element:
                                if elements[element] in type_dict.values():
                                    elem_type = "len[" + i + ", " + elements[element] + "]"
                                elif "flags" in elements[element]:
                                    basic_type = elements[element].split(",")[-1][:-1].strip()
                                    elem_type = "len[" + i + ", " + basic_type + "]"
                                else:
                                    logging.debug("len type unhandled")
                                    elem_type = "None"
                                elements[element] = elem_type
                #format the struct according to syzlang
                element_str = ""
                for element in elements: 
                    element_str += element + "\t" + elements[element] + "\n"
                self.structs_defs[name] = [child, elements]
            return str(name)
        except Exception as e:
            logging.error(e)
            logging.debug("Error occured while resolving the struct: " + name)

    def build_union(self, child):
        """
        Build union
        :return: Union identifier
        """

        try:
            #regex to check if name of element contains 'len' keyword
            len_regx = re.compile("(.+)len")
            name = child.get("ident")
            if name not in self.union_defs.keys():
                logging.debug("[*] Building union " + name)
                elements = {}
                prev_elem_name = "nill"
                strct_strt = int(child.get("start-line"))
                strct_end = int(child.get("end-line"))
                end_line = strct_strt
                prev_elem_type = "None"
                #get the type of each element in union
                for element in child:
                    elem_type = self.get_type(element)
                    start_line = int(element.get("start-line"))
                    #check for flags defined in union's scope
                    if ((start_line - end_line) > 1) and ("int" in prev_elem_type):                       
                        enum_name = self.instruct_flags(name, prev_elem_name, end_line, start_line, prev_elem_type)
                        if enum_name is not None:
                            elements[prev_elem_name]= enum_name
                    end_line = int(element.get("end-line"))
                    curr_name = element.get("ident")
                    elements[curr_name] = str(elem_type)
                    prev_elem_name = curr_name
                    prev_elem_type = elem_type

                if (strct_end - start_line) > 1:
                    enum_name = self.instruct_flags(name, prev_elem_name, start_line, strct_end, elem_type)
                    if enum_name is not None:
                        elements[prev_elem_name] = enum_name
                
                #check for the elements which store length of an array or buffer
                for element in elements:
                    len_grp = len_regx.match(element)
                    if len_grp is not None:
                        buf_name = len_grp.groups()[0]
                        matches = [search_str for search_str in elements if re.search(buf_name, search_str)] 
                        for i in matches:
                            if i is not element:
                                elem_type = "len[" + i + ", " + elements[element] + "]"
                                elements[element] = elem_type

                #format union
                element_str = ""
                for element in elements: 
                    element_str += element + "\t" + elements[element] + "\n"
                self.union_defs[name] = [child, elements]
            return str(name)
        except Exception as e:
            logging.error(e)
            logging.debug("Error occured while resolving the union")


    def pretty_structs_unions(self):
        """
        Generates descriptions of structs and unions for syzkaller
        :return:
        """

        try:
            logging.info("Pretty printing structs and unions ")
            pretty = ""

            for key in self.structs_defs:
                element_str = ""                
                node = self.structs_defs[key][0]
                element_names = self.structs_defs[key][1].keys()                
                strct_strt = int(node.get("start-line"))
                strct_end = int(node.get("end-line"))
                #get flags in vicinity of structs
                self.find_flags(key, element_names, strct_strt, strct_end)
                #predictions for uncategorised flags
                self.possible_flags(key)
                for element in self.structs_defs[key][1]: 
                    element_str += element + "\t" + self.structs_defs[key][1][element] + "\n" 
                elements = " {\n" + element_str + "\n}"
                pretty += (str(key) + str(elements) + "\n")
            for key in self.union_defs:
                node = self.union_defs[key][0]
                element_names = self.union_defs[key][1].keys()                
                union_strt = int(node.get("start-line"))
                union_end = int(node.get("end-line"))
                #get flags in vicinity of structs
                self.find_flags(key, element_names, union_strt, union_end)
                #predictions for uncategorised flags
                #self.possible_flags(key)
                for element in self.union_defs[key][1]:
                    element_str += element + "\t" + self.union_defs[key][1][element] + "\n"
                elements = " [\n" + element_str + "\n]"
                pretty += (str(key) + str(elements) + "\n")
            return pretty
        except Exception as e:
            logging.error(e)
            logging.debug("[*] Error in parsing structs and unions")


    def pretty_ioctl(self, fd):
        """
        Generates descriptions for ioctl calls
        :return:
        """

        try:
            logging.info("Pretty printing ioctl descriptions")
            descriptions = ""
            if self.arguments is not None:
                for key in self.arguments:
                    desc_str = "ioctl$" + key + "("
                    fd_ = "fd " + fd
                    cmd = "cmd const[" + key + "]"
                    arg = ""
                    if self.arguments[key] is not None:
                        arg = "arg " + str(self.arguments[key])
                        desc_str += ", ".join([fd_, cmd, arg])
                    else:
                        desc_str += ", ".join([fd_, cmd])
                    desc_str += ")\n"
                    descriptions += desc_str
            return descriptions
        except Exception as e:
            logging.error(e)
            logging.debug("[*] Error in parsing ioctl command descriptions")

    def make_file(self, header_files):
        """
        Generates a device specific file with descriptions of ioctl calls
        :return: Path of output file
        """

        try:
            includes = ""
            flags_defn = ""
            for file in header_files:
                includes += "include <" + file + ">\n"
            dev_name = self.target.split("/")[-3]
            fd_str = "fd_" + dev_name
            rsrc = "resource " + fd_str + "[fd]\n"
            open_desc = "syz_open_dev$" + dev_name.upper()
            open_desc += "(dev ptr[in, string[\"/dev/" + dev_name + "\"]], "
            open_desc += "id intptr, flags flags[open_flags]) fd_" + dev_name + "\n"
            func_descriptions = str(self.pretty_ioctl(fd_str))
            struct_descriptions = str(self.pretty_structs_unions())
            for flg_name in self.gflags:
                flags_defn += flg_name + " = " + self.gflags[flg_name] + "\n"

            if func_descriptions is not None:
                desc_buf = "#Autogenerated by sys2syz\n"
                desc_buf += "\n".join([includes, rsrc, open_desc, func_descriptions, struct_descriptions, flags_defn])
                output_file_path = os.getcwd() + "/out/" + "dev_" + dev_name + ".txt"
                output_file = open( output_file_path, "w")
                output_file.write(desc_buf)
                output_file.close()
                return output_file_path
            else:
                return None
        except Exception as e:
            logging.error(e)
            logging.debug("[*] Error in making device file")

    def run(self, extracted_file):
        """
        Parses arguments and structures for ioctl calls
        :return: True
        """

        try:
            with open(extracted_file) as ioctl_commands:
                commands = ioctl_commands.readlines()
                for command in commands:
                    parsed_command = list(command.split(", "))
                    self.ptr_dir, cmd, argument = parsed_command

                    #for ioctl type is: IOR_, IOW_, IOWR_
                    if self.ptr_dir != "null":

                        #Get the type of argument
                        argument_def = argument.split(" ")[-1].strip()

                        #when argument is of general type as defined in type_dict
                        logging.debug("Generating descriptions for " + cmd + ", args: " + argument_def)
                        
                        #if argument_name is an array
                        if "[" in argument_def:
                            argument_def = argument_def.split("[")
                            argument_name = argument_def[0]
                        else:
                            argument_name = argument_def

                        if argument_name in type_dict.keys():
                            self.arguments[cmd] = type_dict.get(argument_name)
                        else:
                            raw_arg = self.get_id(self.get_root(argument_name), argument_name)
                            if raw_arg is not None:
                                if type(argument_def) == list:
                                    arg_str = "array[" + raw_arg[0] + ", " + argument_def[1].split("]")[0] + "]"
                                else:
                                    #define argument description for the ioctl call
                                    arg_str = "ptr[" + self.ptr_dir + ", "+ raw_arg[0]+ "]"
                                self.arguments[cmd] = arg_str
                    #for IO_ ioctls as they don't have any arguments
                    else:
                        self.arguments[cmd] = None
            return True
        except Exception as e:
            logging.error(e)
            logging.debug("Error while generating call descriptions")
