# Module : Description.py 
# Description : Contains functions which generate descriptions.
import shelve
import sys

from core.utils import *
from core.logger import get_logger

from os.path import join
from fuzzywuzzy import fuzz, process
import xml.etree.ElementTree as ET
import re
import os
import string
import clang.cindex as cindex
import sys

type_dict = {
    'bool': 'bool8',
    'char': 'int8',
    'signed char': 'int8',
    'unsigned char': 'int8',
    'short': 'int16',
    'short int': 'int16',
    'signed short': 'int16',
    'signed short int': 'int16',
    'unsigned short': 'int16',
    'unsigned short int': 'int16',
    'int': 'int32',
    'signed': 'int32',
    'signed int': 'int32',
    'unsigned': 'int32',
    'unsigned int': 'int32',
    'uint32_t': 'int32',
    'long': 'intptr',
    'long int': 'intptr',
    'signed long': 'intptr',
    'signed long int': 'intptr',
    'unsigned long': 'intptr',
    'unsigned long int': 'intptr',
    'long long': 'int64',
    'long long int': 'int64',
    'signed long long': 'int64',
    'signed long long int': 'int64',
    'unsigned long long': 'int64',
    'unsigned long long int': 'int64',
    'void': 'void',
    '__u64': 'int64',
    '__u32': 'int32'
}


class Descriptions(object):
    def __init__(self, sysobj):
        self.sysobj = sysobj
        self.target = sysobj.target

        self.logger = get_logger("Descriptions", sysobj.log_level)

        self.gflags = {}
        self.structs_defs = {}
        self.union_defs = {}
        self.arguments = {}
        self.ptr_dir = None
        self.header_files = []
        self.current_root = None
        self.current_file = None
        self.functions = {}
        self.trees = {}
        if self.sysobj.input_type == "ioctl":
            self.ioctls = sysobj.ioctls
            self.flag_descriptions = sysobj.macro_details

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
                        self.logger.debug("[*] Found Root ")
                        self.current_root = root
                        self.current_file = self.trees[tree].split(".")[0]
                        return root
        except Exception as e:
            self.logger.error(e)
            self.logger.warning('[*] Unable to find root')

    def resolve_id(self, root, find_id=None):
        """
        Find node having id value same as <find_id>, used for finding ident parameter for elements
        :return: node
        """

        try:
            # adding this case because build_function calls resolve_id without find_id argument
            if find_id is None:
                self.logger.warning("[!] find_id is NULL, hence returning None")
                return None
            for element in root:
                if element.get("id") == find_id:
                    return element
                for child in element:
                    if child.get("id") == find_id:
                        return child
        except Exception as e:
            self.logger.error(e)
            self.logger.warning("[!] Issue in resolving: %s", find_id)

    def get_id(self, root, find_ident):
        """
        Find node having ident value same as find_ident
        :return: 
        """

        try:
            if root is None:
                self.logger.warning("[!] get_id() -> Root is NULL, hence returning NULL")
                return None
            for element in root:
                # if element is found in the tree call get_type
                # function, to find the type of argument for descriptions
                if element.get("ident") == find_ident:
                    self.logger.debug("- Generating description for " + find_ident)
                    generatedType = self.get_type(element), element
                    # print the generatedType as a str
                    print(str(generatedType))
                    return generatedType
                for child in element:
                    if child.get("ident") == find_ident:
                        self.logger.debug("- Generating description for child" + find_ident)
                        return self.get_type(child), child
            self.logger.debug("TO-DO: Find again")
            self.get_id(self.current_root, find_ident)
        except Exception as e:
            self.logger.error(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            self.logger.warning("[!] Issue in resolving: %s", find_ident)

    def get_type(self, child, default_name=None):
        """
        Fetch type of an element
        :return:
        """
        if default_name == "default_name":
            return "int64"
        try:
            # for structures: need to define each element present in struct (build_struct)
            if child.get("type") == "struct":
                self.logger.debug("TO-DO: struct")
                return self.build_struct(child, default_name)
            # for unions: need to define each element present in union (build_union)
            elif child.get("type") == "union":
                self.logger.debug("TO-DO: union")
                return self.build_union(child, default_name)
            # for functions
            elif child.get("type") == "function":
                self.logger.debug("TO-DO: function")
                return self.build_function(child, default_name)
            # for pointers: need to define the pointer type and its direction (build_ptr)
            elif child.get("type") == "pointer":
                self.logger.debug("TO-DO: pointer")
                return self.build_ptr(child, default_name)
            # for arrays, need to define type of elements in array and size of array (if defined)
            elif child.get("type") == "array":
                self.logger.debug("TO-DO: array")
                desc_str = "array"
                if "base-type-builtin" in child.attrib.keys():
                    try:
                        type_str = type_dict[child.get('base-type-builtin')]
                    except KeyError:
                        type_str = "intptr"  # TODO: change this to intptr
                else:
                    root = self.resolve_id(self.current_root, child.get("base-type"))
                    type_str = self.get_type(root)
                size_str = child.get('array-size')
                # sometimes sizes may look like this unsigned long cpu_bitmap[]; in such cases
                # we return max array size
                if size_str is None:
                    size_str = "65536"
                desc_str += "[" + type_str + ", " + size_str + "]"
                return desc_str
            # for enums: predict flag for enums (build_enums)
            elif child.get("type") == "enum":
                self.logger.debug("TO-DO: enum")
                desc_str = "flags["
                desc_str += child.get("ident") + "_flags]"
                return self.build_enums(child)
            # for nodes:
            # builtin types
            elif "base-type-builtin" in child.keys():
                return type_dict.get(child.get("base-type-builtin"))
                # custom type
            else:
                self.logger.debug("TO-DO: base-type")
                root = self.resolve_id(self.current_root, child.get("base-type"))
                return self.get_type(root, default_name=default_name)
        except Exception as e:
            self.logger.error(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            self.logger.info("[!] Error occurred while fetching the type")
            if self.sysobj.os_type == 2:
                print("defaulting to int64")
                return "int64"

    def instruct_flags(self, strct_name, name, strt_line, end_line, flg_type):
        try:
            self.logger.debug("[*] Checking for instruct flags.")
            flg_name = name + "_flag"
            file_name = self.current_file + ".i"
            if flg_name in self.gflags:
                flg_name = name + "_" + strct_name + "_flag"
            flags = []
            if self.sysobj.input_type == "ioctl":
                for i in range(len(self.flag_descriptions[file_name])):
                    flag_tups = self.flag_descriptions[file_name][i]
                    if (int(flag_tups[1]) > strt_line - 1 and int(flag_tups[2]) < end_line - 1):
                        self.logger.debug("[*] Found instruct flags")
                        del self.flag_descriptions[file_name][i]
                        flags = flag_tups[0]
                        break
            else:
                cnt = 0
                total = int(end_line) - strt_line - 1
                for child in self.current_root:
                    if int(child.get("start-line")) in range(strt_line + 1, end_line):
                        cnt += 1
                        flags.append(child.get("ident"))
                    if cnt == total:
                        return
            if len(flags) > 0 and None not in flags:
                self.gflags[flg_name] = ", ".join(flags)
                ret_str = "flags[" + str(flg_name) + ", " + str(flg_type) + "]"
            else:
                ret_str = None
            return ret_str
        except Exception as e:
            self.logger.error(e)
            self.logger.warning("[!] Error in grabbing flags")

    def possible_flags(self, strct_name):
        """function to find possible categories of leftover flags
        """
        self.logger.debug("[*] Finding possible flags for " + strct_name)
        small_flag = []
        visited = []
        file = self.current_file + ".i"
        for i in range(len(self.flag_descriptions[file])):
            flags = self.flag_descriptions[file][i][0]
            small_flag.extend([i.lower() for i in flags])
        matches = [choice for (choice, score) in process.extract(strct_name, small_flag, scorer=fuzz.partial_ratio) if
                   (score >= 50)]
        self.logger.info("[+] Possible flags groups for " + strct_name + ": ")
        for match in matches:
            find_str = match.upper()
            for i in range(len(self.flag_descriptions[file])):
                if (find_str in self.flag_descriptions[file][i][0]):
                    if (self.flag_descriptions[file][i][0] not in visited):
                        visited.append(self.flag_descriptions[file][i][0])
                        self.logger.info("[XX]" + str(self.flag_descriptions[file][i][0]))
                    break
        self.logger.info("-------------------------")

    def find_flags(self, name, elements, start, end):
        """Find flags present near a struct"""
        try:
            self.logger.debug("[*] Finding flags in vicinity of " + name)
            file_name = self.current_file + ".i"
            last_tup = len(self.flag_descriptions[file_name])
            # for flags after the struct
            max_line_no = self.flag_descriptions[file_name][0][2]
            min_line_no = self.flag_descriptions[file_name][last_tup - 1][1]
            index = None
            for i in range(last_tup - 1, 0, -1):
                flags_tup = self.flag_descriptions[file_name][i]
                # find flags after the enf of struct, if start of flag tuple is < end of struct
                if flags_tup[1] < end:
                    if index == None:
                        break
                    min_tup = self.flag_descriptions[file_name][index]
                    print("\033[31;1m[ ** ] Found flags in vicinity\033[m of " + name + ": " + str(min_tup[0]))
                    if (self.append_flag()):
                        if (self.add_flag(min_tup[0], name)):
                            del self.flag_descriptions[file_name][index]
                    break
                elif (min_line_no > flags_tup[1]):
                    min_line_no = flags_tup[1]
                    index = i
            index = None
            for i in range(last_tup):
                flags_tup = self.flag_descriptions[file_name][i]
                # find flags present before start of struct, if end of flag tuple is > start of struct
                if flags_tup[2] > start:
                    if index == None:
                        break
                    max_tup = self.flag_descriptions[file_name][index]
                    print("\033[31;1m[ ** ] Found flags in vicinity\033[m of " + name + ": " + str(max_tup[0]))
                    if (self.append_flag()):
                        if (self.add_flag(max_tup[0], name)):
                            del self.flag_descriptions[file_name][index]
                    break
                elif (max_line_no < flags_tup[2]):
                    max_line_no = flags_tup[2]
                    index = i
            return
        except Exception as e:
            self.logger.error(e)
            self.logger.warning("[!] Error in finding flags present near struct " + name)

    def append_flag(self):
        try:
            if (input("Add the predicted flags? (y/n): ") == "y"):
                return True
            return False
        except Exception as e:
            self.logger.error(e)
            self.logger.warning("[!] Error in function: append_flag")

    def add_flag(self, flags, strct_name, element=None):
        try:
            if element is None:
                element = input("Enter the element name from " + strct_name + " to modify: ")
            flag_name = element + "_" + strct_name + "_flag"
            self.gflags[flag_name] = ", ".join(flags)
            if strct_name in self.structs_defs.keys():
                flag_type = self.structs_defs[strct_name][1][element]
                self.structs_defs[strct_name][1][element] = "flags[" + flag_name + ", " + flag_type + "]"
                self.logger.debug("[*] New flag type added: " + self.structs_defs[strct_name][1][element])
                return True
            elif strct_name in self.union_defs.keys():
                flag_type = self.union_defs[strct_name][1][element]
                self.union_defs[strct_name][1][element] = "flags[" + flag_name + ", " + flag_type + "]"
                self.logger.debug("[*] New flag type added: " + self.union_defs[strct_name][1][element])
                return True
        except Exception as e:
            self.logger.error(e)
            self.logger.warning("[!] Error in function: add_flag")

    def break_enum(self, name, start, end):
        total = (end - start) - 1
        cnt = 0
        for child in self.current_root:
            if int(child.get("start-line")) in range(start + 1, end):
                cnt += 1
                self.gflags[name].append(child.get("ident"))
            if cnt == total:
                return

    def build_enums(self, child):
        name = child.get("ident")
        self.logger.debug("[*] Building enum: " + name)
        if name:
            desc_str = "flags[" + name + "_flags, int8]"
            self.gflags[name + "_flags"] = []
        self.break_enum(name + "_flags", int(child.get("start-line")), int(child.get("end-line")))
        return desc_str

    def build_ptr(self, child, default_name=None):
        """
        Build pointer
        :return: 
        """

        try:
            self.logger.debug("[*] Building pointer")
            if self.sysobj.input_type == "syscall":
                self.ptr_dir = input("Enter pointer direction: ")
            # pointer is a builtin type
            if "base-type-builtin" in child.attrib.keys():
                base_type = child.get("base-type-builtin")

                # check if pointer is buffer type i.e stores char type value
                if base_type == "void" or base_type == "char":
                    ptr_str = "buffer[" + self.ptr_dir + "]"

                else:
                    ptr_str = "ptr[" + self.ptr_dir + ", " + str(type_dict[child.get("base-type-builtin")]) + "]"
            # pointer is of custom type, call get_type function
            else:
                if default_name is not None and child.get('ident') is None:
                    self.logger.debug("- Generating description for " + default_name)
                    x = self.get_type(self.resolve_id(self.current_root, child.get("base-type")), default_name)
                else:
                    x = self.get_type(self.resolve_id(self.current_root, child.get("base-type")))
                if x is None:
                    ptr_str = "ptr[" + self.ptr_dir + ", " + "int64" + "]"
                else:
                    ptr_str = "ptr[" + self.ptr_dir + ", " + x + "]"
            return ptr_str
        except Exception as e:
            self.logger.error(e)
            self.logger.warning("[!] Error occurred while resolving pointer")

    def build_function(self, child, default_name=None):
        """
        Build function
        """
        func_name = child.get('ident')
        if func_name is None:
            func_name = default_name
        self.logger.debug("[*] Building function " + func_name)
        func_args = {}
        func_ret = None
        for i, arg in enumerate(child):
            arg_name = arg.get('ident')
            if arg_name is None:
                arg_name = 'arg' + str(i)
            self.logger.debug("- Generating description for " + arg_name)
            func_args[arg_name] = self.get_type(arg, arg_name)

        if child.get('base-type-builtin') == None:
            resolved_id = self.resolve_id(child.get('base-type'))
            if resolved_id is not None:
                func_ret = self.get_type(resolved_id)
            else:
                # return void if no return type is specified
                func_ret = "void*"
        '''else:
            base_type = type_dict.get(child.get("base-type-builtin")))
            if "int" not in base_type or "void" not in base_type:
                func_str +=  base_type'''
        self.functions[func_name] = [func_args, func_ret]
        return func_name

    def checkname(name):
        return "res" if name == "resource" else name

    def build_struct(self, child, default_name="Deafult"):
        """
        Build struct
        :return: Struct identifier
        """

        global start_line
        try:
            # regex to check if name of element contains 'len' keyword
            len_regx = re.compile("(.+)len")
            name = child.get("ident")
            if name is None:
                name = default_name
            if name not in self.structs_defs.keys():
                self.logger.warning("[*] Building struct: " + name)
                self.structs_defs[name] = []
                elements = {}
                prev_elem_name = "nill"
                if child.get("start-line") is None:
                    self.logger.warning("[!] This Struct has NO Definition: " + name)
                    return
                strct_strt = int(child.get("start-line"))
                if child.get("end-line") is None:
                    self.logger.warning("[!] This Struct has NO Definition: " + name)
                    return
                strct_end = int(child.get("end-line"))
                end_line = strct_strt
                prev_elem_type = "None"
                # get the type of each element in struct
                for element in child:
                    curr_name = element.get("ident")
                    if curr_name is None:
                        curr_name = "default_name"
                        print("Name resolution failed for union element" + str(element))
                        elem_type = "int64"
                    else:
                        self.logger.warning("- Generating description for " + curr_name)
                        elem_type = self.get_type(element, curr_name)
                    print("RECEIVED ELEMENT TYPE: " + str(elem_type) + " FOR ELEMENT: " + str(curr_name))
                    if element.get("start-line") is None:
                        # set element to be builtin base type
                        self.logger.warning("[!] This Struct has NO Definition: " + curr_name)
                        elem_type = type_dict[element.get("base-type-builtin")]
                        start_line = end_line
                    else:
                        start_line = int(element.get("start-line"))
                        # check for flags defined in struct's scope,
                        # possibility of flags only when prev_elem_type has 'int' keyword
                        if ((start_line - end_line) > 1) and ("int" in str(prev_elem_type)):
                            enum_name = self.instruct_flags(name, prev_elem_name, end_line, start_line, prev_elem_type)
                            if enum_name is None:
                                self.logger.debug("- Generating description for " + curr_name)
                                elem_type = self.get_type(element, curr_name)
                            else:
                                elements[prev_elem_name] = enum_name
                        end_line = int(element.get("end-line"))
                    if str(elem_type) == "None":
                        elem_type = "int64"
                    elements[curr_name] = str(elem_type)
                    prev_elem_name = curr_name
                    prev_elem_type = elem_type

                if (strct_end - start_line) > 1:
                    enum_name = self.instruct_flags(name, prev_elem_name, start_line, strct_end, elem_type)
                    if enum_name is None:
                        self.logger.debug("- Generating description for " + curr_name)
                        elem_type = self.get_type(element, curr_name)
                    else:
                        elements[prev_elem_name] = enum_name
                # check for the elements which store length of an array or buffer
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
                                    self.logger.warning("[*] Len type unhandled")
                                    elem_type = "long"
                                elements[element] = elem_type
                self.structs_defs[name] = [child, elements]
            return str(name)
        except Exception as e:
            self.logger.error(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            self.logger.info("[!] Error occurred while resolving the struct: " + name)
            # in case of linux, this error can occur if the struct has not been found anywhere in the code
            # in this case, we will default to long
            # print os_type
            print("os_type is " + self.sysobj.os_type)
            if self.sysobj.os_type == 2:
                self.structs_defs[name] = None
                print("defaulting to long")
                return "long"

    def build_union(self, child, default_name="Default"):
        """
        Build union
        :return: Union identifier
        """
        # regex to check if name of element contains 'len' keyword
        try:
            len_regx = re.compile("(.+)len")
            name = child.get("ident")
            if name is None:
                name = default_name
            if name not in self.union_defs.keys():
                self.logger.warning("[*] Building union: " + name)
                elements = {}
                prev_elem_name = "nill"
                if child.get("start-line") is None:
                    self.logger.warning("[!] This UNION has NO Definition: " + name)
                    return
                strct_strt = int(child.get("start-line"))
                if child.get("end-line") is None:
                    self.logger.warning("[!] This UNION has NO Definition: " + name)
                    return
                strct_end = int(child.get("end-line"))
                end_line = strct_strt
                prev_elem_type = "None"
                # get the type of each element in union
                for element in child:
                    curr_name = element.get("ident")
                    if curr_name is None:
                        curr_name = "default_name"
                        print("Name resolution failed for union element" + str(element))
                        elem_type = "int64"
                    else:
                        self.logger.debug("- Generating description for " + curr_name)
                        elem_type = self.get_type(element, curr_name)
                    if element.get("start-line") is None:
                        # set element to be builtin base type
                        self.logger.warning("[!] This UNION has NO Definition: " + curr_name)
                        elem_type = type_dict[element.get("base-type-builtin")]
                        start_line = end_line
                    else:
                        start_line = int(element.get("start-line"))
                        # check for flags defined in union's scope
                        if ((start_line - end_line) > 1) and ("int" in prev_elem_type):
                            enum_name = self.instruct_flags(name, prev_elem_name, end_line, start_line, prev_elem_type)
                            if enum_name is None:
                                self.logger.debug("- Generating description for " + curr_name)
                                elem_type = self.get_type(element, curr_name)
                            else:
                                elements[prev_elem_name] = enum_name
                        end_line = int(element.get("end-line"))
                        elements[curr_name] = str(elem_type)
                        prev_elem_name = curr_name
                        prev_elem_type = elem_type

                    if (strct_end - start_line) > 1:
                        enum_name = self.instruct_flags(name, prev_elem_name, start_line, strct_end, elem_type)
                        if enum_name is None:
                            self.logger.debug("- Generating description for " + curr_name)
                            elem_type = self.get_type(element, curr_name)
                        else:
                            elements[prev_elem_name] = enum_name
                    # check for the elements which store length of an array or buffer
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
                                    self.logger.warning("[*] Len type unhandled")
                                    elem_type = "None"
                                elements[element] = elem_type
                self.union_defs[name] = [child, elements]
            return str(name)
        except Exception as e:
            self.logger.error(e)
            self.logger.warning("[!] Error occurred while resolving the union: " + name)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            # in case of linux, this error can occur if the struct has not been found anywhere in the code
            # in this case, we will default to long
            # print os_type
            if self.sysobj.os_type == 2:
                self.structs_defs[name] = None
                print("defaulting to long")
                return "long"

    def pretty_func(self):
        func_str = ""
        for func in self.functions.keys():
            func_str += func + "("
            func_str += ", ".join([self.checkname(name) + " " + str(desc) for name, desc in
                                   zip(self.functions[func][0].keys(), self.functions[func][0].values())]) + ") "
            if self.functions[func][1] is not None:
                func_str += str(self.functions[func][0])
            func_str += "\n"
        return func_str

    def pretty_structs_unions(self):
        """
        Generates descriptions of structs and unions for syzkaller
        :return:
        """

        self.logger.debug("[*] Pretty printing structs and unions ")
        pretty = ""
        for key in self.structs_defs:
            element_str = ""
            if self.structs_defs[key] is None or len(self.structs_defs[key]) < 2:
                print("key with the name " + key + " not found")
                continue
            node = self.structs_defs[key][0]
            element_names = self.structs_defs[key][1].keys()
            strct_strt = int(node.get("start-line"))
            strct_end = int(node.get("end-line"))
            # get flags in vicinity of structs for ioctls
            if self.sysobj.input_type == "ioctl":
                self.find_flags(key, element_names, strct_strt, strct_end)
                # predictions fopossible_flagsr uncategorised flags
                self.possible_flags(key)
            for element in self.structs_defs[key][1]:
                element_str += "\t" + element + "\t" + self.structs_defs[key][1][element] + "\n"
            elements = " {\n" + element_str + "}\n"
            pretty += (str(key) + str(elements) + "\n")
        for key in self.union_defs:
            element_str = ""
            node = self.union_defs[key][0]
            element_names = self.union_defs[key][1].keys()
            union_strt = int(node.get("start-line"))
            union_end = int(node.get("end-line"))
            # get flags in vicinity of unions for ioctls
            if self.sysobj.input_type == "ioctl":
                self.find_flags(key, element_names, union_strt, union_end)
                # predictions for uncategorised flags
                self.possible_flags(key)
            for element in self.union_defs[key][1]:
                element_str += "\t" + element + "\t" + self.union_defs[key][1][element] + "\n"
            elements = " [\n" + element_str + "]\n"
            pretty += (str(key) + str(elements) + "\n")
        return pretty

    def pretty_ioctl(self, fd):
        """
        Generates descriptions for ioctl calls
        :return:
        """

        try:
            self.logger.debug("[*] Pretty printing ioctl descriptions")
            descriptions = ""
            if self.arguments is not None:
                for key in self.arguments:
                    desc_str = "ioctl$" + key + "("
                    fd_ = "fd " + fd.replace("-", "_")
                    cmd = "cmd const[" + key + "]"
                    arg = ""
                    if self.arguments[key] is not None and str(self.arguments[key]) != "":
                        arg = "arg " + str(self.arguments[key])
                        desc_str += ", ".join([fd_, cmd, arg])
                    else:
                        desc_str += ", ".join([fd_, cmd])
                    desc_str += ")\n"
                    descriptions += desc_str
            return descriptions
        except Exception as e:
            self.logger.error(e)
            self.logger.warning("[!] Error in parsing ioctl command descriptions")

    def make_file(self):
        """
        Generates a device specific file with descriptions of ioctl calls
        :return: Path of output file
        """

        self.logger.debug("[*] Generating description file")
        includes = ""
        include_path = "dev/" + os.path.basename(self.sysobj.target) + "/"
        flags_defn = ""
        for h_file in set(self.header_files):
            includes += "include <" + include_path + h_file + ">\n"
        dev_name = self.target.split("/")[-1]
        fd_str = "fd_" + dev_name
        rsrc = "resource " + fd_str.replace("-", "_") + "[fd]\n"
        open_desc = "openat$" + dev_name.lower().replace("-", "_")
        open_desc += "(fd const[AT_FDCWD], file ptr[in, string[\"/dev/" + dev_name.replace("-", "_") + "\"]], "
        open_desc += "flags flags[open_flags], mode const[0]) fd_" + dev_name.replace("-", "_") + "\n"
        func_descriptions = str(self.pretty_ioctl(fd_str))
        struct_descriptions = str(self.pretty_structs_unions())
        for flg_name in self.gflags:
            # check if os is linux
            if self.sysobj.os == "linux":
                flags_defn += flg_name + " = " + str(self.gflags[flg_name]) + "\n"
            else:
                flags_defn += flg_name + " = " + ", ".join(self.gflags[flg_name]) + "\n"
        if func_descriptions is not None:
            desc_buf = "# Copyright 2018 syzkaller project authors. All rights reserved.\n# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.\n# Autogenerated by sys2syz\n\n"
            desc_buf += "\n".join(
                [includes, rsrc, open_desc, func_descriptions, self.pretty_func(), struct_descriptions, flags_defn])
            output_file_path = os.path.join(os.getcwd(), "out", self.sysobj.os, "dev_" + dev_name + ".txt")
            output_file = open(output_file_path, "w")
            output_file.write(desc_buf)
            output_file.close()
            return output_file_path
        else:
            return None

    def isFileAGoodCandidate(self, Intertingfile):
        """
        Checks if a file is a good candidate for parsing
        :param file: File to check
        :return: True if file is a good candidate, False otherwise
        """
        # remove .xml extension and append .c extension
        Intertingfile = Intertingfile[:-4] + ".c"
        # check if file exists
        try:
            for root, dirs, files in os.walk(self.target):
                for file in files:
                    if file.endswith(".c") and Intertingfile == file:
                        # open this file
                        with open(os.path.join(root, file), "r") as fd:
                            # read lines from file
                            lines = fd.readlines()
                            # check if lines contains "#include" and any of the ioctl calls
                            for line in lines:
                                if "#include" in line:
                                    for ioctl_header in self.sysobj.header_files:
                                        if ioctl_header in line:
                                            return True
        except IOError:
            self.logger.error("Unable to read the file '%s'", file)
            return False

    def FetchIoctlDescriptionsFromAST(self, IOCTL_CMD, IOCTL_NAME, PreprocessedFileDir):
        # iterate over all the files in the directory
        preprocessedFiles = []
        IoctlDefinitions = None
        for root, dirs, files in os.walk(PreprocessedFileDir):
            # fetch all the files ending with .i
            for file in files:
                if file.endswith(".i") and not file.startswith("."):
                    preprocessedFiles.append(file)
        IoctlDefinitions = None
        # iterate over all the files
        for file in preprocessedFiles:
            IoctlDefinitions = self.check_ioctl_switches(IOCTL_CMD=IOCTL_CMD, IOCTL_TRAP=IOCTL_NAME,
                                                         file_=os.path.join(PreprocessedFileDir, file))
            if IoctlDefinitions is not None:
                return IoctlDefinitions
        if IoctlDefinitions is None:
            return ""

    def ioctl_run(self):
        """
        Parses arguments and structures for ioctl calls
        :return: True
        """
        self.xml_dir = self.sysobj.out_dir
        # Find the xml file youre interested in
        for xml_file in (os.listdir(self.xml_dir)):
            if self.isFileAGoodCandidate(xml_file):
                tree = ET.parse(join(self.xml_dir, xml_file))
                self.trees[tree] = xml_file
        self.flag_descriptions = self.sysobj.macro_details
        self.ioctls = self.sysobj.ioctls
        for command in self.ioctls:
            parsed_command = str(command).split(", ")
            self.ptr_dir, cmd, h_file, argument, IOCTL_TRAP = parsed_command
            if argument == "None":
                # move one directory back
                preprocessDir = os.path.normpath(self.xml_dir + os.sep + os.pardir)
                definitionWithDirection = self.FetchIoctlDescriptionsFromAST(IOCTL_CMD=cmd,
                                                                             IOCTL_NAME=IOCTL_TRAP,
                                                                             PreprocessedFileDir=preprocessDir)

                # remove the direction from the definition
                if (definitionWithDirection is not None) and (definitionWithDirection != ""):

                    definition = definitionWithDirection.split(" ")[0]
                    direction = definitionWithDirection.split(" ")[1]
                    parsed_command[3] = definition
                    argument = definition
                    parsed_command[0] = direction
                    self.ptr_dir = direction
                else:
                    parsed_command[3] = ""
            self.header_files.append(h_file)
            # for ioctl type is: IOR_, IOW_, IOWR_
            if self.ptr_dir != "null":

                # Get the type of argument
                argument_def = argument.split(" ")[-1].strip()  # if argument is ", int )" --> this would return ""
                if argument_def == "":
                    argument_def = argument.strip()
                # when argument is of general type as defined in type_dict
                self.logger.info("[*] Generating descriptions for " + cmd + ", args: " + argument_def)
                # if argument_name is an array
                if "[" in argument_def:
                    argument_def = argument_def.split("[")
                    argument_name = argument_def[0]
                    argument_name = argument_name.strip()
                    if argument_name == "int":
                        argument_name = "long"
                elif "*" == argument_def:
                    if "void" in argument:
                        arg_str = "buf[" + self.ptr_dir + "]"
                        self.arguments[cmd] = arg_str
                        continue
                    else:
                        argument_name = argument.split(" ")[0]
                else:
                    argument_name = argument_def
                if argument_name in type_dict.keys():
                    self.arguments[cmd] = type_dict.get(argument_name)
                else:
                    raw_arg = self.get_id(self.get_root(argument_name), argument_name)
                    if raw_arg is not None:
                        ptr_def = raw_arg[0]
                        if type(argument_def) == list:
                            ptr_def = "array[" + raw_arg[0] + ", " + argument_def[1].split("]")[0] + "]"
                        if ptr_def is None:
                            self.logger.warning("[!] No argument for this command " + cmd)
                            arg_str = ""
                        else:
                            arg_str = "ptr[" + self.ptr_dir + ", " + ptr_def + "]"
                        self.arguments[cmd] = arg_str
                    else:
                        self.logger.warning("[!] Could not find arg definitions for " + cmd)
                        self.arguments[cmd] = ""
            # for IO_ ioctls as they don't have any arguments
            else:
                self.arguments[cmd] = None
        return True

    def find_macro_header(self, macro, linenum):
        include_regex = re.compile(r"#[0-9\s]*\"(.*).h\"")
        # find macro first
        i = linenum
        for i in range(linenum, -1, -1):
            if '#define ' + macro in self.curr_lines[i]:
                break
        if i == linenum:
            sys.exit(-1)  # fatal error - #define macro not found in .i file

        for j in range(i, -1, -1):
            robj = include_regex.match(self.curr_lines[j])
            if robj:
                return robj.group(1).strip("./") + '.h'
        return ""

    def find_func_cursor(self, root, name):
        ret = []
        if root.kind == cindex.CursorKind.FUNCTION_DECL and root.spelling == name:
            return root
        else:
            for child in root.get_children():
                if child.kind == cindex.CursorKind.FUNCTION_DECL and child.spelling == name:
                    ret.append(child)
        return ret

    def find_ioctl_case_cursor(self, root, Ioctl_trap_number):
        ret = []
        if root.kind == cindex.CursorKind.CASE_STMT:
            # get the integer literal value of the case statement
            for child in root.get_children():
                if child.kind == cindex.CursorKind.INTEGER_LITERAL and child.spelling == Ioctl_trap_number:
                    ret.append(child)
        return ret

    def get_cases(self, switchnode):
        caselines = []
        for child in switchnode.get_children():
            if child.kind == cindex.CursorKind.COMPOUND_STMT:
                for cases in child.get_children():
                    if cases.kind == cindex.CursorKind.CASE_STMT:
                        caselines.append(cases.location.line)
                break
        return caselines

    def find_switches(self, node, args):
        ''' Return (switch arg, case linenums)'''
        if node.kind == cindex.CursorKind.SWITCH_STMT:  # check if its switching based on arguments
            found = 0
            for child in node.get_children():
                if child.displayname in args:
                    found = 1
                    break
            if found == 0:
                return None
            else:
                return (child.displayname, self.get_cases(node))
        else:
            for child in node.get_children():
                ret = self.find_switches(child, args)
                if ret is not None:
                    return ret
        return None

    def recurse_functions(self, root, func, args):
        for child in func.get_children():
            if child.kind == cindex.CursorKind.CALL_EXPR:
                ret = self.check_switches(child.spelling, root, 1)
                if ret is not None and ret[0] in args:
                    return ret
            else:
                ret = self.recurse_functions(root, child, args)
                if ret is not None:
                    return ret
            return None

    def recurse_ioctl_functions_and_return_struct_type(self, func, IoctlArg):
        for child in func.get_children():
            if child.kind == cindex.CursorKind.CALL_EXPR:
                # the criteria to break out of recursion is in the function body of the call expression
                # there is either a "call_from_user" or a "call_to_user" function call
                if child.spelling == "call_from_user" or child.spelling == "call_to_user":
                    IoctlArg.append(child.spelling)
                    # fetch the arguments of this function call
                    for arg in child.get_children():
                        # look for a cast expression in the arguments
                        if arg.kind == cindex.CursorKind.CAST_EXPR:
                            # fetch the type of the cast expression
                            for cast in arg.get_children():
                                if cast.kind == cindex.CursorKind.TYPE_REF:
                                    # if the cast type is a pointer
                                    if cast.type.kind == cindex.TypeKind.POINTER:
                                        # fetch the type of the pointer
                                        for ptr in cast.get_children():
                                            if ptr.kind == cindex.CursorKind.TYPE_REF:
                                                # if the pointer type is a struct
                                                if ptr.type.kind == cindex.TypeKind.RECORD:
                                                    # fetch the name of the struct
                                                    for struct in ptr.get_children():
                                                        if struct.kind == cindex.CursorKind.STRUCT_DECL:
                                                            # return the name of the struct
                                                            IoctlArg.append(struct.spelling)
                                                            return IoctlArg

    def check_switches(self, name, root=None, depth=0):
        ''' Return (switch arg, (caselist, headerfile)
            Assumption - all case macros are defined in same header file
        '''

        if root is None:
            index = cindex.Index.create()
            tu = index.parse(self.current_file)
            root = tu.cursor

        func_cursor = self.find_func_cursor(root, name)
        if not func_cursor:
            return None  # probably an inbuilt function being called. Skip
        else:
            func_cursor = func_cursor[-1]

        func_args = [child.displayname for child in func_cursor.get_children() if
                     child.kind == cindex.CursorKind.PARM_DECL]
        switch_cases = self.find_switches(func_cursor, func_args)
        if switch_cases is None and depth == 0:
            # TO-DO : recursively find inside functions
            switch_cases = self.recurse_functions(root, func_cursor, func_args)
            return switch_cases
        elif switch_cases is None and depth == 1:
            return None

        fp = open(self.current_file, 'r')
        self.curr_lines = fp.readlines()

        case_regex = re.compile(r"[\s\t]*case[\s\t]*(.*):")
        caselines = switch_cases[1]
        cases = []
        for linenum in caselines:
            line = self.curr_lines[linenum - 1]
            cobj = case_regex.match(line)
            if cobj:
                cases.append(cobj.group(1))
            else:
                sys.exit(-1)  # fatal error - no case match in case statement
        header = self.find_macro_header(cases[0], caselines[0])
        return (switch_cases[0], (cases, header))

        '''
        startline = int(func.get("start-line"))

        possible_const = {}
        switch_regex = re.compile(r"[\s\t]*switch[\s\t]*\((.*)\)")
        case_regex = re.compile(r"[\s\t]*case[\s\t]*(.*):")
        funccall_regex = re.compile(r"[\s\t=]+([a-zA-Z0-9_]*)\((.*)\)")
        # find in this function itself
        cmd = ""
        scope_count = 0
        i = startline
        func_scope = False
        if '{' in self.curr_lines[i-1]:
            func_scope = True

        while(1):
            curr_line = self.curr_lines[i]
            if '{' in self.curr_lines[i] and func_scope == False:
                func_scope = True
            if '}' in self.curr_lines[i] and func_scope == True:
                func_scope_count = False
                break
            mobj = switch_regex.findall(self.curr_lines[i])
            if mobj and mobj[0] in [child.get("ident") for child in func]:
                cases = []
                if '{' in self.curr_lines[i]:
                    scope_count += 1
                i += 1
                while(1):
                    if '{' in self.curr_lines[i]:
                        scope_count += 1
                    if '}' in self.curr_lines[i]:
                        scope_count -= 1
                    if scope_count == 0:
                        break
                    cobj = case_regex.findall(self.curr_lines[i])
                    if cobj:
                        cases.append(cobj[0])

                    i += 1
                header = self.find_macro_header(cases[0], startline)
                fp.close()
                return (mobj[0], (cases,header))
            if depth == 0:
                fobj = funccall_regex.findall(self.curr_lines[i])
                if fobj:
                    args = [args.strip(" \t") for args in fobj[0][1].split(',')]
                    name = fobj[0][0]
                    next_func = None
                    for element in self.current_root:
                        if element.get("ident") == name:
                            next_func = self.resolve_id(self.current_root, element.get("base-type"))
                            break
                    if next_func is not None:
                        child_consts = self.check_switches(next_func, fp, 1)
                        # check if any returned constants are func's arguments
                        if child_consts is not None:
                            for child in func:
                                if child.get("ident") == child_consts[0]:
                                    fp.close()
                                    return child_consts

            i += 1
        fp.close()
        return None
        '''

    def traverse_and_find_trap_case(self, IOCTL_NAME, IOCTL_CMD, tu, _file):
        preOrderList = list(tu.cursor.walk_preorder())
        IoctlArg = []
        TargetCursorDecl = None
        for c in tu.cursor.walk_preorder():
            if c.location.file is None:
                pass
            elif c.location.file.name != _file:
                pass
            elif c.kind == cindex.CursorKind.CASE_STMT:
                # print the case statement
                # print the location of the case statement
                foundIOCTLCase = False
                for child in c.get_children():
                    # print the case statement
                    for token in child.get_tokens():
                        # print("LINE: " + str(token.spelling) + " " + str(token.location.line))
                        if IOCTL_NAME == str(token.spelling):
                            self.logger.info(
                                "[*] Found IOCTL [" + IOCTL_CMD + "] case Handler: " + str(token.spelling))
                            # iterate through extent until you find a call expression to a function
                            foundIOCTLCase = True
                        break
                    if foundIOCTLCase:
                        foundIOCTLCase = False
                        tokens = tu.get_tokens(extent=c.extent)
                        CalleeDeclRefs = []
                        for token in tokens:
                            if token.kind == cindex.TokenKind.IDENTIFIER and token.cursor.kind == cindex.CursorKind.DECL_REF_EXPR \
                                    and token.cursor.referenced.kind == cindex.CursorKind.FUNCTION_DECL:
                                # fetch the function name
                                FunctionName = str(token.spelling)
                                if FunctionName == "copy_from_user" or FunctionName == "copy_to_user":
                                    # we got it now
                                    self.logger.info("[*] Found IOCTL case KERNEL COPY STMT: " + str(FunctionName))
                                    for functionArg_token in tu.get_tokens(extent=token.cursor.referenced.extent):
                                        if functionArg_token.kind == cindex.TokenKind.IDENTIFIER \
                                                and functionArg_token.cursor.kind == cindex.CursorKind.PARM_DECL:
                                            print("Function arg is " + str(functionArg_token.spelling))
                                else:
                                    CalleeDeclRefs.append(token.cursor)
                        # now we have all the decl refs that are function decls
                        # lets iterate through them and fetch the function args
                        if len(CalleeDeclRefs) == 1:
                            TargetCursorDecl = self.findCursorToTargetFunction(IOCTL_CMD=IOCTL_CMD, tu=tu,
                                                                               functionDeclRef=CalleeDeclRefs[0],
                                                                               bfs=[])
                        elif len(CalleeDeclRefs) > 1:
                            TargetCursorDecl = self.findCursorToTargetFunction(IOCTL_CMD=IOCTL_CMD, tu=tu,
                                                                               functionDeclRef=CalleeDeclRefs[0],
                                                                               bfs=CalleeDeclRefs)

        if TargetCursorDecl is None:
            return ""
        else:
            return TargetCursorDecl

    def findCursorToTargetFunction(self, IOCTL_CMD, tu, functionDeclRef, bfs=[], depth=0):
        # if bfs is empty
        if len(bfs) == 0:
            # fetch function decl scope from the function decl ref
            scope = functionDeclRef.referenced.extent
            # fetch the tokens from the scope and append to bfs
            FoundCallExpression = False
            FoundCallArgBracket = False
            FunctionName = ""
            for token in tu.get_tokens(extent=scope):
                # all function declrefs would be tokens of interests
                # print token cursor kind
                if FoundCallExpression == False:
                    if token.kind == cindex.TokenKind.IDENTIFIER and token.cursor.kind == cindex.CursorKind.DECL_REF_EXPR \
                            and token.cursor.referenced.kind == cindex.CursorKind.FUNCTION_DECL:
                        if token.spelling == "copy_from_user" or token.spelling == "copy_to_user":
                            # we found it
                            self.logger.info(
                                "[*] Found IOCTL [" + IOCTL_CMD + "] case KERNEL COPY STMT: " + str(token.spelling))
                            FunctionName = token.spelling
                            if FunctionName == "copy_from_user":
                                Direction = "in"
                            elif FunctionName == "copy_to_user":
                                Direction = "out"
                            FoundCallExpression = True
                        else:
                            bfs.append(token.cursor)
                elif FoundCallArgBracket == False:
                    if Direction == "in":
                        if token.kind == cindex.TokenKind.PUNCTUATION and token.spelling == "(":  # first argument is the destination
                            FoundCallArgBracket = True
                    elif Direction == "out":
                        if token.kind == cindex.TokenKind.PUNCTUATION and token.spelling == ",":  # second argument is the destination
                            FoundCallArgBracket = True

                elif FoundCallArgBracket == True:
                    if token.kind == cindex.TokenKind.IDENTIFIER \
                            and token.cursor.kind == cindex.CursorKind.DECL_REF_EXPR:

                        ioctlArg = str(token.cursor.type.spelling)
                        if "struct" in ioctlArg:
                            ioctlArg = ioctlArg.split("struct")[1]
                        elif "union" in ioctlArg:
                            ioctlArg = ioctlArg.split("union")[1]
                        else:
                            #probably a typedef pointer
                            ioctlArg = ioctlArg.split("*")[0]

                        ioctlArg = ioctlArg.strip()
                        self.logger.info(
                            "[*] IOCTL [" + IOCTL_CMD + "] MARSHALL KS_US OBJ: " + str(ioctlArg))
                        return ioctlArg + " " + Direction

            # if bfs vector is not empty
            if len(bfs) > 0:
                while len(bfs) > 0:
                    # pop the first element
                    currentCursorDeclRef = bfs.pop(0)
                    currentCursor = currentCursorDeclRef.referenced
                    scope = currentCursor.referenced.extent
                    # fetch the tokens from the scope and append to bfs
                    FoundCallExpression = False
                    FoundCallArgBracket = False
                    FunctionName = ""
                    for token in tu.get_tokens(extent=scope):
                        # all function declrefs would be tokens of interests
                        # print token cursor kind
                        if FoundCallExpression == False:
                            if token.kind == cindex.TokenKind.IDENTIFIER \
                                    and token.cursor.kind == cindex.CursorKind.DECL_REF_EXPR \
                                    and token.cursor.referenced.kind == cindex.CursorKind.FUNCTION_DECL:
                                if token.spelling == "copy_from_user" or token.spelling == "copy_to_user":
                                    # we found it
                                    self.logger.critical(
                                        "[*] Found IOCTL [" + IOCTL_CMD + "] case KERNEL COPY STMT: " + str(
                                            token.spelling))
                                    FunctionName = token.spelling
                                    if FunctionName == "copy_from_user":
                                        Direction = "in"
                                    elif FunctionName == "copy_to_user":
                                        Direction = "out"
                                    FoundCallExpression = True
                                else:
                                    bfs.append(token.cursor)
                        elif FoundCallArgBracket == False:
                            if Direction == "in":
                                if token.kind == cindex.TokenKind.PUNCTUATION and token.spelling == "(":  # first argument is the destination
                                    FoundCallArgBracket = True
                            elif Direction == "out":
                                if token.kind == cindex.TokenKind.PUNCTUATION and token.spelling == ",":  # second argument is the destination
                                    FoundCallArgBracket = True
                        elif FoundCallArgBracket == True:
                            if token.kind == cindex.TokenKind.IDENTIFIER and token.cursor.kind == cindex.CursorKind.DECL_REF_EXPR:
                                ioctlArg = str(token.cursor.type.spelling)
                                if "struct" in ioctlArg:
                                    ioctlArg = ioctlArg.split("struct")[1]
                                ioctlArg = ioctlArg.strip()
                                self.logger.critical(
                                    "[*] IOCTL [" + IOCTL_CMD + "] MARSHALL KS_US OBJ: " + str(ioctlArg))
                                return ioctlArg + " " + Direction
            else:
                return None

    def check_ioctl_switches(self, IOCTL_CMD, IOCTL_TRAP, file_):
        ''' Return (ioctl Call Name, (argument direction, argument type))
            Assumption - all case macros are defined in same header file
        '''
        index = cindex.Index.create()
        tunit = index.parse(file_)
        root = tunit.cursor

        return self.traverse_and_find_trap_case(IOCTL_CMD=IOCTL_CMD, IOCTL_NAME=IOCTL_TRAP, tu=tunit, _file=file_)

    def syscall_run(self):
        """
        Parses arguments and structures for ioctl calls
        :return: True
        """
        syscall_args = {}
        self.xml_dir = self.sysobj.out_dir
        for xml_file in (os.listdir(self.xml_dir)):
            tree = ET.parse(join(self.xml_dir, xml_file))
            self.trees[tree] = xml_file
        args_name = self.target + "_args"
        syscall_root = self.get_root(args_name)
        for element in syscall_root:
            # if element is found in the tree call get_type
            # function, to find the type of argument for descriptions
            if element.get("ident") == args_name:
                for child in element:
                    self.logger.debug("- Function argument: " + child.get('ident'))
                    syscall_args[child.get('ident')] = self.get_syscall_arg(child.get('base-type'))
                break
        self.functions[self.target] = [syscall_args, None]
        flag_str = ""
        for flg_name in self.gflags:
            flag_str += flg_name + " = " + self.gflags[flg_name] + "\n"
        func_str = self.pretty_func()
        struct_union_str = self.pretty_structs_unions()
        print("--------------Description--------------\n")
        print("\n".join([func_str, struct_union_str, flag_str]))

    def get_syscall_arg(self, base_id):
        for element in self.resolve_id(self.current_root, base_id):
            if element.get('ident') == "le":
                element_base = self.resolve_id(self.current_root, element.get('base-type'))
                for child in element_base:
                    return self.get_type(child)
