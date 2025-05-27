#!/usr/bin/env python
# Copyright (c) 2015-2017 Vector 35 LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import idc
import idautils
import idaapi
import json

# Import for newer IDA versions
try:
    from ida_kernwin import ask_file
except ImportError:
    # For older versions, this won't work in IDA 9.1, so we'll use idaapi
    ask_file = None

DefaultSectionSemantics = 0
ReadOnlyCodeSectionSemantics = 1
ReadOnlyDataSectionSemantics = 2
ReadWriteDataSectionSemantics = 3


def get_file_dialog():
    """Get filename using available dialog method"""
    if ask_file:
        return ask_file(1, "*.json", "Export file name")
    else:
        # Use idaapi for newer versions
        return idaapi.ask_file(1, "*.json", "Export file name")


def linearize_comment(ea, function_comment=False):
    regular_comment = ""
    repeatable_comment = ""

    if function_comment:
        regular_comment = idc.get_func_cmt(ea, 0)
        repeatable_comment = idc.get_func_cmt(ea, 1)
    else:
        regular_comment = idc.get_cmt(ea, 0)
        repeatable_comment = idc.get_cmt(ea, 1)

    if regular_comment is None and repeatable_comment is None:
        return None
    elif regular_comment is not None and repeatable_comment is None:
        return regular_comment
    elif repeatable_comment is not None and regular_comment is None:
        return repeatable_comment
    else:
        if len(regular_comment) == 0:
            return repeatable_comment
        if len(repeatable_comment) == 0:
            return regular_comment
        return regular_comment + "\n" + repeatable_comment


def main(fileName):
    if fileName is None:
        return
    jsonValue = {}
    jsonValue["names"] = {}
    jsonValue["functions"] = {}
    jsonValue["segments"] = []
    jsonValue["strings"] = {}

    for addr, name in idautils.Names():
        jsonValue["names"][addr] = name

    # Record segment details
    for ea in idautils.Segments():
        cur_seg = {}
        seg = idaapi.getseg(ea)
        if seg:
            cur_seg["start"] = seg.start_ea
            cur_seg["end"] = seg.end_ea
            cur_seg["name"] = idaapi.get_segm_name(seg)
            cur_seg["r"] = (seg.perm & idaapi.SEGPERM_READ) != 0
            cur_seg["w"] = (seg.perm & idaapi.SEGPERM_WRITE) != 0
            cur_seg["x"] = (seg.perm & idaapi.SEGPERM_EXEC) != 0
            cur_seg["semantics"] = DefaultSectionSemantics
            if seg.type == idaapi.SEG_CODE:
                cur_seg["semantics"] = ReadOnlyCodeSectionSemantics
            elif seg.type == idaapi.SEG_DATA or seg.type == idaapi.SEG_BSS:
                if cur_seg["w"]:
                    cur_seg["semantics"] = ReadWriteDataSectionSemantics
                else:
                    cur_seg["semantics"] = ReadOnlyDataSectionSemantics
            
            jsonValue["segments"].append(cur_seg)

    # Record function details
    for ea in idautils.Functions():
        cur_func = {}
        cur_func["start"] = ea
        
        # Get function end address
        f = idaapi.get_func(ea)
        if f:
            cur_func["end"] = f.end_ea
        else:
            cur_func["end"] = ea
        
        cur_func["comment"] = linearize_comment(ea, True)
        cur_func["comments"] = {}
        for line_ea in idautils.Heads(ea, cur_func["end"]):
            line_comment = linearize_comment(line_ea)
            if line_comment is not None:
                cur_func["comments"][line_ea] = line_comment

        # Get function flags
        flags = idc.get_func_flags(ea)
        cur_func["can_return"] = (flags & idc.FUNC_NORET) != idc.FUNC_NORET
        cur_func["thunk"] = False
        
        blocks = []
        if f:
            for block in idaapi.FlowChart(f):
                blocks.append([block.start_ea, block.end_ea])

                # IDA treats thunks as being part of the function they are thunking to
                # Binary Ninja doesn't so only add the first basic block for all thunks
                if flags & idc.FUNC_THUNK != 0:
                    cur_func["thunk"] = True
                    break
        cur_func["basic_blocks"] = blocks
        
        # Get function name
        func_name = idc.get_func_name(ea)
        
        # Skip functions with auto-generated names starting with "sub_"
        if func_name.startswith("sub_"):
            continue
            
        jsonValue["functions"][func_name] = cur_func

    # Record string details
    for string in idautils.Strings():
        name = ""
        if string.ea in jsonValue["names"]:
            name = jsonValue["names"][string.ea]

        xrefs = list(idautils.DataRefsTo(string.ea))
        if idaapi.IDA_SDK_VERSION < 700:
            jsonValue["strings"][string.ea] = (name, string.length, string.type, xrefs)
        else:
            jsonValue["strings"][string.ea] = (name, string.length, string.strtype, xrefs)

    # TODO: global variable names and types
    # TODO: stack local variable names and types
    # TODO: types and enumerations
    # TODO: non-function comments

    with open(fileName, "wb") as f:
        f.write(json.dumps(jsonValue, indent=4).encode('utf-8'))

    print("Exported idb to {}".format(fileName))


if __name__ == "__main__":
    main(get_file_dialog())
