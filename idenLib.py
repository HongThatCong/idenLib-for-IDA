# -------------------------------------------------------------------------------
#
# Copyright (c) 2019
# Lasha Khasaia @_qaz_qaz
# https://github.com/secrary/idenLib
#
# 25/09/2020: HTC - VinCSS (a member of Vingroup)
#   - linter, some refactor code, wrap IO call in try/excption
#   - add set_func_library function
#   - Allow user to select multi signature files
#   - Ask user to uses current cached sigs or select new
#   Thanks Lasha Khasaia for a good tool/plugin
#
# -------------------------------------------------------------------------------

# pylint: disable=C0111,C0103

from __future__ import print_function

import os
import cPickle as pickle
import capstone
import zstd

import idaapi
import idautils
import idc

from PyQt5 import QtWidgets

MIN_FUNC_SIZE = 0x20
MAX_FUNC_SIZE = 0x100
PLUGIN_NAME = "idenLib"
PLUGIN_VERSION = "v0.4"
IDENLIB_CONTACT = "Contact: Lasha Khasaia (@_qaz_qaz)"

CAPSTONE_MODE = capstone.CS_MODE_64 if idc.__EA64__ else capstone.CS_MODE_32
SIG_EXT = ".sig64" if idc.__EA64__ else ".sig"

symEx_dir = os.path.join(idaapi.get_user_idadir(), "SymEx")
symEx_cache_dir = os.path.join(symEx_dir, "cache")
idenLibCache = os.path.join(symEx_cache_dir, "idenLibCache" + ("64" if idc.__EA64__ else ""))
idenLibCacheMain = os.path.join(symEx_cache_dir, "idenLibCacheMain" + ("64" if idc.__EA64__ else ""))

g_func_sigs = {}
g_main_sigs = {}
decompressor = zstd.ZstdDecompressor()

def getNames():
    for _ea, name in idautils.Names():
        yield name

def getFiles(path):
    files = QtWidgets.QFileDialog.getOpenFileNames(None,
                                                   "Select one or more sig files for function identification",
                                                   path,
                                                   "*" + SIG_EXT)
    return files[0]

# return (start_ea, size)
def getFuncRanges():
    funcs_addr = []
    start = 0
    next_func = idaapi.get_next_func(start)
    while next_func:
        size = next_func.size()
        if size > MIN_FUNC_SIZE:
            if size > MAX_FUNC_SIZE:
                size = MAX_FUNC_SIZE

            funcs_addr.append(next_func.start_ea - start)
            yield (next_func.start_ea, size)

        next_func = idaapi.get_next_func(next_func.start_ea)

def getOpcodes(addr, size):
    md = capstone.Cs(capstone.CS_ARCH_X86, CAPSTONE_MODE)
    md.detail = True
    instr_bytes = idaapi.get_bytes(addr, size)
    opcodes_buf = b''
    for i in md.disasm(instr_bytes, size):
        # get last opcode
        if i.opcode[3] != 0:
            opcodes_buf += "%02x" % (i.opcode[3])
        elif i.opcode[2] != 0:
            opcodes_buf += "%02x" % (i.opcode[2])
        elif i.opcode[1] != 0:
            opcodes_buf += "%02x" % (i.opcode[1])
        else:
            opcodes_buf += "%02x" % (i.opcode[0])
    return opcodes_buf

def set_func_library(addr):
    func = idaapi.get_func(addr)
    if func:
        func.flags |= idaapi.FUNC_LIB
        idaapi.update_func(func)

def idenLibProcessSignatures():
    global g_func_sigs
    global g_main_sigs

    files = getFiles(symEx_dir)
    if not files:
        print("[idenLib] user cancelled")
        return False

    total = 0
    for f in files:
        if not f.endswith(SIG_EXT):
            continue

        try:
            ifile = open(f, 'rb')
            data = ifile.read()
            ifile.close()
        except IOError as e:
            print("[idenLib] open file %s error: %s" % (f, str(e)))
            continue

        try:
            sigs = decompressor.decompress(data).strip()
        except Exception as e:
            print("[idenLib] Exception when decompress file %s: %s" % (f, str(e)))
            continue

        count = 0
        sigs = sigs.split(b"\n")
        for line in sigs:
            line = line.strip()
            if line != "":
                sig_opcodes, name = line.split(" ")
            else:
                continue

            if '_' in sig_opcodes: # "main" signatures
                opcodeMain, mainIndexes = sig_opcodes.split('_')
                fromFunc, fromBase = mainIndexes.split("!")
                g_main_sigs[opcodeMain] = (name.strip(), int(fromFunc), int(fromBase))
            elif '+' in sig_opcodes:
                opcodes, strBranches = sig_opcodes.split('+')
                nBranches = int(strBranches)
                g_func_sigs[opcodes.strip()] = (name.strip(), nBranches)
            else:
                g_func_sigs[sig_opcodes.strip()] = (name.strip(), 0)

        count += 1
        total += count
        print("[idenLib] file %s processed, %d signatures" % (f, count))

    if total == 0:
        print("[idenLib] no signatures found.")
        return False

    try:
        with open(idenLibCache, "wb") as f:
            pickle.dump(g_func_sigs, f)

        with open(idenLibCacheMain, "wb") as f:
            pickle.dump(g_main_sigs, f)

        print("[idenLib] Signatures refreshed. Total signatures are %d." % total)
        return True

    except Exception as e:
        print("[idenLib] exception occurred when dump cache: %s" % str(e))
        return False


def idenLib():
    global g_func_sigs
    global g_main_sigs

    new_sigs = False
    cached = False
    if os.path.isfile(idenLibCache):
        try:
            with open(idenLibCache, "rb") as f:
                g_func_sigs = pickle.load(f)
            if os.path.isfile(idenLibCacheMain):
                with open(idenLibCacheMain, "rb") as f:
                    g_main_sigs = pickle.load(f)
                    cached = True
        except Exception as e:
            # continue with new sigs after excption
            print("[idenLib] load cache files error: %s" % str(e))

    if cached:
        ret = idaapi.ask_yn(idaapi.ASKBTN_YES, "Do you want to select another signatures than current cached ?")
        if ret == idaapi.ASKBTN_CANCEL:
            print("[idenLib] user cancelled")
            return

        new_sigs = ret == idaapi.ASKBTN_YES
    else:
        new_sigs = True

    idaapi.msg_clear()

    if new_sigs:
        if not idenLibProcessSignatures():
            return

    idaapi.show_wait_box("Please wait scan and apply signatures...")

    # function sigs from the current binary
    func_bytes_addr = {}
    for addr, size in getFuncRanges():
        f_bytes = getOpcodes(addr, size)
        func_bytes_addr[f_bytes] = addr

    # apply sigs
    counter = 0
    mainDetected = False
    for sig_opcodes, addr in func_bytes_addr.items():
        if g_func_sigs.has_key(sig_opcodes):
            set_func_library(addr)
            func_name = g_func_sigs[sig_opcodes][0]
            current_name = idc.get_func_name(addr)
            if current_name != func_name:
                idc.set_name(addr, func_name, idaapi.SN_FORCE)
                print("{}: {}".format(hex(addr).rstrip("L"), func_name))
                counter = counter + 1

        if g_main_sigs.has_key(sig_opcodes): # "main" sig
            callInstr = g_main_sigs[sig_opcodes][1] + addr
            if idaapi.print_insn_mnem(callInstr) == "call":
                call_target = idc.get_operand_value(callInstr, 0)
                set_func_library(call_target)
                func_name = g_main_sigs[sig_opcodes][0]
                current_name = idc.get_func_name(call_target)
                if current_name != func_name:
                    idaapi.set_name(call_target, func_name, idaapi.SN_FORCE)
                    print("{}: {}".format(hex(call_target).rstrip("L"), func_name))
                    counter = counter + 1
                    mainDetected = True

    if not mainDetected:
        for entry in idautils.Entries():
            for sig_opcodes, name_funcRva_EntryRva in g_main_sigs.items():
                callInstr = name_funcRva_EntryRva[2] + entry[2] # from EP
                if idaapi.print_insn_mnem(callInstr) == "call":
                    fromFunc = name_funcRva_EntryRva[1]
                    func_start = callInstr - fromFunc
                    func_opcodes = getOpcodes(func_start, MAX_FUNC_SIZE)
                    if func_opcodes.startswith(sig_opcodes):
                        call_target = idc.get_operand_value(callInstr, 0)
                        set_func_library(call_target)
                        current_name = idc.get_func_name(call_target)
                        func_name = g_main_sigs[sig_opcodes][0]
                        if current_name != func_name:
                            idaapi.set_name(call_target, func_name, idaapi.SN_FORCE)
                            print("{}: {}".format(hex(call_target).rstrip("L"), func_name))
                            counter = counter + 1
                            mainDetected = True
                            break

    idaapi.hide_wait_box()

    print("[idenLib] Applied to {} function(s)".format(counter))


class idenLibHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        idenLib()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class AboutHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        print(PLUGIN_NAME + " " + PLUGIN_VERSION)
        print(IDENLIB_CONTACT)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class RefreshHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        idenLibProcessSignatures()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# icon author: https://www.flaticon.com/authors/freepik
icon_data = "".join([
    "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52\x00\x00\x00"
    "\x18\x00\x00\x00\x18\x08\x03\x00\x00\x00\xD7\xA9\xCD\xCA\x00\x00\x00\x4E\x50"
    "\x4C\x54\x45\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\xC4\xA2\xA6\x59\x00\x00\x00\x19\x74\x52\x4E\x53\x00\x20"
    "\xEE\x4F\xC9\x64\xD3\xB3\x32\x99\x88\x17\x0C\xC1\x5C\x28\xF6\x7F\xE6\xDD\xBB"
    "\xA2\x47\x41\x90\xCE\x19\x07\xA1\x00\x00\x00\xC8\x49\x44\x41\x54\x28\xCF\x75"
    "\xD1\xDB\xAE\x83\x20\x10\x85\xE1\x35\x08\x0E\xCA\x16\x3C\xDB\xF5\xFE\x2F\xBA"
    "\xC7\x58\xDB\xB4\xA1\xFF\x8D\xC8\x27\x48\x02\x7E\x26\xD6\xDF\xE7\x58\x70\x46"
    "\xAB\x79\x82\x23\x19\xD4\x31\x55\xC1\x93\x47\x75\xAB\xFD\x10\xA9\xAE\x38\x16"
    "\xEA\x0B\x36\x6F\x6D\x88\x56\x8A\xE4\xFC\x02\xA5\xA5\x58\x9C\x73\x19\x23\x99"
    "\x6E\x88\x12\xA3\x94\x6B\x2B\x78\x9B\xB8\xA1\xA5\x9B\xE9\x9F\xF0\x20\xA7\x37"
    "\x58\x37\x64\x52\xAB\x50\x48\x57\x85\xF3\x21\x55\x18\x6C\xA6\x0A\x3D\xD9\x1B"
    "\x68\x37\x7E\x41\xD3\x4E\x0A\x2C\x40\xF7\x05\x12\x60\x2B\x5C\xC2\x70\x43\x0E"
    "\x21\x14\xD8\x97\xD0\x02\x8E\xB3\xFD\xA3\x1D\xD4\x0F\xD0\x75\x5D\x77\x03\x1D"
    "\x99\xD1\x5B\x25\xED\x21\x34\x09\x93\x8D\xA3\x41\x9E\xEC\xA5\xB3\xA2\xBF\xB6"
    "\x7A\xD8\xF8\x04\xD9\xDA\xA1\x76\x5C\x24\x3A\xBD\x6E\x4D\xCE\xD2\xFB\x36\x05"
    "\xBF\xFB\x07\x19\xFC\x16\xA4\x38\xC6\x08\x3D\x00\x00\x00\x00\x49\x45\x4E\x44"
    "\xAE\x42\x60\x82"
])


class idenLibMain(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "idenLib - Library Function Identification"
    help = IDENLIB_CONTACT
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''

    def run(self, _arg):
        idenLib()

    def term(self):
        pass

    def init(self):
        #
        # Ensure symEx and cache dir existed
        #
        if not os.path.isdir(symEx_dir):
            print("[idenLib] default sig directory {} not existed !!!".format(symEx_dir))
            os.mkdir(symEx_dir)

        if not os.path.isdir(symEx_cache_dir):
            os.mkdir(symEx_cache_dir)

        act_icon = idaapi.load_custom_icon(data=icon_data, format="png")
        act_name = "idenLib:action"
        idaapi.register_action(idaapi.action_desc_t(
            act_name,
            "idenLib - Function Identification",
            idenLibHandler(),
            None,
            "idenLib",
            act_icon))

        # Insert the action in a toolbar
        idaapi.attach_action_to_toolbar("DebugToolBar", act_name)
        idaapi.attach_action_to_menu(
            'Edit/idenLib/',
            act_name,
            idaapi.SETMENU_APP)

        # refresh signatures
        act_name = "idenLib:refresh"
        idaapi.register_action(idaapi.action_desc_t(
            act_name,
            "Refresh Signatures",
            RefreshHandler(),
            None,
            "idenLib - Refresh"))
        idaapi.attach_action_to_menu(
            'Edit/idenLib/',
            act_name,
            idaapi.SETMENU_APP)

        # about
        act_name = "idenLib:about"
        idaapi.register_action(idaapi.action_desc_t(
            act_name,
            "About",
            AboutHandler(),
            None,
            "idenLib - About"))
        idaapi.attach_action_to_menu(
            'Edit/idenLib/',
            act_name,
            idaapi.SETMENU_APP)

        return idaapi.PLUGIN_OK


def PLUGIN_ENTRY():
    return idenLibMain()

if __name__ == "__main__":
    PLUGIN_ENTRY()
