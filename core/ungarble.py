import refinery
from binaryninja.log import Logger
from binaryninja import *
from PySide6.QtWidgets import QTableWidgetItem
from PySide6.QtCore import Signal, QObject

logger = Logger(session_id=0, logger_name=__name__)

# Wrappers are needed for proper signaling to update
# table in main widget, while also making use of
# BackgroundTaskThread from the Binja API
class EmulateLocationsWrapper(QObject):
    update_ui_signal = Signal(int, int, str, int)

    def __init__(self):
        super().__init__()
        self.task = None
    
    def start(self, locations, data):
        self.task = EmulateLocations(locations, data)
        self.task.update_ui_signal = self.update_ui_signal
        self.task.start()

class EmulateLocations(BackgroundTaskThread):
    update_ui_signal = None

    def __init__(self, locations, data):
        BackgroundTaskThread.__init__(self, "Emulating Locations...", True)
        self.locations = locations
        self.data = data
        self.done = False

    def run(self):
        self.emulate_locations()

    def emulate_locations(self):
        total_targets = len(self.locations)
        for i, location in enumerate(self.locations):
            if len(location['current']) == 0:
                logger.log_info(f"Emulating 0x{location['start']:2x}")
                if self.cancelled:
                    break
                eresult = self.run_vstack(self.data, location['start'], location['end'])
                logger.log_info(f"Emulation result 0x{location['start']:2x} // result: {eresult}")
                self.update_ui_signal.emit(location['start'], location['end'], eresult, i)
            self.progress = f"{i+1}/{total_targets} target ranges emulated"
        self.done = True

    def load_pipeline(self, cmd: str, clear_cache=False) -> refinery.Unit:
        from refinery.lib.loader import load_pipeline
        if clear_cache:
            load_pipeline.cache_clear()
        pl = load_pipeline(cmd)
        return pl

    # A lot of this syntatic sugar is from overrides within Binary Refinery.
    # This passes our data (PE) to a loaded pipeline that attempts to emulate a
    # set of two addresses within the virtual address space of the loaded PE
    # using the vstack unit. This unit uses Unicorn to log writes to local stack
    # addresses throughout its emulation. Here the -W will log wrties in calls
    # made throughout the execution of the code, -c will wait until a function
    # call completes, -L allows partial matches of string outputs and -s provides
    # the starting address for emulation. <3 to @huettenhain for letting
    # me avoid writing yet another Unicorn wrapper.
    def run_vstack(self, data, start_address, stop_address):
        #result = data | self.load_pipeline(f"vstack -W -c -L -s={stop_address} {start_address} | carve printable -n 8") | bytes
        if start_address > stop_address:
            logger.log_error(f"{start_address:2x} larger than {stop_address:2x}")
            return ""
        result = data | self.load_pipeline(f"vstack -C -s={stop_address} {start_address} | carve printable -n 8") | bytes
        rstr = result.decode('ascii')
        return rstr

# Wrappers are needed for proper signaling to update
# table in main widget, while also making use of
# BackgroundTaskThread from the Binja API
class FindLocationsWrapper(QObject):
    update_ui_signal = Signal(int, int)
    finished = Signal()

    def __init__(self):
        super().__init__()
        self.task = None

    def start(self, pe, bv):
        self.task = FindLocations(pe, bv)
        self.task.update_ui_signal = self.update_ui_signal
        self.task.finished = self.finished
        self.task.start()

class FindLocations(BackgroundTaskThread):
    update_ui_signal = None
    finished = None

    def __init__(self, data, bv):
        BackgroundTaskThread.__init__(self, "Finding Locations...", True)
        self.data = data
        self.results = []
        self.done = False
        self.bv = bv
    
    def run(self):
        self.find_target_locations()

    """
    Pattern of our call to slicebytetostring after each deobfuscation
    sequence.
    00482999  xor     eax, eax  {0x0}
    0048299b  lea     rbx, [rsp+0x6d {var_93}]
    004829a0  mov     ecx, 0x2e
    004829a5  call    sub_4461e0
    """
    def check_slicebytetostr(self, finstrs, i):
        if finstrs[i-1][0][0].text == 'mov' \
        and finstrs[i-1][1] == 5 \
        and finstrs[i-2][0][0].text == 'lea' \
        and finstrs[i-2][1] == 5:
            return True
        """
        00db372d  31c0               xor     eax, eax  {0x0}
        00db372f  488d9c241e010000   lea     rbx, [rsp+0x11e {var_92}]
        00db3737  b921000000         mov     ecx, 0x21
        00db373c  0f1f4000           nop     dword [rax]
        00db3740  e81b3e69ff         call    slicebytetostr
        """
        if finstrs[i-2][0][0].text == 'mov' \
        and finstrs[i-2][1] == 5 \
        and finstrs[i-3][0][0].text == 'lea' \
        and finstrs[i-3][1] == 5:
            return True

        return False
    
    def check_slicebytetostr_strict(self, finstrs, i):
        if finstrs[i-1][0][0].text == 'mov' \
        and finstrs[i-1][1] == 5 \
        and finstrs[i-1][0][4].value < 0xffff \
        and finstrs[i-2][0][0].text == 'lea' \
        and finstrs[i-2][1] == 5 \
        and finstrs[i-3][0][0].text == 'xor' :
            return True
        """
        00db372d  31c0               xor     eax, eax  {0x0}
        00db372f  488d9c241e010000   lea     rbx, [rsp+0x11e {var_92}]
        00db3737  b921000000         mov     ecx, 0x21
        00db373c  0f1f4000           nop     dword [rax]
        00db3740  e81b3e69ff         call    slicebytetostr
        """
        if finstrs[i-2][0][0].text == 'mov' \
        and finstrs[i-2][1] == 5 \
        and finstrs[i-2][0][4].value < 0xffff \
        and finstrs[i-3][0][0].text == 'lea' \
        and finstrs[i-3][1] == 5 \
        and finstrs[i-4][0][0].text == 'xor' :
            return True

        return False
    
    # Linear identification of slicebytetostr calls was leading to
    # addresses later on within the function. This enumerates basic
    # block edges to find these instruction collections.
    def check_bb_slicebytetostr(self, bb, depth):
        MAX_BB_DEPTH = 6
        if depth == MAX_BB_DEPTH:
            return None
        else:
            depth += 1
            cbb = list(bb)
            result = None
            for i, cbb_instr in enumerate(cbb):
                if cbb_instr[0][0].text == 'call':
                    if self.check_slicebytetostr_strict(cbb, i):
                        # This is the address being called in the
                        # call instruction.
                        logger.log_info(f"slicebytetostr address: {cbb_instr} 0x{cbb_instr[0][2].value:2x} from basic block: 0x{bb.start:2x}")
                        return cbb_instr[0][2].value
            for edge in bb.outgoing_edges:
                result = self.check_bb_slicebytetostr(edge.target, depth)
                if result:
                    break
        return result

    """
    009da72f  4881ec90000000     sub     rsp, 0x90
    009da736  4889ac2488000000   mov     qword [rsp+0x88 {__saved_rbp}], rbp
    009da73e  488dac2488000000   lea     rbp, [rsp+0x88 {__saved_rbp}]
    009da746  48ba416816241723…mov     rdx, 0x7774231724166841
    """
    def match_disas_adv_seq_bb(self, f):
        #Collect all potential start and end addresses
        for bb in f.basic_blocks:
            finstrs = list(bb)
            for i, instr in enumerate(finstrs):
                # This pattern may seem simplistic, but
                # having generic enough patterns is difficult
                # and using ILs is not always feasible due to
                # the complexity of Golang functions results
                # in them not being lifted by default
                try:
                    if instr[0][0].text == 'mov' \
                    and len(instr[0]) == 5 \
                    and instr[0][4].value > 0xFFFF \
                    and finstrs[i+1][0][0].text == 'mov' \
                    and len(finstrs[i+1][0]) == 12 \
                    and finstrs[i+2][0][0].text == 'mov' \
                    and len(finstrs[i+2][0]) == 5 \
                    and finstrs[i-1][0][0].text != 'mov':
                        curr_start = bb.start
                        for j in range(0, i):
                            curr_start += bb[j][1]
                        slicebytetostr_addr = self.check_bb_slicebytetostr(bb, 0)
                        if slicebytetostr_addr:
                            return slicebytetostr_addr
                except:
                    pass
        return None

    """
    Disassembled instructions are nested lists, so we need
    to enumerate all nested tokens to find if a specific type exists.
    """
    def match_param_type(self, disas_instr):
        for i in disas_instr:
            if isinstance(i, list):
                for j in i:
                    if isinstance(j, binaryninja.architecture.InstructionTextToken):
                        if j.value > 0xFFFF:
                            return True
            else:
                for i in disas_instr:
                    if isinstance(j, binaryninja.architecture.InstructionTextToken):
                        if j.value > 0xFFFF:
                            return True    
        return False

    def match_disas_bb_simple(self, bb):
        #Collect all potential start and end addresses
        finstrs = list(bb)
        for i, instr in enumerate(finstrs):
            # This pattern may seem simplistic, but
            # having generic enough patterns is difficult
            # and using ILs is not always feasible due to
            # the complexity of Golang functions.
            if i == len(finstrs)-2:
                break
            try:
                if finstrs[i][0][0].text == 'mov' \
                and self.match_param_type(finstrs[i]) \
                and self.match_param_type(finstrs[i+2]) \
                and finstrs[i-1][0][0].text != 'mov':
                    saddr = bb.start
                    for j in range(0, i):
                        saddr += bb[j][1]
                    return saddr
            except:
                pass
        return None

    def get_obf_start(self, start_block):
        end_addresses = []
        max_depth = 4

        def check_block(block):
            addr = self.match_disas_bb_simple(block)
            if addr:
                end_addresses.append(addr)

        def recursive_check(block, depth):
            depth += 1
            if depth == max_depth:
                return
            check_block(block)
            for prev in block.incoming_edges:
                recursive_check(prev.source, depth)

        recursive_check(start_block, 0)
        return end_addresses

    # This will dynamically find slicebytetostr that is
    # used in all string obfuscation instances using a
    # custom heuristic (may break) then will enumerate
    # all callsites to find where obfuscated sequences start
    # and save them for emulation.
    def recurse_from_callsites(self, bv, eaddr):
        callers = list(bv.get_callers(eaddr))
        total_callers = len(callers)
        for i, caller in enumerate(callers):
            if self.cancelled:
                break
            self.progress = f"{i}/{total_callers} callsites checked"
            raddr = self.get_obf_start(bv.get_basic_blocks_at(caller.address)[0])
            # There's legitimate callsites (0 instance) and instances where
            # an obfuscation sequence can start where the original slicebytetostr
            # call was made, resulting in two addresses being found, so we need
            # to handle all of these cases.
            if len(raddr) == 0:
                #logger.log_info(f"Unable to retrieve start address for 0x{caller.address:2x}")
                pass
            elif len(raddr) == 1:
                #logger.log_info(f"0x{caller.address:2x} has one start location")
                self.update_ui_signal.emit(raddr[0], caller.address)
            elif len(raddr) > 1:
                #logger.log_info(f"0x{caller.address:2x} has more than one start location")
                self.update_ui_signal.emit(raddr[1], caller.address)

        self.finished.emit()
        self.done = True

    def find_target_locations(self):
        logger.log_info(f"Finding slicebytetostr")
        addr = self.find_slicebytetostr(self.bv)
        logger.log_info(f"Recursively enumerating all callsites from 0x{addr:2x}")
        if addr:
            self.recurse_from_callsites(self.bv, addr)
        else:
            return []

    def find_slicebytetostr(self, bv):
        for f in bv.functions:
            result = self.match_disas_adv_seq_bb(f)
            if result:
                return result
        return None

class Ungarble():
    # A lot of this syntatic sugar is from overrides within Binary Refinery.
    # This passes our data (PE) to a loaded pipeline that attempts to emulate a
    # set of two addresses within the virtual address space of the loaded PE
    # using the vstack unit. This unit uses Unicorn to log writes to local stack
    # addresses throughout its emulation. Here the -W will log wrties in calls
    # made throughout the execution of the code, -c will wait until a function
    # call completes, -L allows partial matches of string outputs and -s provides
    # the starting address for emulation. <3 to @huettenhain for letting
    # me avoid writing yet another Unicorn wrapper.
    @staticmethod
    def run_vstack(data, start_address, stop_address):
        from refinery.lib.loader import load_pipeline
        result = data | load_pipeline(f"vstack -W -c -L -s={stop_address} {start_address} | carve printable -n 9") | bytes
        rstr = result.decode('ascii')
        return rstr