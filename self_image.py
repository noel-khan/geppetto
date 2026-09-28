from __future__     import annotations  # Enables clean self-referential type hints
from dataclasses    import dataclass, field
from typing         import Any
from enum           import Enum, auto
from functools      import wraps
import subprocess   # run arbitrary system/shell commands
import os           # folder management
import shutil       # file management
import random       # gen random origin
import uuid         # alias device filenames to avoid name collisions
import time         # to time function calls
import timeit       # benchmark CPU utilization
import psutil       # benchmark RAM utilization in terms of 4Kb pages
import tracemalloc  # benchmark RAM utilization
import sys          # read arguments
import gc           # garbage collector, helps keep RAM measurements clean


# -------------------- CONSTANTS ------------------------


@dataclass(frozen=True)
class CONSTANTS:
    # --- CONFIGURATION ---
    ADD_INSTRUMENTATION = True              # whether to attach instrumentation to record runtimes and memory utilization
    IS_DYNAMIC_ASSEMBLY = False             # Enable if FRR assembled after launch to ensure all traffic is captured; else False to avoid built-in waits that'll throw off timing tests

    BENCHMARK_RUNS      = 100               # qty runs to capture timing info on
    VERSION             = "0.3"             # MAJOR(0).MINOR(N)
    OUTPUT_FOLDER       = "./out"           # local cache for device files, generated model, run logs
    OUTPUT_FILE         = "/self_image.sdf" # generated model name
    LABELS_FOLDER       = "./ports"         # local folder with meshes (TODO: move from host to /device/meshes)
    MESHES_FOLDER       = "/meshes/"        # device path
    ATTACHMENT_TIMEOUT  = 0                 # Seconds we wait for attachments. If device attached, wait 2s and reset timer
    ENUMERATION_TIMEOUT = 2                 # Seconds we'll wait after one device is detected
    TSHARK_INTERFACE    = -1                # Z+. tshark interface to record traffic from. 0 records all. Overridden by GET_TSHARK_IFCS

    # --- MAGIC CHARS ---
    PARAM1              = "XXXXX"
    PARAM2              = "YYYYY"
    PARAM3              = "ZZZZZ"
    CLR_RESET           = "\033[0m"
    CLR_RED             = "\033[31m"
    CLR_YELLOW          = "\033[93m"
    CLR_ORANGE          = "\033[38;5;208m"
    # DEVICE_VENDOR     = "DeMontfort"

    # --- COMMANDS ---
    SYSFS_PREFIX_DEV    = "/sys/bus/usb/devices" # root to search for devices. TODO: use pseudo folder for unit test automation
    SYSFS_PREFIX        =f"{SYSFS_PREFIX_DEV}/usb" 
    LIST_SYSFS_USBS     =f"find {SYSFS_PREFIX}*/ -name ep* | grep -v -e 'ep_00' | sed 's|/ep_[0-9][0-9]$||' | uniq"
    SYSFS_BLOCKS        = "ls -d $(find XXXXX -name block)/* | grep -w -e 'sd[a-z]\\+[0-9]*$'"   # P1 is kernel device path 
    SYSFS_TTYACM        =f"ls -d {SYSFS_PREFIX_DEV}/*XXXXX*/tty/*"                              # P1 is kernel device path 
    SYSFS_ADDR          =f"cat {SYSFS_PREFIX_DEV}/XXXXX/devnum"                                 # P1 is kernel device path 
    SYSFS_SPEED         =f"cat {SYSFS_PREFIX_DEV}/XXXXX/speed"                                  # P1 is kernel device path 
    BLOCK_MOUNTS        = "lsblk -o PATH,MOUNTPOINTS | grep /media/ | grep XXXXX | awk '{$1=\"\"; print $0}'"  # P1 is block-dev-id, e.g., /dev/sda
    GET_SDF_FILE        = "find XXXXX -iname \"*.sdf\""                                         # P1 is mountpt
    GET_PJS_FILE        = "find XXXXX -iname \"*.json\""                                        # P1 is mountpt
    CLEAR_DIRTY_BIT     = "sudo fsck -p XXXXX | grep -v fsck | uniq"                            # P1 is block-dev-id. `sudo visudo` and add line to avoid pw prompts
    PJS_HUB_ATR         = "grep -e 'is_hub' XXXXX/YYYYY | awk -F: '{print $2}'"                 # P1 is mountpt, P2 is the .json file
    GET_SAVE_FILEPATH   =f"echo {OUTPUT_FOLDER}/XXXXX_$(date +%Y%m%d_%H%M%S).log"               # P1 is filename

    # --- EXPERIMENTAL DATA COLLECTION ---
    CLEAR_KERNEL_LOG    = "sudo dmesg -C"                                                       # `sudo visudo` and add line to avoid pw prompts
    SAVE_KERNEL_LOG     =f"sudo dmesg | tee {OUTPUT_FOLDER}/dmesg_$(date +%Y%m%d_%H%M%S).log"
    ENABLE_WIRESHARK    = "sudo modprobe usbmon"                                                # `sudo visudo` and add line to avoid pw prompts
    # Cant use Vendor ID since some tests use COTS parts with different IDs:
    # GET_TSHARK_BUSID    = "lsusb | grep XXXXX | awk '{$2=1*$2;$2=\"usbmon\"$2; print $2}' | awk -F. '{print $1}'".replace(PARAM1,DEVICE_VENDOR)
    # GET_TSHARK_IFCS     = "tshark -D | grep XXXXX"
    GET_TSHARK_IFCS     = "tshark -D | grep usbmon0 | awk '{print 1*$1}'"                       # Reads all USB traffic. USE PS/2 KEYBOARD/MOUSE!!!
    LOG_TSHARK_DETAILS  =f"sudo tshark -Q -i XXXXX -V  -S---------- >{OUTPUT_FOLDER}/tshark_detail.log" 
    LOG_TSHARK_SUMMARY  =f"sudo tshark    -i XXXXX >{OUTPUT_FOLDER}/tshark_summary.log"         # Do not run with -Q
    LOG_TSHARK_BINARY   =f"sudo tshark -Q -i XXXXX -w - >{OUTPUT_FOLDER}/tshark.pcapng"         # P1 is tshark interface        
    KILL_TSHARK_PROCS   = "ps -aux | grep -e 'tshark' | awk '{ system(\"sudo kill -s 2 \" $2)}'"# sig2 = SIGINT = CTL-C. Graceful exit but w/ unbounded wait
    GET_TSHARK_STATS    =f"sudo tshark -r {OUTPUT_FOLDER}/tshark.pcapng -q -z conv,usb -z endpoints,usb >{OUTPUT_FOLDER}/tshark_stats.txt"

    # --- FEEDBACK ---
    MSG_SHELL           = "Failed to execute terminal command."
    MSG_NO_DEVICES      = "Did not find any usb devices in sysfs."
    MSG_AFFIRM_PAROW    = "Row[XXXXX] PAROW should be None."                                    # P1 is USBID
    MSG_NEGATE_PAROW    = "Row[XXXXX] PAROW should be NOT None."                                # P1 is USBID
    MSG_LABELS_MISSING  = "The XXXXX folder (which contains port labels) is missing."           # P1 is LABELS_FOLDER
    MSG_PROBING_BLKS    = "Checking block devices for errors..."
    MSG_DEPTH_JUMP      = "Row[XXXXX] Depth discontinuity - possibly internally-cascaded hub."
    MSG_DEPTH_NEGATIVE  = "Row[XXXXX] Depth was less than zero, which should never happen."
    MSG_ZERODEPTH_HUB   = "Row[XXXXX] is a zero-depth hub, but if it's a (non-root) hub, it must necessarily be non-zero."
    MSG_UNKNOWN_TOKEN   = "Expected sysfs hierarchy to be delimited only by \\{-, :, .\\} but found "
    MSG_INVALID_CONFIG  = "You can't run benchmarks on dynamic assemblies due to tshark automation and operator latencies that will throw timing off."
    MSG_DISJOINT_MODEL  = "This assembly was logically disjoint. Ensure there's a structural part and its is_hub is correct."


    # --- TEMPLATES ---

    # PARAM1/2: x/y-position to prevent overlaps in case of rhizome topology
    # PARAM3: SDF (filename only)
    SDF_FIRST_PART  = """
<include>
    <uri>model://ZZZZZ.sdf</uri>
    <name>ZZZZZ</name>
    <pose>XXXXX YYYYY 0 0 0 0</pose>
</include>
"""
 
    # PARAM1: insertion point for parts-list
    SDF_TEMPLATE    = """<?xml version="1.0" ?>
<sdf version="1.11">
    <model name="complete_robot">
        XXXXX
    </model>
</sdf>
"""

    # PARAM1 = SDF (filename only, no extension)
    # PARAM2 = <parent-filename-no-ext>::<port>
    # PARAM3 = Upstream port (assumed to be P0)
    SDF_PART        = """
<include>
    <uri>model://XXXXX.sdf</uri>
    <name>XXXXX</name>
    <pose relative_to="YYYYY" />
</include>
<joint name="JXXXXX" type="fixed">
    <parent>YYYYY</parent>
    <child>XXXXX::PZZZZZ</child>
</joint>
"""


# interpolate or reorder however you like. The print_inventory() function 
# is no wiser. If you do add a field, update initialize_inventory() too.
class FieldIdx(Enum):
    ROW       = 0      # anchor first value then use auto on subsequent values for easier maintenance
    USBID     = auto()
    ADDR      = auto()
    #CFGIF     = auto() # for MSC. Would need another col for CDC but technically I dont /need/ either bit of info. Less is more.
    SPEED     = auto()
    DEPTH     = auto()
    CPORT     = auto() # Child's AT/TO-port (a child's upstream port is always P0). Negative indicates attribute only
    PPORT     = auto() # Parent's downstream port
    PAROW     = auto() # reference to paren't row so we can get the SDF name
    BLOCKID   = auto()
    MOUNTPT   = auto()
    TTYACM    = auto()
    SDF_NAME  = auto()
    PJS_NAME  = auto()
    IS_HUB    = auto()
    SDF_UUID  = auto() 

    def __index__(self):
        return self.value


class NodeType(Enum):
    HOST    = 0
    BUS     = auto()
    RH_PORT = auto()
    PORT    = auto()
    IFC_EP  = auto()


class CLI_MODE(Enum):
    ONE_SHOT  = 0
    BENCHMARK = auto()


# -------------------- INSTRUMENTATION ------------------------
# rather than print runtimes to the terminal as we go, accumulate 
# results and print as one cohesive list. Runtime instrumentation
# is only performed when CAPTURE_RUNTIMES = True. Otherwise the 
# instrumentation decorator is a NOP lamba. 

g_timing_results:str = ""

def track_resource_utilization(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        global g_timing_results
        process = psutil.Process(os.getpid())

        tracemalloc.clear_traces() # clear high-water marks from previous runs
        gc.collect() # ensure leftover memory is deallocated to avoid polluting RAM measurements
        
        #icurr, ipeak = tracemalloc.get_traced_memory() # no need to track initials since I clear_traces()
        mem_before = process.memory_info().rss 

        start = time.perf_counter()

        result = func(*args, **kwargs)

        end = time.perf_counter()

        mem_after = process.memory_info().rss 
        fcurr, fpeak = tracemalloc.get_traced_memory()
        #tracemalloc.stop() # needs to called AFTER collecting measurements. <-- now left running to avoid reinitialization jitter

        # Result format: 'fx time ms'. Placing fx first makes it easier 
        #  to calculate stats after sorting by fx 
        timing_record = f"{func.__name__}() {(1000*(end - start)):010.6f} ms {fcurr:d} b_alloc {fpeak:d} b_hwm {mem_after - mem_before:d} b_pages\r\n"
        g_timing_results = g_timing_results + timing_record
        return result
    return wrapper


instrumentation = track_resource_utilization if CONSTANTS.ADD_INSTRUMENTATION else (lambda f: f)


# ------------------ DATA STRUCTURES ----------------------

@dataclass
class Table:
    headers: list = field(default_factory=list)
    rows: list = field(default_factory=list) # each element in row is a list with len=COLUMNS
    widths: list = field(default_factory=list)

    def __post_init__(self):
        self.headers.extend(col.name for col in FieldIdx)
        self.widths.extend(len(h) for h in self.headers)

    def add_row(self) -> int:
        self.rows.append([None] * self.COLUMNS) 
        return len(self.rows)-1 # base-1 idx to data row

    @property # RO
    def COLUMNS(self):
        return len(self.headers)


@dataclass # automatically decorates class with boilerplate 
class TreeNode:
    id:         int
    path:       str
    ntype:      NodeType
    parent:     TreeNode | None = None    
    children:   list[TreeNode] = field(default_factory=list)

    def add_child(self, child_node: TreeNode) -> TreeNode:
        child_node.parent = self
        self.children.append(child_node)
        return child_node

    def has_child(self, child_id: int) -> bool:
        return any(c.id == child_id for c in self.children)

    def get_child(self, child_id: int) -> TreeNode:
        return next((c for c in self.children if c.id == child_id), None)


# -------------------- SYSFS DEVICE QUERIES ------------------------

@instrumentation
def find_usb_devices() -> str:
    result = subprocess.run(
        CONSTANTS.LIST_SYSFS_USBS,
        shell=True,
        text=True,
        capture_output=True
    )
    
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(pERROR(CONSTANTS.MSG_SHELL))
    return result.stdout.splitlines()


@instrumentation
def find_block_devices(device_listing:list) -> dict:
    if len(device_listing) == 0:
        raise RuntimeError(pERROR(CONSTANTS.MSG_NO_DEVICES))
    dev2blk = {}
    for f in device_listing:
        result = subprocess.run(
            CONSTANTS.SYSFS_BLOCKS.replace(CONSTANTS.PARAM1, f),
            shell=True,
            text=True,
            capture_output=True
        )
        if result.returncode == 0:
            dev2blk[f] = "/dev/" + result.stdout.split("/")[-1].strip()
    return dev2blk


@instrumentation
def find_acm_devices(device_listing:list) -> dict:
    if len(device_listing) == 0:
        raise RuntimeError(pERROR(CONSTANTS.MSG_NO_DEVICES))

    # drop ifc_ep from listing and add to dict
    device_listing_unique = set()
    for dev in device_listing:
        token = str(dev).replace(CONSTANTS.SYSFS_PREFIX,"")
        if token.count(":"):
            token = token.split(":")[0]
        if token.count("/"):
            token = token.split("/")[-1]
        device_listing_unique.add(token)

    dev2acm = {}
    for dev in device_listing_unique:
        result = subprocess.run(
            CONSTANTS.SYSFS_TTYACM.replace(CONSTANTS.PARAM1, dev),
            shell=True,
            text=True,
            capture_output=True
        )
        if result.returncode == 0:
            dev2acm[dev] = "/dev/" + result.stdout.split("/")[-1].strip()
    return dev2acm


@instrumentation
def find_mountpoints(dev2blks:dict) -> dict:
    blk2mnt:dict = {}
    for key, value in dev2blks.items():
        result = subprocess.run(
            CONSTANTS.BLOCK_MOUNTS.replace(CONSTANTS.PARAM1, value),
            shell=True,
            text=True,
            capture_output=True
        )
        if result.returncode == 0:
            if len(result.stdout.strip().splitlines()) == 1:
                blk2mnt[value] = result.stdout.strip()

    return blk2mnt


@instrumentation
def sanitize_blk2mnt(blk2mnt:dict) -> dict:
    new_blk2mnt:dict = {}
    for key, value in blk2mnt.items():
        if len(str(value)): # i.e., has mount point
            new_blk2mnt[key] = value
    return new_blk2mnt


@instrumentation
def sanitize_dev2blk(dev2blk:dict, blk2mnt:dict) -> dict:
    new_dev2blk:dict = {}
    for key, value in dev2blk.items():
        if blk2mnt.get(value) is not None:
            new_dev2blk[key] = value
    return new_dev2blk


@instrumentation
def check_block_devices(dev2blk:dict):
    _s = f"\n{CONSTANTS.MSG_PROBING_BLKS}"
    pbuffer:str = "\r\n" +  pINFO(_s) + "\r\n" + ("-" * len(_s)) + "\r\n"
    for key, value in dev2blk.items():
        result = subprocess.run(
            CONSTANTS.CLEAR_DIRTY_BIT.replace(CONSTANTS.PARAM1, value),
            shell=True,
            stdout=subprocess.PIPE,     # capture stdout stream
            stderr=subprocess.STDOUT,   # redirect stderr to stdout to combine all output
            text=True,
            #capture_output=True
        )
        pbuffer = pbuffer + result.stdout.strip() + "\r\n"
    print(pbuffer)


# -------------------- TABULAR INVENTORY ------------------------


@instrumentation
def initialize_inventory(dev2blk:dict, blk2mnt:dict, dev2acm:dict) -> Table:
    t = Table()
    for key, value in dev2blk.items():
        idx = t.add_row()
        t.rows[idx][FieldIdx.ROW] = idx
        #t.rows[idx][FieldIdx.CFGIF] = str(key).split("/")[-1].split(":")[-1]            # grab interface.EP
        t.rows[idx][FieldIdx.USBID] = str(key).split("/")[-1].split(":")[0]             # drop interface.EP
        t.rows[idx][FieldIdx.ADDR]  = None
        t.rows[idx][FieldIdx.SPEED]  = None
        t.rows[idx][FieldIdx.DEPTH] = str(t.rows[idx][FieldIdx.USBID]).count(".")       # base1. Preliminary. Max is 7
        t.rows[idx][FieldIdx.CPORT] = str(t.rows[idx][FieldIdx.USBID]).split(".")[-1]   # tentative since we may be dealing with a cascaded hub
        t.rows[idx][FieldIdx.PPORT] = None                                              # we cant set this until we determine which devices are hubs
        t.rows[idx][FieldIdx.BLOCKID] = value
        t.rows[idx][FieldIdx.MOUNTPT] = blk2mnt.get(value)
        t.rows[idx][FieldIdx.TTYACM]  = dev2acm.get(t.rows[idx][FieldIdx.USBID])

        t.widths[FieldIdx.ROW]      = len(t.headers[FieldIdx.ROW]) 
        t.widths[FieldIdx.ADDR]     = len(t.headers[FieldIdx.ADDR]) 
        t.widths[FieldIdx.SPEED]    = len(t.headers[FieldIdx.SPEED]) 
        t.widths[FieldIdx.DEPTH]    = len(t.headers[FieldIdx.DEPTH]) 
        t.widths[FieldIdx.CPORT]    = len(t.headers[FieldIdx.CPORT]) 
        t.widths[FieldIdx.PPORT]    = len(t.headers[FieldIdx.PPORT]) 
        t.widths[FieldIdx.USBID]    = max(len(t.rows[idx][FieldIdx.USBID])      if t.rows[idx][FieldIdx.USBID]   is not None else 0, t.widths[FieldIdx.USBID]) 
        #t.widths[FieldIdx.CFGIF]    = max(len(t.rows[idx][FieldIdx.CFGIF])      if t.rows[idx][FieldIdx.CFGIF]   is not None else 0, t.widths[FieldIdx.CFGIF])
        t.widths[FieldIdx.BLOCKID]  = max(len(t.rows[idx][FieldIdx.BLOCKID])    if t.rows[idx][FieldIdx.BLOCKID] is not None else 0, t.widths[FieldIdx.BLOCKID])
        t.widths[FieldIdx.MOUNTPT]  = max(len(t.rows[idx][FieldIdx.MOUNTPT])    if t.rows[idx][FieldIdx.MOUNTPT] is not None else 0, t.widths[FieldIdx.MOUNTPT])
        t.widths[FieldIdx.TTYACM]   = max(len(t.rows[idx][FieldIdx.TTYACM])     if t.rows[idx][FieldIdx.TTYACM]  is not None else 0, t.widths[FieldIdx.TTYACM])
        t.widths[FieldIdx.SDF_UUID] = 10                                                # actually 32 chars, but we dont need to see all that
    return t


@instrumentation
def probe_for_file(t:Table, LOOKUP:str, nameIdx:int) -> Table:
    for r in range(len(t.rows)):
        result = subprocess.run(
            LOOKUP.replace(CONSTANTS.PARAM1, t.rows[r][FieldIdx.MOUNTPT]),
            shell=True,
            text=True,
            capture_output=True
        )
        if result.returncode == 0:
            if len(result.stdout):
                t.rows[r][nameIdx] = result.stdout.split("/")[-1].strip()
                t.widths[nameIdx] = max(t.widths[nameIdx], len(str(t.rows[r][nameIdx])))
    return t


@instrumentation
def probe_pjs_for_true(t:Table, LOOKUP:str, propIdx:int, default:Any = None) -> Table:
    for r in range(len(t.rows)):
        t.rows[r][propIdx] = default
        if t.rows[r][FieldIdx.PJS_NAME] is not None and len(t.rows[r][FieldIdx.PJS_NAME]):
            result = subprocess.run(
                LOOKUP.replace(CONSTANTS.PARAM1, t.rows[r][FieldIdx.MOUNTPT]).replace(CONSTANTS.PARAM2, t.rows[r][FieldIdx.PJS_NAME]),
                shell=True,
                text=True,
                capture_output=True
            )
            if result.returncode == 0:
                if len(result.stdout):
                    t.rows[r][propIdx] = result.stdout.strip().count("true") == 1 # handles extraneous chars in result
            
        t.widths[propIdx] = max(t.widths[propIdx], len(str(t.rows[r][propIdx])))
    return t


# this can only happen after we've probed for files. 
# Treats RH-ports and hub-ports as the same.
@instrumentation
def initialize_hub_parent_port(inventory:Table) ->Table:
    for r in range(len(inventory.rows)):
        row = inventory.rows[r]
        if row[FieldIdx.IS_HUB]:
            row[FieldIdx.PPORT] = str(row[FieldIdx.USBID]).replace("-",".").split(".")[-2] # one-deeper than non-hubs
        else:
            row[FieldIdx.PPORT] = str(row[FieldIdx.USBID]).replace("-",".").split(".")[-1]

        inventory.widths[FieldIdx.PPORT] = max(len(row[FieldIdx.PPORT]) if row[FieldIdx.PPORT] is not None else 0, inventory.widths[FieldIdx.PPORT])

    return inventory


# I'm going to temporarily overwrite the order field with a sortable breadcrumb, sort, then revert
@instrumentation
def sort_ascending(inventory:Table) -> Table:
    # now that we set is_hub, use that to adjust the depth
    for r in inventory.rows:
        r[FieldIdx.DEPTH] = r[FieldIdx.DEPTH] + int(not r[FieldIdx.IS_HUB])

    for r in inventory.rows:
        r[FieldIdx.ROW] = fixed_width(r[FieldIdx.DEPTH],3,"0", False) + str(not r[FieldIdx.IS_HUB])[0] + "_" + r[FieldIdx.USBID] 

    inventory.rows = sorted(inventory.rows, key=lambda x: x[0])
    # renumber order field
    for i in range(len(inventory.rows)):
        inventory.rows[i][FieldIdx.ROW] = i
    return inventory


@instrumentation
def assign_uuid(inventory:Table) -> Table:
    for row in inventory.rows:
        row[FieldIdx.SDF_UUID] = uuid.uuid4().hex
    return inventory



@instrumentation
def add_dev_address(t:Table):
    for i in range(len(t.rows)):
        result = subprocess.run(
            CONSTANTS.SYSFS_ADDR.replace(CONSTANTS.PARAM1, t.rows[i][FieldIdx.USBID]),
            shell=True,
            text=True,
            capture_output=True
        )
        if result.returncode != 0:
            raise RuntimeError(pERROR(CONSTANTS.MSG_SHELL))
        t.rows[i][FieldIdx.ADDR] = result.stdout.strip()
        t.widths[FieldIdx.ADDR] = max(len(str(t.rows[i][FieldIdx.ADDR])) if t.rows[i][FieldIdx.ADDR] is not None else 0, t.widths[FieldIdx.ADDR])
    return t


@instrumentation
def add_dev_speed(t:Table):
    for i in range(len(t.rows)):
        result = subprocess.run(
            CONSTANTS.SYSFS_SPEED.replace(CONSTANTS.PARAM1, t.rows[i][FieldIdx.USBID]),
            shell=True,
            text=True,
            capture_output=True
        )
        if result.returncode != 0:
            raise RuntimeError(pERROR(CONSTANTS.MSG_SHELL))
        t.rows[i][FieldIdx.SPEED] = result.stdout.strip()
        t.widths[FieldIdx.SPEED] = max(len(str(t.rows[i][FieldIdx.SPEED])) if t.rows[i][FieldIdx.SPEED] is not None else 0, t.widths[FieldIdx.SPEED])
    return t


# -------------------- TREE OPERATIONS ------------------------


# strip off IFC_EPs because we're concerned about ports
# Once stripped, we also ensure the list is unique - eyelash
# more efficient than processing duplicates
@instrumentation
def filter_lsusb(lsusb:list) -> list:
    new_lsusb = set()
    for row in lsusb:
        row = "/".join(str(row).split("/")[:-1])
        if row.count("-"):
            new_lsusb.add(row)
    return list(new_lsusb)


# helper that uses the path delimiter to determine node type
def identify_node_type(s:str) -> tuple[str, NodeType]:
    index, char = next(((i, c) for i, c in enumerate(s) if c in {"-",":","."}), (None, None))
    if index == None:
        return (s, NodeType.BUS)
    else:
        if char == ":":
            ntype = NodeType.IFC_EP
        elif char == "-":
            ntype = NodeType.RH_PORT
        elif char == ".":
            ntype = NodeType.PORT
        else:
            print(pERROR(CONSTANTS.MSG_UNKNOWN_TOKEN) + " " + char)
        return (s[index+1:], ntype)


# creates a tree-representation of lsusb
@instrumentation
def build_tree(lsusb:list) -> tuple[TreeNode, dict]:
    index:dict = {}
    root = TreeNode(id="host", ntype=NodeType.HOST, path="/")
    if len(lsusb) == 0:
        print(CONSTANTS.MSG_NO_DEVICES)
        return root

    lsusb = filter_lsusb(lsusb)
    #print_lsusb(lsusb) # debug
    for dev in lsusb:
        if dev.startswith(CONSTANTS.SYSFS_PREFIX):
            dev = dev[len(CONSTANTS.SYSFS_PREFIX):]
            fields = dev.split("/")

            prev_id = ""
            curr_node = root
            for f in fields:
                s, t = identify_node_type(f.replace(prev_id,"", 1)) #
                tmp_node = curr_node.get_child(s)
                if tmp_node is not None:
                    curr_node = tmp_node
                elif len(s):
                    curr_node = curr_node.add_child(TreeNode(id=s, ntype=t, path=f))
                    index[f] = curr_node
                prev_id = f
    return (root, index)


# for fast lookups, collect/correlate USBIDs and rownumbers.
# assumes inventory's ROW field is sorted-ascending by DEPTH.
def index_hubs(inventory) -> dict:
    index:dict = {}
    for r in range(len(inventory.rows)):
        usbid:str = inventory.rows[r][FieldIdx.USBID]
        if inventory.rows[r][FieldIdx.IS_HUB]:
            index[usbid] = r                                                    # <---- doesnt hurt, but probably dont need
            # remove the port the hub is connected to, index that too
            usbid = usbid.split(".")
            usbid.pop() # returns popped item so concat on a separate line
            usbid = ".".join(usbid)
            index[usbid] = r
    return index


# Resolves ports/row references for internally/externally cascaded-hubs
# for each row in the table, use the index to find the tree-node corresponding to 
# the USBID then walk up the hierarchy until you find another row w/ a descriptor
@instrumentation
def update_inventory_refs(inventory:Table, nodeidx:dict, tree:TreeNode) -> Table:
    hubidx = index_hubs(inventory)

    for r in range(len(inventory.rows)):
        row = inventory.rows[r]
        parent:TreeNode = nodeidx[row[FieldIdx.USBID]].parent

        if not row[FieldIdx.IS_HUB]:
            row[FieldIdx.PPORT] = row[FieldIdx.CPORT]
        elif row[FieldIdx.IS_HUB]: # is actually the hub-descriptor so go up another level
            if parent.path.count("."):
                row[FieldIdx.PPORT] = parent.path.split(".")[-1] # preliminary. May be overridden by cascaded hub
            parent = parent.parent

        cascaded_port = False
        while parent is not None:
            # a parent/ancestor needs to be in the inventory
            if hubidx.get(parent.path,None) is not None:
                row[FieldIdx.PAROW] = hubidx[parent.path]
                if cascaded_port:
                    casecaded_port = str(row[FieldIdx.USBID]).removeprefix(parent.path + ".")
                    # pop trailing port if this is a hub
                    if row[FieldIdx.IS_HUB]:
                        casecaded_port = casecaded_port.split(".")
                        casecaded_port.pop()
                        casecaded_port = ".".join(casecaded_port)
                    row[FieldIdx.PPORT] = casecaded_port
                break
            elif parent.parent is None:
                break
            else:
                parent = parent.parent
                cascaded_port = True

        inventory.widths[FieldIdx.PPORT] = max(len(row[FieldIdx.PPORT]) if row[FieldIdx.PPORT] is not None else 0, inventory.widths[FieldIdx.PPORT])

    return inventory


# -------------------- FILE IO ------------------------


def sdf_alias(row:list, add_ext:bool = True) -> str:
    alias = str(row[FieldIdx.SDF_NAME]).split(".")[0]   # drop .sdf
    alias = alias + row[FieldIdx.SDF_UUID]              # add uuid 
    if add_ext: 
        alias = alias + ".sdf"                          # reattach .sdf
    return alias


# copies files from MSC devices into cache, but renames files to avoid name collisions
@instrumentation
def cache_sdf_files(inventory:Table): 
    for r in inventory.rows:
        if r[FieldIdx.MOUNTPT] is not None and r[FieldIdx.SDF_NAME] is not None \
        and len(str(r[FieldIdx.MOUNTPT])) and len(str(r[FieldIdx.SDF_NAME])):
            new_filename = CONSTANTS.OUTPUT_FOLDER + "/" + sdf_alias(r)
            shutil.copy2(r[FieldIdx.MOUNTPT] + "/" + r[FieldIdx.SDF_NAME], new_filename)


@instrumentation
def copy_port_labels() -> None:
    if not os.path.isdir(CONSTANTS.LABELS_FOLDER):
        print(pWARN(CONSTANTS.MSG_LABELS_MISSING.replace(CONSTANTS.PARAM1, CONSTANTS.LABELS_FOLDER)))
        return
    with os.scandir(CONSTANTS.LABELS_FOLDER) as port_labels: # needs to be separate from any() to avoid premature file enumeration
        if any(port_labels):
            shutil.copytree(CONSTANTS.LABELS_FOLDER, CONSTANTS.OUTPUT_FOLDER, dirs_exist_ok=True)


@instrumentation
def copy_meshes(inventory:Table) -> None:
    for r in inventory.rows:
        if os.path.isdir(r[FieldIdx.MOUNTPT] + CONSTANTS.MESHES_FOLDER):
            shutil.copytree(r[FieldIdx.MOUNTPT] + CONSTANTS.MESHES_FOLDER, CONSTANTS.OUTPUT_FOLDER + CONSTANTS.MESHES_FOLDER, dirs_exist_ok=True)


def save_feedback(banner:str, pbuffer:str, filename:str, cout:bool = True):
    if cout:
        print("\r\n" +  pINFO(banner) + "\r\n" + ("-" * len(banner)) + "\r\n" + pbuffer)

    # exploit the shell to instantiate a filename with a timestamp 
    result = subprocess.run(CONSTANTS.GET_SAVE_FILEPATH \
        .replace(CONSTANTS.PARAM1, filename), shell=True, text=True, capture_output=True)
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(pERROR(CONSTANTS.MSG_SHELL))
    filepath:str = result.stdout.strip()
    with open(filepath, "w", encoding="utf-8") as file:
        file.write(pbuffer)


# -------------------- DEBUG ------------------------
# Because tshark writes random whitespace and numbers to the 
# terminal, I cant just print as I go but need to accumulate
# content, pad wit CRLF, and write all at once to print a cohesive
# block of text.

def print_lsusb(lsusb:list) -> None:
    pbuffer:str = ""
    for el in lsusb:
        pbuffer = pbuffer + el + "\r\n"
    save_feedback("USB devices visible in sysfs", pbuffer, "lsusb")


def print_dev2blk(dev2blk:dict) -> None:
    pbuffer:str = ""
    for key, value in dev2blk.items():
        pbuffer = pbuffer + key + " has block device id " + value + "\r\n"
    save_feedback("USB MSC devices visible in sysfs", pbuffer, "blocks")


# accummulate content and print at once since tshark (even when -q)
# inserts random whitespace that messes up formatting
def print_inventory(inventory:Table) -> None:
    pbuffer:str = ""
    # print headers
    for i in range(inventory.COLUMNS):
        pbuffer += fixed_width(inventory.headers[i], inventory.widths[i]) + "| "
    # print header/data divider
    pbuffer = pbuffer + "\r\n"
    for i in range(inventory.COLUMNS):
        pbuffer += ("-" * inventory.widths[i]) + "| "
    # print rows
    for row in inventory.rows:
        tmpline = "\r\n"
        for i in range(inventory.COLUMNS):
            tmpline += fixed_width(str(row[i]), inventory.widths[i]) + "| "
        pbuffer = pbuffer + tmpline
    save_feedback("FRR inventory", pbuffer, "inventory")


def print_timing():
    global g_timing_results
    save_feedback("Instrumentation", g_timing_results, "resource_utilization", False)


def show_help():
    _s = "ABOUT"
    pbuffer:str = "\r\n" + pINFO(_s) + "\r\n" + ("-" * len(_s)) + "\r\n"
    pbuffer = pbuffer + f"Self Image v{CONSTANTS.VERSION}. (c) Noel Khan 1/1/2026\r\n"
    pbuffer = pbuffer +  "SYNTAX: python3 self_image.py [CLI_MODE]\r\n"
    pbuffer = pbuffer +  "  where CLI_MODE: {-1 = ONE_SHOT (default), -b = BENCHMARK}\r\n"
    print(pbuffer)


# ----------------- EXPERIMENTAL DATA COLLECTION HELPERS ----------------------

# Popen does not wait for a process to finish
def run_systemcall(s:str, wait:bool = True, checkerror:bool = True) -> str:
    try:
        if wait:
            result = subprocess.run(s, shell=True,text=True, capture_output=True)
            if checkerror and result.returncode != 0:
                raise RuntimeError(pERROR(CONSTANTS.MSG_SHELL))
        else:
            result = subprocess.Popen(s, shell=True, text=True)
            if checkerror and result.returncode is not None:
                raise RuntimeError(pERROR(CONSTANTS.MSG_SHELL))
        if result.stdout is not None:
            return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"STDOUT:\n{e.stdout}")
        print(f"STDERR:\n{e.stderr}")


# ----------------- FEEDBACK HELPERS ----------------------


def fixed_width(s: str, w: int, c: str = " ", left_align: bool = True) -> str:
    if len(str(s)) > w:
        s = str(s)[0:(w-2)] + ".."
    return str(s).ljust(w, c) if left_align else str(s).rjust(w, c)


def pERROR(s:str) -> str:
    return CONSTANTS.CLR_RED + s + CONSTANTS.CLR_RESET


def pWARN(s:str) -> str:
    return CONSTANTS.CLR_ORANGE + s + CONSTANTS.CLR_RESET


def pINFO(s:str) -> str:
    return CONSTANTS.CLR_YELLOW + s + CONSTANTS.CLR_RESET


# -------------------- VALIDATION ------------------------

# TODO: check for negative depth
@instrumentation
def validate_inventory(inventory) -> bool:
    _s = "\nValidation"
    pbuffer:str = "\r\n" + pINFO(_s) + "\r\n" + ("-" * len(_s)) + "\r\n"
    Errors = 0
    prev = 0 # was -1 when depth was base0
    i = 0

    # check for negative depths
    i = 0
    for r in inventory.rows:
        if r[FieldIdx.DEPTH] < 0:
            pbuffer = pbuffer + pWARN(CONSTANTS.MSG_DEPTH_NEGATIVE.replace(CONSTANTS.PARAM1, str(r[FieldIdx.ROW]))) + "\r\n"
        i = i + 1

    # check for zero depth hubs
    i = 0
    for r in inventory.rows:
        if r[FieldIdx.DEPTH] == 0 and r[FieldIdx.IS_HUB]:
            pbuffer = pbuffer + pWARN(CONSTANTS.MSG_ZERODEPTH_HUB.replace(CONSTANTS.PARAM1, str(r[FieldIdx.ROW]))) + "\r\n"
        i = i + 1

    # Check for jumps in depth, which indicate cascaded-hubs
    for r in inventory.rows:
        if r[FieldIdx.DEPTH] - prev > 1: 
            pbuffer = pbuffer + pWARN(CONSTANTS.MSG_DEPTH_JUMP.replace(CONSTANTS.PARAM1, str(r[FieldIdx.ROW]))) + "\r\n"
        prev = r[FieldIdx.DEPTH]
        i = i + 1
   
    # ensure at least one row is None
    buses:dict = {} # key=BUSID, val=RowID/Order
    for r in inventory.rows:
        # I'm assuming there are no intermediate descriptionless hubs
        if r[FieldIdx.DEPTH] == 0: 
            if buses.get(r[FieldIdx.USBID]) == None:
                buses[r[FieldIdx.USBID]] = r[FieldIdx.ROW]
    if len(buses):
        # affirmation 
        for key, value in buses.items():
            if inventory.rows[value][FieldIdx.PAROW] is not None:
                pbuffer = pbuffer + pWARN(CONSTANTS.MSG_AFFIRM_PAROW.replace(CONSTANTS.PARAM1, str(r[FieldIdx.ROW]))) + "\r\n"
        # negation
        for r in inventory.rows:
            if buses.get(r[FieldIdx.USBID]) is None and r[FieldIdx.PAROW] is None:
                pbuffer = pbuffer + pERROR(CONSTANTS.MSG_NEGATE_PAROW.replace(CONSTANTS.PARAM1, str(r[FieldIdx.ROW]))) + "\r\n"
                Errors = Errors + 1

    # negation: ensure all row.PAROW are NOT None
    count = 0
    for r in inventory.rows:
        if r[FieldIdx.PAROW] is None: 
            count = count + 1
    if count == len(inventory.rows):
        pbuffer = pbuffer + pWARN(CONSTANTS.MSG_DISJOINT_MODEL) + "\r\n"
        Errors = Errors + 1
        

    pbuffer = pbuffer + "done"
    print(pbuffer)
    return (Errors == 0)


# -------------------- MODEL BUILDER ------------------------


# handles rhizome topology
@instrumentation
def generate_self_image(inventory:Table):
    body_parts:str = ""
    for i in range(len(inventory.rows)):
        _name = sdf_alias(inventory.rows[i], False) #  extension is built-into the markup
        if inventory.rows[i][FieldIdx.DEPTH] <= 1: # was == 0 when base0, now == 1 for base1
            _part = CONSTANTS.SDF_FIRST_PART.replace(CONSTANTS.PARAM3, _name)
            # in the case of a rhizome topology w/multiple top-level elements, pick random XY position
            _part = _part.replace(CONSTANTS.PARAM1, str(random.uniform(0, 5)))
            _part = _part.replace(CONSTANTS.PARAM2, str(random.uniform(0, 5)))
        else:
            # get parent name
            _part = CONSTANTS.SDF_PART.replace(CONSTANTS.PARAM1,_name)
            _part = _part.replace(CONSTANTS.PARAM3, "0")
            _pport = inventory.rows[i][FieldIdx.PPORT]
            # get child name
            if inventory.rows[i][FieldIdx.PAROW] is not None:
                _name = sdf_alias(inventory.rows[inventory.rows[i][FieldIdx.PAROW]], False)
                _name = _name + "::P" + _pport
                _part = _part.replace(CONSTANTS.PARAM2, _name)
            else:
                print("how did you get here?")
        # append part
        body_parts = body_parts + _part
    
    body_parts = CONSTANTS.SDF_TEMPLATE.replace(CONSTANTS.PARAM1, body_parts)
    with open(CONSTANTS.OUTPUT_FOLDER + CONSTANTS.OUTPUT_FILE, "w", encoding="utf-8") as file:
        file.write(body_parts)
    return


# -------------------- MAIN ------------------------


@instrumentation
def main(cli_mode:CLI_MODE):

    # cleaning AFTER a run ensures the next run (as in right now) begins with a clean diaper
    if CONSTANTS.ADD_INSTRUMENTATION and not CONSTANTS.IS_DYNAMIC_ASSEMBLY:
        run_systemcall(CONSTANTS.CLEAR_KERNEL_LOG) 
    # we can NOT capture traffic in benchmarking mode due to tshark automation that adds a delay when stopping
    # tshark. If there's an ungraceful termination, we end up with a corrupt file that we can't gather stats on
    if CONSTANTS.ADD_INSTRUMENTATION and cli_mode != CLI_MODE.BENCHMARK:
        run_systemcall(CONSTANTS.ENABLE_WIRESHARK)
        CONSTANTS.TSHARK_INTERFACE = run_systemcall(CONSTANTS.GET_TSHARK_IFCS) # override manual setting
        run_systemcall(CONSTANTS.LOG_TSHARK_BINARY .replace(CONSTANTS.PARAM1, CONSTANTS.TSHARK_INTERFACE), False)
        run_systemcall(CONSTANTS.LOG_TSHARK_SUMMARY.replace(CONSTANTS.PARAM1, CONSTANTS.TSHARK_INTERFACE), False)
        run_systemcall(CONSTANTS.LOG_TSHARK_DETAILS.replace(CONSTANTS.PARAM1, CONSTANTS.TSHARK_INTERFACE), False)

    # wait in this loop until some nonzero number of MSC are attached. 
    # This allows us to start recording USB traffic before device attachment.
    prior_msc_count = 0
    deadline = time.time() + CONSTANTS.ATTACHMENT_TIMEOUT
    while (time.time() < deadline or prior_msc_count == 0):
        # gather usb info
        lsusb   = find_usb_devices()
        print_lsusb(lsusb)

        # gather storage info
        dev2blk = find_block_devices(lsusb)
        blk2mnt = find_mountpoints(dev2blk)
        blk2mnt = sanitize_blk2mnt(blk2mnt)
        dev2blk = sanitize_dev2blk(dev2blk, blk2mnt)
        # gather sensor info
        dev2acm = find_acm_devices(lsusb)

        if not CONSTANTS.IS_DYNAMIC_ASSEMBLY:
            break
        elif prior_msc_count != len(dev2blk.items()):
            prior_msc_count = len(dev2blk.items())
            time.sleep(CONSTANTS.ENUMERATION_TIMEOUT)
            deadline = time.time() + CONSTANTS.ATTACHMENT_TIMEOUT # restart timer
    # end while

    check_block_devices(dev2blk)
    print_dev2blk(dev2blk)

    # join device and storage info then check for self-descriptions
    inventory = initialize_inventory(dev2blk, blk2mnt, dev2acm)
    inventory = add_dev_address(inventory)
    inventory = add_dev_speed(inventory)
    inventory = probe_for_file(inventory, CONSTANTS.GET_SDF_FILE, FieldIdx.SDF_NAME) # *.sdf
    inventory = probe_for_file(inventory, CONSTANTS.GET_PJS_FILE, FieldIdx.PJS_NAME) # *.json
    inventory = probe_pjs_for_true(inventory, CONSTANTS.PJS_HUB_ATR, FieldIdx.IS_HUB, False) 
    inventory = sort_ascending(inventory)
    inventory = assign_uuid(inventory)
    #print_inventory(inventory)

    # build tree data structure to robustly identify topological parents
    tree, nidx  = build_tree(lsusb)
    inventory = update_inventory_refs(inventory, nidx, tree) 
    print_inventory(inventory)

    if validate_inventory(inventory): # must follow print_inventory for messages to appear after table
        generate_self_image(inventory)
        cache_sdf_files(inventory)
        copy_port_labels()          # N/A to all models and NOT on stored device (but should be TODO)
        copy_meshes(inventory)      # aids visualization but technically not required.

    # Teardown activities
    if CONSTANTS.ADD_INSTRUMENTATION:
        run_systemcall(CONSTANTS.SAVE_KERNEL_LOG)
        # Dynamic assembly involves random operator/timeout delays so timing doesnt make sense
        if not CONSTANTS.IS_DYNAMIC_ASSEMBLY:
            print_timing()
        # Apart from benchmarking, we record traffic, so stop recording and generate a stats file
        if cli_mode != CLI_MODE.BENCHMARK:
            run_systemcall(CONSTANTS.KILL_TSHARK_PROCS, wait=True, checkerror=False)
            time.sleep(3) # allow procs to end
            run_systemcall(CONSTANTS.GET_TSHARK_STATS, checkerror=False)


# -------------------- EXECUTION MODES ------------------------


# |--------------------------||--------------------------|
# |           INPUTS         ||         OUTPUTS          |
# |----------------|---------||------|-------|-----------|
# |DYNAMIC ASSEMBLY|CLI_MODE ||Timing|Traffic|Kernel Logs|
# |----------------|---------||------|-------|-----------|
# |       F        | ONESHOT ||  T   |   T   |     T     |
# |       T        | ONESHOT ||  F   |   T   |     T     |
# |       F        |BENCHMARK||  T   |   F   |     T     |
# |       T        |BENCHMARK||  F   |   F   |     T     |  <-- INVALID
# |----------------|---------||------|-------|-----------|


# housecleaning
show_help()
shutil.rmtree(CONSTANTS.OUTPUT_FOLDER, ignore_errors=True)
os.makedirs(CONSTANTS.OUTPUT_FOLDER, exist_ok=True)
if CONSTANTS.ADD_INSTRUMENTATION:
    tracemalloc.start()


# determine run mode
cli_mode = CLI_MODE.ONE_SHOT # default
if len(sys.argv) > 1:
    if sys.argv[1] == "-b" or sys.argv[1] == "-B":
        cli_mode = CLI_MODE.BENCHMARK
        if CONSTANTS.IS_DYNAMIC_ASSEMBLY:
            raise RuntimeError(CONSTANTS.MSG_INVALID_CONFIG)
# CLI args only used to determine run mode, which we've now done so clear the args
sys.argv = [sys.argv[0]] 


if cli_mode == CLI_MODE.ONE_SHOT:
    main(cli_mode)
elif cli_mode == CLI_MODE.BENCHMARK:
    total_time = timeit.timeit(stmt="main(cli_mode)", setup="", globals=globals(), number=CONSTANTS.BENCHMARK_RUNS)
    save_feedback(f"Average cycle time over {CONSTANTS.BENCHMARK_RUNS} runs", f"{total_time / CONSTANTS.BENCHMARK_RUNS:03.9f} seconds", "avg_runtime")

