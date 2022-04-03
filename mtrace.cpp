/*
 * Copyright River Loop Security 2020-2022 All Rights Reserved.
 * This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <functional>
#include <list>
#include <map>
#include <set>
#include <utility>
#include <sstream>
#include <string>

uint64_t object_count;

std::map<ADDRINT, uint64_t> by_size;
std::map<ADDRINT, uint64_t> by_callstack;
std::map<std::pair<ADDRINT, ADDRINT>, uint64_t> by_both;

std::ostream *info = &std::cerr;
std::ostream *out = &std::cout;
PIN_LOCK lock;

std::hash<std::string> str_hash;
// std::list<std::pair<img_hash, offset>>
std::list<std::pair<ADDRINT, ADDRINT>> callstack;
std::map<ADDRINT, std::string> img_hashes;
std::set<ADDRINT> callstack_hashes;

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for mtrace output");

BOOL flag_list_allocs;
KNOB<BOOL> knob_list_allocs(KNOB_MODE_WRITEONCE,  "pintool",
    "l", "0", "list allocs");

BOOL flag_size_histogram;
KNOB<BOOL> knob_size_histogram(KNOB_MODE_WRITEONCE,  "pintool",
    "y", "0", "alloc histogram based on size");

BOOL flag_type_histogram;
KNOB<BOOL> knob_type_histogram(KNOB_MODE_WRITEONCE,  "pintool",
    "t", "0", "alloc histogram based on callstack");

BOOL flag_obj_count;
KNOB<BOOL> knob_obj_count(KNOB_MODE_WRITEONCE,  "pintool",
    "c", "0", "count of allocations");

BOOL flag_strict_histogram;
KNOB<BOOL> knob_strict_histogram(KNOB_MODE_WRITEONCE,  "pintool",
    "x", "0", "alloc histogram based on callstack and size");

BOOL flag_pc_trace;
KNOB<BOOL> knob_pc_trace(KNOB_MODE_WRITEONCE,  "pintool",
    "i", "0", "log the basic block head address");

BOOL flag_func_trace;
KNOB<BOOL> knob_func_trace(KNOB_MODE_WRITEONCE,  "pintool", 
    "f", "0", 
    "log memory related functions (malloc, mmap, brk, etc.) as they are hit");

BOOL flag_describe_callstack;
KNOB<BOOL> knob_describe_callstack(KNOB_MODE_WRITEONCE,  "pintool",
    "cs", "0", "describe the callstack hashes");

BOOL flag_rw_trace;
KNOB<BOOL> knob_rw_trace(KNOB_MODE_WRITEONCE,  "pintool",
    "b", "0", "trace reads and writes");

std::string flag_image;
KNOB<std::string> knob_image(KNOB_MODE_WRITEONCE,  "pintool",
    "m", "", "image name to restrict rw tracing to");

ADDRINT flag_filter;
KNOB<ADDRINT> knob_filter(KNOB_MODE_WRITEONCE,  "pintool",
    "e", "0", "callstack type to focus on");

ADDRINT flag_getchr;
KNOB<ADDRINT> knob_getchr(KNOB_MODE_WRITEONCE, "pintool",
    "g", "0", "address of lexer::getChar function in libpoppler");

ADDRINT flag_fs_getchr;
KNOB<ADDRINT> knob_fs_getchr(KNOB_MODE_WRITEONCE, "pintool",
    "j", "0", "address of filestream::getChar function in libpoppler");

std::string flag_match_sequence;
int flag_match_len;
int flag_match_pos;
KNOB<std::string> knob_match_sequence(KNOB_MODE_WRITEONCE,  "pintool",
    "ms", "", "sequence to match before enabling rw tracing");

std::string flag_inference_file;
KNOB<std::string> knob_inference_file(KNOB_MODE_WRITEONCE,  "pintool",
    "n", "", "inference type definition file\nof the format -\n"
    "t/name/size\nm/off/name/size[/h:type]");

std::string flag_rw_filter_file;
KNOB<std::string> knob_rw_filter_file(
    KNOB_MODE_WRITEONCE,  "pintool", 
    "r", "", "file containing a list of addresses in hex"
    " of reads and writes to trace");
std::set<ADDRINT> rw_whitelist;

INT32 Usage() {
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

VOID log_bb(ADDRINT img_hash, ADDRINT head) {
    *out << img_hash << "@" <<  head << std::endl;
}

class Access {
public:
    Access(ADDRINT img_hash, ADDRINT at, ADDRINT offset, 
        std::string type, ADDRINT size) : 
        img_hash(img_hash), at(at), offset(offset), type(type), size(size) { }
    ADDRINT img_hash; 
    ADDRINT at; 
    ADDRINT offset;
    std::string type;
    ADDRINT size; 

    std::string to_string() {
        std::stringstream ss;
        ss << this;
        return ss.str();
    }
};

std::ostream& operator<<(std::ostream &os, const Access &a) {
    os << a.type << "/" << a.offset << "/" << a.size;
    os << "/" << a.img_hash << "/" << a.at << ";";
    return os;
}

class Object {
public:
    Object(ADDRINT callstack, ADDRINT start, ADDRINT size) : 
        callstack(callstack), start(start), size(size) { }
    ADDRINT callstack;
    ADDRINT start; 
    ADDRINT size; 
    std::list<Access *> accesses;
    // [rw](off,size);

    std::string to_string() {
        std::stringstream ss;
        for (Access *a : accesses) {
            ss << *a;
        }
        return ss.str();
    }
};

class Type {
public:
    Type(ADDRINT callstack, ADDRINT size) : 
        callstack(callstack), size(size) { }
    ADDRINT callstack;
    ADDRINT size; 
    std::map<std::string, uint64_t> patterns;
    std::list<Object *> objects;
};

class DwarfMember {
public:
    DwarfMember() { 
        offset = -1;
        name = "";
        size = -1;
        hint = "";
    }
    DwarfMember(
        uint64_t offset, std::string name, uint64_t size, std::string hint) : 
        offset(offset), name(name), size(size), hint(hint) { }
    uint64_t offset;
    std::string name;
    uint64_t size;
    std::string hint;
    void print() {
        std::cout << "  off:  " << offset << std::endl;
        std::cout << "  name: " << name << std::endl;
        std::cout << "  size: " << size << std::endl;
        std::cout << "  hint: " << hint << std::endl;
        std::cout << "  --" << std::endl;
    }
};

class DwarfType {
public:
    DwarfType() { 
        name = "";
        size = -1;
    }
    DwarfType(
        std::string name, uint64_t size) : 
        name(name), size(size) { }
    std::string name;
    uint64_t size;
    std::map<uint64_t, DwarfMember*> members;
    void print() {
        std::cout << "name: " << name << std::endl;
        std::cout << "size: " << size << std::endl;
        for (std::pair<uint64_t, DwarfMember*> it : members) {
            it.second->print();
        }
    }
};

// by size
std::map<uint64_t, DwarfType*> dwarf_types;

class ObjectTracker {
private:
    bool finalized = false;
public:
    ObjectTracker() {}
    ADDRINT low = 0xffffffffffffffff;
    ADDRINT high = 0;

    // <base, size>, object
    std::map<std::pair<ADDRINT, ADDRINT>, Object*> ranges;
    // <callstack, size>, type
    std::map<std::pair<ADDRINT, ADDRINT>, Type*> types;

    void addObject(ADDRINT callstack, ADDRINT start, ADDRINT size) {
        if (start < low) {
            low = start;
        }

        if (start+size > high) {
            high = start+size;
        }

        ranges[std::make_pair(start, size)] = new Object(callstack, start, size);
    }

    Object* findObject(ADDRINT addr) {
        if (addr < low || addr > high) {
            return NULL;
        }

        std::map<std::pair<ADDRINT, ADDRINT>, Object*>::iterator it;
        for (it=ranges.begin(); it!=ranges.end(); ++it) {
            std::pair<ADDRINT, ADDRINT> bsz = it->first;
            if (bsz.first <= addr && (bsz.first + bsz.second) > addr) {
                return it->second;
            }
        }

        return NULL;
    }

    void recordAccess(
        ADDRINT img_hash, ADDRINT at, ADDRINT addr, 
        std::string type, ADDRINT size) 
    {
        Object *o = findObject(addr);
        if (o == NULL) return;

        ADDRINT off = addr - o->start;

        o->accesses.push_back(new Access(img_hash, at, off, type, size));
    }

    void removeObject(ADDRINT addr) {
        Object *o = findObject(addr);
        if (o == NULL) return;
        
        std::pair<ADDRINT, ADDRINT> ok = std::make_pair(o->start, o->size);
        ranges.erase(ok);

        _recordObject(o);
    }

    void _recordObject(Object *o) {
        if (o == NULL) return;

        if (o->to_string().size() == 0) return;

        std::pair<ADDRINT, ADDRINT> tk = std::make_pair(o->callstack, o->size);
        std::map<std::pair<ADDRINT, ADDRINT>, Type*>::iterator it = 
            types.find(tk);

        if (it == types.end()) {
            types[tk] = new Type(o->callstack, o->size);
        }

        types[tk]->patterns[o->to_string()] += 1;
        types[tk]->objects.push_back(o);
    }

    void finalize() {
        if (finalized) return;
        finalized = true;

        std::map<std::pair<ADDRINT, ADDRINT>, Object*>::iterator it;
        for (it=ranges.begin(); it!=ranges.end(); ++it) {
            if (it->second == NULL) continue;
            _recordObject(it->second);
        }
    }
};

ObjectTracker *objectTracker;

ADDRINT hash_img(std::string img_name) {
    ADDRINT img_hash = (ADDRINT)str_hash(img_name);
    size_t sz = img_hashes.size();
    img_hashes[img_hash] = img_name;
    if (img_hashes.size() > sz && (
        flag_func_trace || flag_pc_trace || flag_describe_callstack)) {
        *out << img_hash << ":" << img_name << std::endl;
    }
    return img_hash;
}

// Handler for memory reads.
VOID pre_read_callback(
    ADDRINT img_hash, ADDRINT at, ADDRINT read_ea, UINT32 read_size) {
    if (flag_match_pos < flag_match_len) return;
    objectTracker->recordAccess(img_hash, at, read_ea, "r", read_size);
}

// Handler for memory writes, pre execution to get effective address.
VOID pre_write_callback(
    ADDRINT img_hash, ADDRINT at, ADDRINT write_ea, UINT32 write_size) {
    if (flag_match_pos < flag_match_len) return;
    objectTracker->recordAccess(img_hash, at, write_ea, "w", write_size);
}

VOID fs_getchr_pre(ADDRINT fsThis) {
    // capture this
    // pos = *(this + 0x158) + *(this + 0x148) - (this + 0x41)
    PIN_GetLock(&lock, 0);
    ADDRINT bufPos = 0;
    ADDRINT bufPtr = 0;
    ADDRINT buf = fsThis+0x41;
    PIN_SafeCopy(&bufPos, (ADDRINT *)(fsThis+0x158), 8);
    PIN_SafeCopy(&bufPtr, (ADDRINT *)(fsThis+0x148), 8);
    PIN_ReleaseLock(&lock);
    // ADDRINT total = 0;
    // *out << "this " << std::hex << fsThis << std::endl;
    // *out << "pos " << bufPos << std::endl;
    // *out << "ptr " << bufPtr << std::endl;
    // *out << "buf " << buf << std::endl << std::endl;
    *out << "fpos " << bufPos + (bufPtr - buf) << std::endl;
}

VOID fs_getchr_post(ADDRINT rtn_val) {
    uint8_t ch = (uint8_t)rtn_val;
    *out << "fch " << ch << std::endl;  
}

VOID getchr_post(ADDRINT rtn_val) {
    uint8_t ch = (uint8_t)rtn_val;
    *out << "dch " << ch << std::endl; // << " (" << ret_addr - base << ")" << std::endl;
    if (flag_match_pos < flag_match_len) {
        if (ch == flag_match_sequence[flag_match_pos]) {
            flag_match_pos++;
        } else {
            flag_match_pos = 0;
        }
    }
}

// Handler for routines, filters on name.
VOID routine_callback(RTN rtn, VOID *v) {
    RTN_Open(rtn);

    ADDRINT addr = RTN_Address(rtn);
    IMG img = IMG_FindByAddress(addr);
    if (!IMG_Valid(img)) return;

    std::string name = IMG_Name(img);
    if (name.find(flag_image) == std::string::npos) {
        RTN_Close(rtn);
        return;  
    }

    ADDRINT img_hash = hash_img(name);
    ADDRINT base = IMG_LowAddress(img);
    ADDRINT rel_addr = addr - base;

    if (flag_getchr != 0 && rel_addr == flag_getchr) {
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getchr_post,
            // IARG_PTR, new std::string(RTN_Name(rtn)),
            IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    }

    if (flag_fs_getchr != 0 && rel_addr == flag_fs_getchr) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fs_getchr_pre,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fs_getchr_post,
            IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    }

    if (!flag_rw_trace) {
        RTN_Close(rtn);
        return;
    }

    // For each instruction, add hooks.
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        ADDRINT ins_off = INS_Address(ins) - base;
        if (rw_whitelist.size() > 0 && rw_whitelist.count(ins_off) == 0) {
            continue;
        }

        if(INS_IsMemoryRead(ins)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)pre_read_callback,
                IARG_ADDRINT, img_hash, IARG_ADDRINT, ins_off, 
                IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
        }

        if (INS_IsMemoryWrite(ins)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)pre_write_callback, 
                IARG_ADDRINT, img_hash, IARG_ADDRINT, ins_off, 
                IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
        }
    }

    RTN_Close(rtn);
}

VOID trace_callback(TRACE trace, VOID *v) {
    if (!flag_pc_trace) return;
    ADDRINT addr = TRACE_Address(trace);

    IMG img = IMG_FindByAddress(addr);
    if (!IMG_Valid(img)) return;
    ADDRINT base = IMG_LowAddress(img);

    ADDRINT img_hash = hash_img(IMG_Name(img));

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        BBL_InsertCall(
            bbl, IPOINT_BEFORE, (AFUNPTR)log_bb, 
            IARG_ADDRINT, img_hash,
            IARG_ADDRINT, BBL_Address(bbl) - base, 
            IARG_END);
    }
}

ADDRINT hash_callstack() {
    ADDRINT h = 0;
    for (std::pair<ADDRINT, ADDRINT> p : callstack) {
        h ^= p.first >> 33;
        h *= 0xff51afd7ed558ccdL;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53L;
        h ^= h >> 33;

        h ^= p.second >> 33;
        h *= 0xff51afd7ed558ccdL;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53L;
        h ^= h >> 33;
    }

    size_t sz = callstack_hashes.size();
    callstack_hashes.insert(h);

    if (flag_describe_callstack && callstack_hashes.size() > sz) {
        for (std::pair<ADDRINT, ADDRINT> p : callstack) {
            *out << h << "=" << p.first << "@" << p.second << std::endl;
        }
    }
    return h;
}

VOID callstack_pre(
    std::string img_name, ADDRINT img_hash, ADDRINT start) {
    callstack.push_back(std::make_pair(img_hash, start));
}

VOID callstack_post() {
    if (callstack.size() < 1) return;
    callstack.pop_back();
}

VOID instruction_callback(INS ins, VOID *v) {
    bool call = INS_IsCall(ins);
    bool ret = INS_IsRet(ins);
    if (!call && !ret) return;


    if (call) {
        ADDRINT addr = INS_Address(ins);
        ADDRINT next = INS_NextAddress(ins);
        IMG img = IMG_FindByAddress(addr);
        if (!IMG_Valid(img)) return;
        ADDRINT base = IMG_LowAddress(img);
        // ADDRINT rel_addr = addr - base;
        ADDRINT rel_next = next - base;

        std::string img_name = IMG_Name(img);
        ADDRINT img_hash = hash_img(img_name);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)callstack_pre,
            IARG_PTR, new std::string(img_name),
            IARG_ADDRINT, img_hash,
            IARG_ADDRINT, rel_next,
            IARG_END);
    } else if(ret) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)callstack_post,
            IARG_END);
    }
}

ADDRINT _cs;
ADDRINT _size;

VOID pre_malloc(ADDRINT size) {
    object_count++;
    ADDRINT cs = hash_callstack();
    by_size[size]++;
    by_callstack[cs]++;
    by_both[std::make_pair(cs, size)]++;
    if (flag_list_allocs) {
        *out << "(" << size << "," << cs << ")" << std::endl;
    }
    _cs = cs;
    _size = size;
}

VOID post_malloc(ADDRINT base) {
    if (flag_filter != 0 && _cs != flag_filter) return;
    objectTracker->addObject(_cs, base, _size);
}

// Handler for free().
VOID pre_free(ADDRINT base) {
    objectTracker->removeObject(base);
}

VOID func_trace(std::string img_name, std::string rtn_name) {
    *out << img_name << "::" << rtn_name << std::endl;
}

VOID ftrace_pre_malloc(ADDRINT size) {
    ADDRINT cs = hash_callstack();
    *out << "(" << cs << ": malloc(" << size << ") = ";
}

VOID ftrace_post_malloc(ADDRINT retval) {
    *out << retval << ")" << std::endl;
}

VOID ftrace_pre_free(ADDRINT addr) {
    ADDRINT cs = hash_callstack();
    *out << "(" << cs << ": free(" << addr << ") = void)" << std::endl;
}

VOID ftrace_pre_brk(ADDRINT addr) {
    ADDRINT cs = hash_callstack();
    *out << "(" << cs << ": brk(" << addr << ") = ";
}

VOID ftrace_post_brk(ADDRINT retval) {
    *out << retval << ")" << std::endl;
}

VOID ftrace_pre_sbrk(ADDRINT inc) {
    ADDRINT cs = hash_callstack();
    *out << "(" << cs << ": sbrk(" << inc << ") = ";
}

VOID ftrace_post_sbrk(ADDRINT retval) {
    *out << retval << ")" << std::endl;
}

VOID ftrace_pre_mmap(ADDRINT addr, ADDRINT length, ADDRINT prot, 
    ADDRINT flags, ADDRINT fd, ADDRINT offset) {
    ADDRINT cs = hash_callstack();
    *out << "(" << cs << ": mmap(" << 
        addr << "," <<
        length << "," <<
        prot << "," <<
        flags << "," <<
        fd << "," <<
        offset << ") = ";
}

VOID ftrace_post_mmap(ADDRINT retval) {
    *out << retval << ")" << std::endl;
}

VOID ftrace_pre_munmap(ADDRINT addr, ADDRINT length, ADDRINT prot, 
    ADDRINT flags, ADDRINT fd, ADDRINT offset) {
    ADDRINT cs = hash_callstack();
    *out << "(" << cs << ": munmap(" << addr << "," << length << ") = ";
}

VOID ftrace_post_munmap(ADDRINT retval) {
    *out << retval << ")" << std::endl;
}

VOID image_callback(IMG img, VOID *v) {
    if (!IMG_Valid(img)) return;
    std::string img_name = IMG_Name(img);
    if (flag_func_trace) {
        // malloc
        RTN malloc_rtn = RTN_FindByName(img, "malloc"); 
        if (RTN_Valid(malloc_rtn)) {
            RTN_Open(malloc_rtn);
            RTN_InsertCall(malloc_rtn, IPOINT_BEFORE, 
                (AFUNPTR)ftrace_pre_malloc,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
            RTN_InsertCall(malloc_rtn, IPOINT_AFTER, 
                (AFUNPTR)ftrace_post_malloc,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
            RTN_Close(malloc_rtn);
        }

        // free
        RTN free_rtn = RTN_FindByName(img, "free"); 
        if (RTN_Valid(free_rtn)) {
            RTN_Open(free_rtn);
            RTN_InsertCall(free_rtn, IPOINT_BEFORE, 
                (AFUNPTR)ftrace_pre_free,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
            RTN_Close(free_rtn);
        }

        // mmap
        RTN mmap_rtn = RTN_FindByName(img, "mmap"); 
        if (RTN_Valid(mmap_rtn)) {
            RTN_Open(mmap_rtn);
            RTN_InsertCall(mmap_rtn, IPOINT_BEFORE, 
                (AFUNPTR)ftrace_pre_mmap,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 4, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 5, 
                IARG_END);
            RTN_InsertCall(mmap_rtn, IPOINT_AFTER, 
                (AFUNPTR)ftrace_post_mmap,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
            RTN_Close(mmap_rtn);
        }

        // munmap
        RTN munmap_rtn = RTN_FindByName(img, "munmap"); 
        if (RTN_Valid(munmap_rtn)) {
            RTN_Open(munmap_rtn);
            RTN_InsertCall(munmap_rtn, IPOINT_BEFORE, 
                (AFUNPTR)ftrace_pre_munmap,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                IARG_END);
            RTN_InsertCall(munmap_rtn, IPOINT_AFTER, 
                (AFUNPTR)ftrace_post_munmap,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
            RTN_Close(munmap_rtn);
        }

        // brk
        RTN brk_rtn = RTN_FindByName(img, "brk"); 
        if (RTN_Valid(brk_rtn)) {
            RTN_Open(brk_rtn);
            RTN_InsertCall(brk_rtn, IPOINT_BEFORE, 
                (AFUNPTR)ftrace_pre_brk,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
            RTN_InsertCall(brk_rtn, IPOINT_AFTER, 
                (AFUNPTR)ftrace_post_brk,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
            RTN_Close(brk_rtn);
        }

        // sbrk
        RTN sbrk_rtn = RTN_FindByName(img, "sbrk"); 
        if (RTN_Valid(sbrk_rtn)) {
            RTN_Open(sbrk_rtn);
            RTN_InsertCall(sbrk_rtn, IPOINT_BEFORE, 
                (AFUNPTR)ftrace_pre_sbrk,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
            RTN_InsertCall(sbrk_rtn, IPOINT_AFTER, 
                (AFUNPTR)ftrace_post_sbrk,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
            RTN_Close(sbrk_rtn);
        }
    }

    // RTN free_rtn = RTN_FindByName(img, "free"); 
    RTN malloc_rtn = RTN_FindByName(img, "malloc"); 
    if (RTN_Valid(malloc_rtn)) {
        RTN_Open(malloc_rtn);
        RTN_InsertCall(malloc_rtn, IPOINT_BEFORE, (AFUNPTR)pre_malloc,
               IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        if (flag_rw_trace) {
            RTN_InsertCall(malloc_rtn, IPOINT_AFTER, (AFUNPTR)post_malloc,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        }
        RTN_Close(malloc_rtn);
    }

    RTN free_rtn = RTN_FindByName(img, "free"); 
    if (RTN_Valid(free_rtn)) {
        RTN_Open(free_rtn);
        if (flag_rw_trace) {
            RTN_InsertCall(free_rtn, IPOINT_BEFORE, (AFUNPTR)pre_free,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        }
        RTN_Close(free_rtn);
    }
    
}

DwarfType *infer(Type *t) {
    // offset, size
    std::map<ADDRINT, ADDRINT> inferred_members;
    for (Object *o : t->objects) {
        for (Access *a : o->accesses){
            // get offset,size pair
            if (a->size > inferred_members[a->offset]) {
                inferred_members[a->offset] = a->size;
            }
        }
    }

    DwarfType *match = NULL;
    double highest = 0.0;
    for (std::pair<uint64_t, DwarfType *> sz_dt : dwarf_types) {
        uint64_t sz = sz_dt.first;
        if (sz != t->size) continue;

        DwarfType *dt = sz_dt.second;
        double score = 0.0;
        for (std::pair<uint64_t, DwarfMember *> off_dm : dt->members) {
            uint64_t off = off_dm.first;
            DwarfMember *dm = off_dm.second;

            ADDRINT imsz = inferred_members[off];
            if (imsz == 0) {
                score -= 0.1;
            } else if (imsz < dm->size) {
                score += 0.5;
            } else if (imsz == dm->size) {
                score += 1.0;
            } else if (imsz > dm->size) {
                score -= 0.5;
            }
        }

        if (score > highest) {
            highest = score;
            match = dt;
        }
    }

    return match;
}

VOID Fini(INT32 code, VOID *v) {
    // *out << "size " << callstack.size() << std::endl; 
    *out << std::flush;

    if (flag_obj_count) {
        *out << "================ Object Count: " << std::endl;
        *out << object_count << std::endl;
    }

    if (flag_type_histogram) {
        *out << "================ Type Histogram" << std::endl;
        for (std::pair<ADDRINT,uint64_t> t : by_callstack) {
            *out << t.first << ":" << t.second << std::endl;
        }
    }

    if (flag_size_histogram) {
        *out << "================ Size Histogram" << std::endl;
        for (std::pair<ADDRINT,uint64_t> t : by_size) {
            *out << t.first << ":" << t.second << std::endl;
        }
    }

    if (flag_strict_histogram) {
        *out << "================ Strict Histogram" << std::endl;
        for (std::pair<std::pair<ADDRINT,ADDRINT>,uint64_t> t : by_both) {
            *out << t.first.first << "," << t.first.second << ":" << 
                t.second << std::endl;
        }
    }

    if (flag_rw_trace) {
        objectTracker->finalize();
        *out << "================ RW Trace" << std::endl;
        for (std::pair<std::pair<ADDRINT, ADDRINT>, Type*> kv :
            objectTracker->types) {
            Type *t = kv.second;
            if (!flag_inference_file.empty()) {
                DwarfType *match = infer(t);
                if (match != NULL) {
                    *out << "(" << match->name << ") ";
                }
            }

            *out << t->callstack << "," << t->size << std::endl;
            for (std::pair<std::string, uint64_t> p : t->patterns) {
                *out << p.second << ":" << p.first << std::endl;
            }
        }
    }

    *out << std::flush;
}

void parse_inference() {
    std::string line;
    std::ifstream infile(flag_inference_file.c_str());
    int skip = 2;
    
    DwarfType *dt = NULL;
    DwarfMember *dm = NULL;
    while (std::getline(infile, line)) {
        if (skip > 0) {
            skip--;
            continue;
        }

        std::stringstream ss(line);
        std::string tok;
        #define START 0
        #define TYPE_NAME 1
        #define TYPE_SIZE 2
        #define MEMBER_OFF 3
        #define MEMBER_NAME 4
        #define MEMBER_SIZE 5
        #define MEMBER_HINT 6
        #define DONE 7

        int state = START;
        while (std::getline(ss, tok, '/')) {
            switch (state) {
                case START:
                    if (tok == "t") {
                        if (dt != NULL) dt->print();
                        dt = new DwarfType();
                        state = TYPE_NAME;
                    } else if (tok == "m") {
                        dm = new DwarfMember();
                        state = MEMBER_OFF;
                    }
                    break;
                case TYPE_NAME:
                    dt->name = tok;
                    state = TYPE_SIZE;
                    break;
                case TYPE_SIZE:
                    dt->size = strtoul(tok.c_str(), NULL, 16);
                    dwarf_types[dt->size] = dt;
                    state = DONE;
                    break;
                case MEMBER_OFF:
                    dm->offset = strtoul(tok.c_str(), NULL, 16);
                    dt->members[dm->offset] = dm;
                    state = MEMBER_NAME;
                    break;
                case MEMBER_NAME:
                    dm->name = tok;
                    state = MEMBER_SIZE;
                    break;
                case MEMBER_SIZE:
                    dm->size = strtoul(tok.c_str(), NULL, 16);
                    state = MEMBER_HINT;
                    break;
                case MEMBER_HINT:
                    dm->hint = tok;
                    state = DONE;
                    break;
                default:
                    state = DONE;
                    break;
            }

            if (state == DONE) break;
        } // end while split
    }  // end while line

    if (dt != NULL) dt->print();
}

void parse_rw_filter() {
    std::string line;
    std::ifstream infile(flag_rw_filter_file.c_str());
    
    while (std::getline(infile, line)) {
        ADDRINT addr = (ADDRINT)strtoul(line.c_str(), NULL, 16);
        rw_whitelist.insert(addr);
    }
}

int main(int argc, char *argv[]) {
    object_count = 0;
    objectTracker = new ObjectTracker();

    PIN_InitSymbols();

    if( PIN_Init(argc,argv) ) {
        return Usage();
    }

    PIN_InitLock(&lock);

    flag_list_allocs = knob_list_allocs.Value();
    flag_size_histogram = knob_size_histogram.Value();
    flag_type_histogram = knob_type_histogram.Value();
    flag_obj_count = knob_obj_count.Value();
    flag_strict_histogram = knob_strict_histogram.Value();
    flag_pc_trace = knob_pc_trace.Value();
    flag_func_trace = knob_func_trace.Value();
    flag_describe_callstack = knob_describe_callstack.Value();
    flag_rw_trace = knob_rw_trace.Value();
    flag_image = knob_image.Value();
    flag_filter = knob_filter.Value();
    flag_getchr = knob_getchr.Value();
    flag_fs_getchr = knob_fs_getchr.Value();
    flag_match_sequence = knob_match_sequence.Value();
    flag_match_pos = 0;
    flag_match_len = flag_match_sequence.length();
    flag_inference_file = knob_inference_file.Value();
    flag_rw_filter_file = knob_rw_filter_file.Value();

    if (flag_match_len > 0 && (flag_getchr == 0 || !flag_rw_trace)) {
        *out << "-ms requires -g and -b" << std::endl;
        return 1;
    }

    if (!flag_inference_file.empty()) {
        parse_inference();
    }

    if (!flag_rw_filter_file.empty()) {
        parse_rw_filter();
    }

    std::string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    TRACE_AddInstrumentFunction(trace_callback, 0);
    INS_AddInstrumentFunction(instruction_callback, 0);
    IMG_AddInstrumentFunction(image_callback, 0);
    RTN_AddInstrumentFunction(routine_callback, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    PIN_StartProgram();
    
    return 0;
}
