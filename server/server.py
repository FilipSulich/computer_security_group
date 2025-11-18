import asyncio, asyncssh, os, struct, stat, logging
from auth import validate_user_password
from policy import AccessControl

#logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)

HOST_KEY_PATH = '../ssh_host_ed25519_key'
LISTEN_HOST, LISTEN_PORT = '', 2222
SFTP_SUBSYSTEM_NAME = 'sftp'
JAIL_ROOT = os.path.abspath('./sftp_root')

SSH_FXP_INIT, SSH_FXP_VERSION = 1, 2
SSH_FXP_OPEN, SSH_FXP_CLOSE = 3, 4
SSH_FXP_READ, SSH_FXP_WRITE = 5, 6
SSH_FXP_LSTAT, SSH_FXP_FSTAT = 7, 8
SSH_FXP_OPENDIR, SSH_FXP_READDIR = 11, 12
SSH_FXP_MKDIR = 14
SSH_FXP_REALPATH = 16
SSH_FXP_STAT = 17

SSH_FXP_STATUS, SSH_FXP_HANDLE, SSH_FXP_DATA = 101, 102, 103
SSH_FXP_NAME, SSH_FXP_ATTRS = 104, 105

#STATUS codes
SSH_FX_OK, SSH_FX_EOF, SSH_FX_NO_SUCH_FILE, SSH_FX_PERMISSION_DENIED, SSH_FX_FAILURE = 0, 1, 2, 3, 4

#pflags
PF_READ, PF_WRITE = 0x1, 0x2
PF_APPEND, PF_CREAT, PF_TRUNC, PF_EXCL = 0x4, 0x8, 0x10, 0x20

#packing helpers
def p_u32(n): return struct.pack(">I", n)
def p_u64(n): return struct.pack(">Q", n)
def p_str(b): return p_u32(len(b)) + b

def pack_pkt(ptype, payload):
    body = bytes([ptype]) + payload
    return p_u32(len(body)) + body

def u32(buf, off): return struct.unpack_from(">I", buf, off)[0], off+4
def u64(buf, off): return struct.unpack_from(">Q", buf, off)[0], off+8
def ustr(buf, off):
    ln, off = u32(buf, off)
    return buf[off:off+ln], off+ln

#PATH CANONICALIZATION
def canon_sftp_path(path_bs):
    """Return canonical SFTP POSIX path like '/foo/bar'"""
    s = path_bs.decode(errors="replace").replace("\\", "/")

    if not s or s == ".":
        return "/"
    
    if s.startswith("/"):
        rel = os.path.normpath(s[1:])
    else:
        rel = os.path.normpath(s)

    return "/" if rel == "." else "/" + rel


def safe_join(jroot, path_bs):
    """Prevent escapes outside the jail root."""
    s = path_bs.decode(errors="replace").replace("\\", "/")
    rel = os.path.normpath(s.lstrip("/"))
    full = os.path.realpath(os.path.join(jroot, rel))
    jail = os.path.realpath(jroot)

    if not (full == jail or full.startswith(jail + os.sep)):
        raise PermissionError("Path escape attempt")
    
    return full


#file attribute packer
def sftp_attrs_from_stat(st):
    perms = stat.S_IFMT(st.st_mode) | (st.st_mode & 0o777)

    return (
        p_u32(0x1 | 0x4 | 0x8) + #flags: size, perms, atime/mtime
        p_u64(st.st_size) +
        p_u32(perms) +
        p_u32(int(st.st_atime)) +
        p_u32(int(st.st_mtime))
    )


#handling table management
class DirHandle:
    def __init__(self, entries):
        self.entries = entries
        self.idx = 0

class FileHandle:
    def __init__(self, file_obj, canonical_path):
        self.file_obj = file_obj
        self.canonical_path = canonical_path

class Handles:
    def __init__(self):
        self._map = {}
        self._n = 1

    def add(self, obj):
        hid = str(self._n).encode()
        self._map[hid] = obj
        self._n += 1
        return p_str(hid)

    def get(self, hid):
        return self._map.get(hid)

    def close(self, hid):
        obj = self._map.pop(hid, None)
        # Close file if it's a FileHandle
        if isinstance(obj, FileHandle) and hasattr(obj.file_obj, 'close'):
            try:
                obj.file_obj.close()
            except Exception:
                pass


#SFTP session - handling table management
class SFTPSession(asyncssh.SSHServerSession):
    def __init__(self, username):
        self.username = username
        self.buf = b""
        self.initialized = False
        self.handles = Handles()
        self.ac = AccessControl() #access control engine

    #required by AsyncSSH
    def connection_made(self, chan):
        self._chan = chan
        
        try:
            self._chan.set_encoding(None)
        except Exception:
            pass

    def subsystem_requested(self, name):
        return name == SFTP_SUBSYSTEM_NAME

    def data_received(self, data, datatype):
        if isinstance(data, str):
            data = data.encode()
        self.buf += data

        while len(self.buf) >= 4:
            pkt_len, = struct.unpack(">I", self.buf[:4])

            if len(self.buf) < 4 + pkt_len:
                break

            pkt = self.buf[4:4+pkt_len]
            self.buf = self.buf[4+pkt_len:]
            self._handle(pkt)

    def _send_status(self, req_id, code, msg=b""):
        self._chan.write(pack_pkt(
            SSH_FXP_STATUS,
            p_u32(req_id) + p_u32(code) + p_str(msg) + p_str(b"")
        ))

    #SFTP packet dispacher
    def _handle(self, pkt: bytes):
        ptype = pkt[0]
        payload = pkt[1:]

        #INIT handshake
        if not self.initialized:
            if ptype != SSH_FXP_INIT:
                return self._send_status(0, SSH_FX_FAILURE, b"expected INIT")
            self._chan.write(pack_pkt(SSH_FXP_VERSION, p_u32(3)))
            self.initialized = True

            return

        req_id, off = u32(payload, 0)

        #REALPATH
        if ptype == SSH_FXP_REALPATH:
            raw, off = ustr(payload, off)
            canon = canon_sftp_path(raw)

            allowed, rec = self.ac.authorize(self.username, "realpath", canon)
            if not allowed:
                return self._send_status(req_id, SSH_FX_PERMISSION_DENIED, rec["reason"].encode())

            try:
                full = safe_join(JAIL_ROOT, raw)
                st = os.stat(full)
                attrs = sftp_attrs_from_stat(st)

            except FileNotFoundError:
                attrs = p_u32(0)

            resp = (
                p_u32(req_id) + p_u32(1) +
                p_str(canon.encode()) +
                p_str(canon.encode()) +
                attrs
            )
            return self._chan.write(pack_pkt(SSH_FXP_NAME, resp))

        #STAT/LSTAT
        if ptype in (SSH_FXP_STAT, SSH_FXP_LSTAT):
            raw, off = ustr(payload, off)
            canon = canon_sftp_path(raw)
            allowed, rec = self.ac.authorize(self.username, "stat", canon)

            if not allowed:
                return self._send_status(req_id, SSH_FX_PERMISSION_DENIED, rec["reason"].encode())

            try:
                full = safe_join(JAIL_ROOT, raw)
                st = os.stat(full)

            except FileNotFoundError:
                return self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"no such file")

            return self._chan.write(pack_pkt(SSH_FXP_ATTRS, p_u32(req_id) + sftp_attrs_from_stat(st)))

        #OPENDIR
        if ptype == SSH_FXP_OPENDIR:
            raw, off = ustr(payload, off)
            canon = canon_sftp_path(raw)

            allowed, rec = self.ac.authorize(self.username, "list", canon)
            if not allowed:
                return self._send_status(req_id, SSH_FX_PERMISSION_DENIED, rec["reason"].encode())

            try:
                full = safe_join(JAIL_ROOT, raw)
                entries = list(os.scandir(full))
                handle = self.handles.add(DirHandle(entries))

                return self._chan.write(pack_pkt(SSH_FXP_HANDLE, p_u32(req_id) + handle))

            except FileNotFoundError:
                return self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"directory not found")

            except PermissionError:
                return self._send_status(req_id, SSH_FX_PERMISSION_DENIED, b"permission denied")

        #READDIR
        if ptype == SSH_FXP_READDIR:
            handle_bs, off = ustr(payload, off)
            dh = self.handles.get(handle_bs)

            if not dh:
                return self._send_status(req_id, SSH_FX_FAILURE, b"bad handle")

            batch = dh.entries[dh.idx: dh.idx+50]
            dh.idx += len(batch)

            if not batch:
                return self._send_status(req_id, SSH_FX_EOF, b"EOF")

            out = p_u32(req_id) + p_u32(len(batch))

            for e in batch:
                name = e.name.encode()

                try:
                    attrs = sftp_attrs_from_stat(e.stat(follow_symlinks=False))

                except Exception:
                    attrs = p_u32(0)
                out += p_str(name) + p_str(name) + attrs

            return self._chan.write(pack_pkt(SSH_FXP_NAME, out))

        #MKDIR
        if ptype == SSH_FXP_MKDIR:
            raw, off = ustr(payload, off)
            canon = canon_sftp_path(raw)

            allowed, rec = self.ac.authorize(self.username, "mkdir", canon)
            if not allowed:
                return self._send_status(req_id, SSH_FX_PERMISSION_DENIED, rec["reason"].encode())

            try:
                full = safe_join(JAIL_ROOT, raw)
                os.makedirs(full, exist_ok=False)

            except FileExistsError:
                return self._send_status(req_id, SSH_FX_FAILURE, b"already exists")
            
            except FileNotFoundError:
                return self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"parent missing")
            
            except PermissionError:
                return self._send_status(req_id, SSH_FX_PERMISSION_DENIED, b"denied")

            return self._send_status(req_id, SSH_FX_OK, b"OK")

        #OPEN
        if ptype == SSH_FXP_OPEN:
            filename, off = ustr(payload, off)
            flags, off = u32(payload, off)

            safe_path = filename.decode(errors="replace").replace("\\", "/")

            op = "write" if flags & PF_WRITE else "read"
            
            if ".." in safe_path or safe_path.startswith(".."):
                pass 

            allowed, rec = self.ac.authorize(self.username, op, safe_path)
            if not allowed:
                return self._send_status(req_id, SSH_FX_PERMISSION_DENIED, rec["reason"].encode())

            try:
                full = safe_join(JAIL_ROOT, filename)

                mode = "rb"
                if flags & PF_WRITE:
                    mode = "r+b"
                if flags & PF_CREAT:
                    mode = "w+b" if not os.path.exists(full) else "r+b"
                if flags & PF_TRUNC:
                    mode = "w+b"
                if flags & PF_EXCL and os.path.exists(full):
                    return self._send_status(req_id, SSH_FX_FAILURE, b"exists")

                f = open(full, mode)
                file_handle = FileHandle(f, safe_path)

            except Exception as e:
                return self._send_status(req_id, SSH_FX_FAILURE, str(e).encode())

            handle = self.handles.add(file_handle)
            return self._chan.write(pack_pkt(SSH_FXP_HANDLE, p_u32(req_id) + handle))

        #READ
        if ptype == SSH_FXP_READ:
            handle_bs, off = ustr(payload, off)
            offset, off = u64(payload, off)
            length, off = u32(payload, off)

            file_handle = self.handles.get(handle_bs)

            if not file_handle or not isinstance(file_handle, FileHandle):
                return self._send_status(req_id, SSH_FX_FAILURE, b"bad handle")

            # Check authorization with the actual file path
            allowed, rec = self.ac.authorize(self.username, "read", file_handle.canonical_path)

            if not allowed:
                return self._send_status(req_id, SSH_FX_PERMISSION_DENIED, rec["reason"].encode())

            file_handle.file_obj.seek(offset)
            data = file_handle.file_obj.read(length)

            if not data:
                return self._send_status(req_id, SSH_FX_EOF, b"EOF")

            return self._chan.write(pack_pkt(
                SSH_FXP_DATA,
                p_u32(req_id) + p_str(data)
            ))

        #WRITE
        if ptype == SSH_FXP_WRITE:
            handle_bs, off = ustr(payload, off)
            offset, off = u64(payload, off)
            data, off = ustr(payload, off)

            file_handle = self.handles.get(handle_bs)
            if not file_handle or not isinstance(file_handle, FileHandle):
                return self._send_status(req_id, SSH_FX_FAILURE, b"bad handle")

            # Check authorization with the actual file path
            allowed, rec = self.ac.authorize(self.username, "write", file_handle.canonical_path)
            if not allowed:
                return self._send_status(req_id, SSH_FX_PERMISSION_DENIED, rec["reason"].encode())

            file_handle.file_obj.seek(offset)
            file_handle.file_obj.write(data)
            file_handle.file_obj.flush()
            return self._send_status(req_id, SSH_FX_OK, b"OK")

        #CLOSE
        if ptype == SSH_FXP_CLOSE:
            handle_bs, off = ustr(payload, off)
            self.handles.close(handle_bs)
            return self._send_status(req_id, SSH_FX_OK, b"OK")

        #unknown op
        return self._send_status(req_id, SSH_FX_FAILURE, b"unsupported")


#SSH SERVER WRAPPER
class Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        self._username = username
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return validate_user_password(username, password)

    def session_requested(self):
        return SFTPSession(self._username)


#MAIN
async def main():
    os.makedirs(JAIL_ROOT, exist_ok=True)

    await asyncssh.listen(
        LISTEN_HOST,
        LISTEN_PORT,
        server_host_keys=[HOST_KEY_PATH],
        server_factory=Server
    )

    print(f"✓ SFTP server running on port {LISTEN_PORT}")
    await asyncio.Event().wait()

if __name__ == "__main__":

    try:
        asyncio.run(main())

    except (KeyboardInterrupt, SystemExit):
        pass