from . import const


class specdata3:
    # XDR definition:
    # struct specdata3 {
    #     uint32 major;
    #     uint32 minor;
    # };
    def __init__(self, major=None, minor=None):
        self.major = major
        self.minor = minor

    def __repr__(self):
        out = []
        if self.major is not None:
            out += [f'major={self.major!r}']
        if self.minor is not None:
            out += [f'minor={self.minor!r}']
        return f"specdata3({', '.join(out)})"


class nfs_fh3:
    # XDR definition:
    # struct nfs_fh3 {
    #     opaque data<NFS3_FHSIZE>;
    # };
    def __init__(self, data=None):
        self.data = data

    def __repr__(self):
        out = []
        if self.data is not None:
            out += [f'data={self.data!r}']
        return f"nfs_fh3({', '.join(out)})"


class nfstime3:
    # XDR definition:
    # struct nfstime3 {
    #     uint32 seconds;
    #     uint32 nseconds;
    # };
    def __init__(self, seconds=None, nseconds=None):
        self.seconds = seconds
        self.nseconds = nseconds

    def __repr__(self):
        out = []
        if self.seconds is not None:
            out += [f'seconds={self.seconds!r}']
        if self.nseconds is not None:
            out += [f'nseconds={self.nseconds!r}']
        return f"nfstime3({', '.join(out)})"


class fattr3:
    # XDR definition:
    # struct fattr3 {
    #     ftype3 type;
    #     uint32 mode;
    #     uint32 nlink;
    #     uint32 uid;
    #     uint32 gid;
    #     uint64 size;
    #     uint64 used;
    #     specdata3 rdev;
    #     uint64 fsid;
    #     uint64 fileid;
    #     nfstime3 atime;
    #     nfstime3 mtime;
    #     nfstime3 ctime;
    # };
    def __init__(self, type=None, mode=None, nlink=None, uid=None, gid=None, size=None, used=None, rdev=None,
                 fsid=None, fileid=None, atime=None, mtime=None, ctime=None):
        self.type = type
        self.mode = mode
        self.nlink = nlink
        self.uid = uid
        self.gid = gid
        self.size = size
        self.used = used
        self.rdev = rdev
        self.fsid = fsid
        self.fileid = fileid
        self.atime = atime
        self.mtime = mtime
        self.ctime = ctime

    def __repr__(self):
        out = []
        if self.type is not None:
            out += [f'type={const.FTYPE3.get(self.type, self.type)}']
        if self.mode is not None:
            out += [f'mode={self.mode!r}']
        if self.nlink is not None:
            out += [f'nlink={self.nlink!r}']
        if self.uid is not None:
            out += [f'uid={self.uid!r}']
        if self.gid is not None:
            out += [f'gid={self.gid!r}']
        if self.size is not None:
            out += [f'size={self.size!r}']
        if self.used is not None:
            out += [f'used={self.used!r}']
        if self.rdev is not None:
            out += [f'rdev={self.rdev!r}']
        if self.fsid is not None:
            out += [f'fsid={self.fsid!r}']
        if self.fileid is not None:
            out += [f'fileid={self.fileid!r}']
        if self.atime is not None:
            out += [f'atime={self.atime!r}']
        if self.mtime is not None:
            out += [f'mtime={self.mtime!r}']
        if self.ctime is not None:
            out += [f'ctime={self.ctime!r}']
        return f"fattr3({', '.join(out)})"


class post_op_attr:
    # XDR definition:
    # union post_op_attr switch(bool present) {
    #     case TRUE:
    #         fattr3 attributes;
    #     case FALSE:
    #         void;
    # };
    def __init__(self, present=None, attributes=None):
        self.present = present
        self.attributes = attributes

    def __repr__(self):
        out = []
        if self.present is not None:
            out += [f'present={self.present!r}']
        if self.attributes is not None:
            out += [f'attributes={self.attributes!r}']
        return f"post_op_attr({', '.join(out)})"


class wcc_attr:
    # XDR definition:
    # struct wcc_attr {
    #     uint64 size;
    #     nfstime3 mtime;
    #     nfstime3 ctime;
    # };
    def __init__(self, size=None, mtime=None, ctime=None):
        self.size = size
        self.mtime = mtime
        self.ctime = ctime

    def __repr__(self):
        out = []
        if self.size is not None:
            out += [f'size={self.size!r}']
        if self.mtime is not None:
            out += [f'mtime={self.mtime!r}']
        if self.ctime is not None:
            out += [f'ctime={self.ctime!r}']
        return f"wcc_attr({', '.join(out)})"


class pre_op_attr:
    # XDR definition:
    # union pre_op_attr switch(bool present) {
    #     case TRUE:
    #         wcc_attr attributes;
    #     case FALSE:
    #         void;
    # };
    def __init__(self, present=None, attributes=None):
        self.present = present
        self.attributes = attributes

    def __repr__(self):
        out = []
        if self.present is not None:
            out += [f'present={self.present!r}']
        if self.attributes is not None:
            out += [f'attributes={self.attributes!r}']
        return f"pre_op_attr({', '.join(out)})"


class wcc_data:
    # XDR definition:
    # struct wcc_data {
    #     pre_op_attr before;
    #     post_op_attr after;
    # };
    def __init__(self, before=None, after=None):
        self.before = before
        self.after = after

    def __repr__(self):
        out = []
        if self.before is not None:
            out += [f'before={self.before!r}']
        if self.after is not None:
            out += [f'after={self.after!r}']
        return f"wcc_data({', '.join(out)})"


class post_op_fh3:
    # XDR definition:
    # union post_op_fh3 switch(bool present) {
    #     case TRUE:
    #         nfs_fh3 handle;
    #     case FALSE:
    #         void;
    # };
    def __init__(self, present=None, handle=None):
        self.present = present
        self.handle = handle

    def __repr__(self):
        out = []
        if self.present is not None:
            out += [f'present={self.present!r}']
        if self.handle is not None:
            out += [f'handle={self.handle!r}']
        return f"post_op_fh3({', '.join(out)})"


class set_uint32:
    # XDR definition:
    # union set_uint32 switch(bool set) {
    #     case TRUE:
    #         uint32 val;
    #     default:
    #         void;
    # };
    def __init__(self, set=None, val=None):
        self.set = set
        self.val = val

    def __repr__(self):
        out = []
        if self.set is not None:
            out += [f'set={self.set!r}']
        if self.val is not None:
            out += [f'val={self.val!r}']
        return f"set_uint32({', '.join(out)})"


class set_uint64:
    # XDR definition:
    # union set_uint64 switch(bool set) {
    #     case TRUE:
    #         uint64 val;
    #     default:
    #         void;
    # };
    def __init__(self, set=None, val=None):
        self.set = set
        self.val = val

    def __repr__(self):
        out = []
        if self.set is not None:
            out += [f'set={self.set!r}']
        if self.val is not None:
            out += [f'val={self.val!r}']
        return f"set_uint64({', '.join(out)})"


class set_time:
    # XDR definition:
    # union set_time switch(time_how set) {
    #     case SET_TO_CLIENT_TIME:
    #         nfstime3 time;
    #     default:
    #         void;
    # };
    def __init__(self, set=None, time=None):
        self.set = set
        self.time = time

    def __repr__(self):
        out = []
        if self.set is not None:
            out += [f'set={const.time_how.get(self.set, self.set)}']
        if self.time is not None:
            out += [f'time={self.time!r}']
        return f"set_time({', '.join(out)})"


class sattr3:
    # XDR definition:
    # struct sattr3 {
    #     set_uint32 mode;
    #     set_uint32 uid;
    #     set_uint32 gid;
    #     set_uint64 size;
    #     set_time atime;
    #     set_time mtime;
    # };
    def __init__(self, mode=None, uid=None, gid=None, size=None, atime=None, mtime=None):
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.size = size
        self.atime = atime
        self.mtime = mtime

    def __repr__(self):
        out = []
        if self.mode is not None:
            out += [f'mode={self.mode!r}']
        if self.uid is not None:
            out += [f'uid={self.uid!r}']
        if self.gid is not None:
            out += [f'gid={self.gid!r}']
        if self.size is not None:
            out += [f'size={self.size!r}']
        if self.atime is not None:
            out += [f'atime={self.atime!r}']
        if self.mtime is not None:
            out += [f'mtime={self.mtime!r}']
        return f"sattr3({', '.join(out)})"


class diropargs3:
    # XDR definition:
    # struct diropargs3 {
    #     nfs_fh3 dir;
    #     filename3 name;
    # };
    def __init__(self, dir=None, name=None):
        self.dir = dir
        self.name = name

    def __repr__(self):
        out = []
        if self.dir is not None:
            out += [f'dir={self.dir!r}']
        if self.name is not None:
            out += [f'name={self.name!r}']
        return f"diropargs3({', '.join(out)})"


class diropres3ok:
    # XDR definition:
    # struct diropres3ok {
    #     post_op_fh3 obj;
    #     post_op_attr obj_attributes;
    #     wcc_data dir_wcc;
    # };
    def __init__(self, obj=None, obj_attributes=None, dir_wcc=None):
        self.obj = obj
        self.obj_attributes = obj_attributes
        self.dir_wcc = dir_wcc

    def __repr__(self):
        out = []
        if self.obj is not None:
            out += [f'obj={self.obj!r}']
        if self.obj_attributes is not None:
            out += [f'obj_attributes={self.obj_attributes!r}']
        if self.dir_wcc is not None:
            out += [f'dir_wcc={self.dir_wcc!r}']
        return f"diropres3ok({', '.join(out)})"


class diropres3:
    # XDR definition:
    # union diropres3 switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         diropres3ok resok;
    #     default:
    #         wcc_data resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"diropres3({', '.join(out)})"


class wccstat3:
    # XDR definition:
    # union wccstat3 switch(nfsstat3 status) {
    #     case -1:
    #         void;
    #     default:
    #         wcc_data wcc;
    # };
    def __init__(self, status=None):
        self.status = status

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        return f"wccstat3({', '.join(out)})"


class getattr3res:
    # XDR definition:
    # union getattr3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         fattr3 attributes;
    #     default:
    #         void;
    # };
    def __init__(self, status=None, attributes=None):
        self.status = status
        self.attributes = attributes

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.attributes is not None:
            out += [f'attributes={self.attributes!r}']
        return f"getattr3res({', '.join(out)})"


class sattrguard3:
    # XDR definition:
    # union sattrguard3 switch(bool check) {
    #     case TRUE:
    #         nfstime3 ctime;
    #     case FALSE:
    #         void;
    # };
    def __init__(self, check=None, ctime=None):
        self.check = check
        self.ctime = ctime

    def __repr__(self):
        out = []
        if self.check is not None:
            out += [f'check={self.check!r}']
        if self.ctime is not None:
            out += [f'ctime={self.ctime!r}']
        return f"sattrguard3({', '.join(out)})"


class setattr3args:
    # XDR definition:
    # struct setattr3args {
    #     nfs_fh3 object;
    #     sattr3 new_attributes;
    #     sattrguard3 guard;
    # };
    def __init__(self, object=None, new_attributes=None, guard=None):
        self.object = object
        self.new_attributes = new_attributes
        self.guard = guard

    def __repr__(self):
        out = []
        if self.object is not None:
            out += [f'object={self.object!r}']
        if self.new_attributes is not None:
            out += [f'new_attributes={self.new_attributes!r}']
        if self.guard is not None:
            out += [f'guard={self.guard!r}']
        return f"setattr3args({', '.join(out)})"


class wcc_data3res:
    def __init__(self, category, status=None, wcc_data=None):
        self.category = str(category) or ''
        self.status = status
        self.wcc_data = wcc_data

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.wcc_data is not None:
            out += [f'wcc_data={self.wcc_data!r}']
        return self.category + f"({', '.join(out)})"


class lookup3resok:
    # XDR definition:
    # struct lookup3resok {
    #     nfs_fh3 object;
    #     post_op_attr obj_attributes;
    #     post_op_attr dir_attributes;
    # };
    def __init__(self, object=None, obj_attributes=None, dir_attributes=None):
        self.object = object
        self.obj_attributes = obj_attributes
        self.dir_attributes = dir_attributes

    def __repr__(self):
        out = []
        if self.object is not None:
            out += [f'object={self.object!r}']
        if self.obj_attributes is not None:
            out += [f'obj_attributes={self.obj_attributes!r}']
        if self.dir_attributes is not None:
            out += [f'dir_attributes={self.dir_attributes!r}']
        return f"lookup3resok({', '.join(out)})"


class lookup3res:
    # XDR definition:
    # union lookup3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         lookup3resok resok;
    #     default:
    #         post_op_attr resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"lookup3res({', '.join(out)})"


class access3args:
    # XDR definition:
    # struct access3args {
    #     nfs_fh3 object;
    #     uint32 access;
    # };
    def __init__(self, object=None, access=None):
        self.object = object
        self.access = access

    def __repr__(self):
        out = []
        if self.object is not None:
            out += [f'object={self.object!r}']
        if self.access is not None:
            out += [f'access={self.access!r}']
        return f"access3args({', '.join(out)})"


class access3resok:
    # XDR definition:
    # struct access3resok {
    #     post_op_attr obj_attributes;
    #     uint32 access;
    # };
    def __init__(self, obj_attributes=None, access=None):
        self.obj_attributes = obj_attributes
        self.access = access

    def __repr__(self):
        out = []
        if self.obj_attributes is not None:
            out += [f'obj_attributes={self.obj_attributes!r}']
        if self.access is not None:
            out += [f'access={self.access!r}']
        return f"access3resok({', '.join(out)})"


class access3res:
    # XDR definition:
    # union access3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         access3resok resok;
    #     default:
    #         post_op_attr resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"access3res({', '.join(out)})"


class readlink3resok:
    # XDR definition:
    # struct readlink3resok {
    #     post_op_attr symlink_attributes;
    #     nfspath3 data;
    # };
    def __init__(self, symlink_attributes=None, data=None):
        self.symlink_attributes = symlink_attributes
        self.data = data

    def __repr__(self):
        out = []
        if self.symlink_attributes is not None:
            out += [f'symlink_attributes={self.symlink_attributes!r}']
        if self.data is not None:
            out += [f'data={self.data!r}']
        return f"readlink3resok({', '.join(out)})"


class readlink3res:
    # XDR definition:
    # union readlink3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         readlink3resok resok;
    #     default:
    #         post_op_attr resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"readlink3res({', '.join(out)})"


class read3args:
    # XDR definition:
    # struct read3args {
    #     nfs_fh3 file;
    #     uint64 offset;
    #     uint32 count;
    # };
    def __init__(self, file=None, offset=None, count=None):
        self.file = file
        self.offset = offset
        self.count = count

    def __repr__(self):
        out = []
        if self.file is not None:
            out += [f'file={self.file!r}']
        if self.offset is not None:
            out += [f'offset={self.offset!r}']
        if self.count is not None:
            out += [f'count={self.count!r}']
        return f"read3args({', '.join(out)})"


class read3resok:
    # XDR definition:
    # struct read3resok {
    #     post_op_attr file_attributes;
    #     uint32 count;
    #     bool eof;
    #     opaque data<>;
    # };
    def __init__(self, file_attributes=None, count=None, eof=None, data=None):
        self.file_attributes = file_attributes
        self.count = count
        self.eof = eof
        self.data = data

    def __repr__(self):
        out = []
        if self.file_attributes is not None:
            out += [f'file_attributes={self.file_attributes!r}']
        if self.count is not None:
            out += [f'count={self.count!r}']
        if self.eof is not None:
            out += [f'eof={self.eof!r}']
        if self.data is not None:
            out += [f'data={self.data!r}']
        return f"read3resok({', '.join(out)})"


class read3res:
    # XDR definition:
    # union read3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         read3resok resok;
    #     default:
    #         post_op_attr resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"read3res({', '.join(out)})"


class write3args:
    # XDR definition:
    # struct write3args {
    #     nfs_fh3 file;
    #     uint64 offset;
    #     uint32 count;
    #     stable_how stable;
    #     opaque data<>;
    # };
    def __init__(self, file=None, offset=None, count=None, stable=None, data=None):
        self.file = file
        self.offset = offset
        self.count = count
        self.stable = stable
        self.data = data

    def __repr__(self):
        out = []
        if self.file is not None:
            out += [f'file={self.file!r}']
        if self.offset is not None:
            out += [f'offset={self.offset!r}']
        if self.count is not None:
            out += [f'count={self.count!r}']
        if self.stable is not None:
            out += [f'stable={const.STABLE_HOW.get(self.stable, self.stable)}']
        if self.data is not None:
            out += [f'data={self.data!r}']
        return f"write3args({', '.join(out)})"


class write3resok:
    # XDR definition:
    # struct write3resok {
    #     wcc_data file_wcc;
    #     uint32 count;
    #     stable_how committed;
    #     writeverf3 verf;
    # };
    def __init__(self, file_wcc=None, count=None, committed=None, verf=None):
        self.file_wcc = file_wcc
        self.count = count
        self.committed = committed
        self.verf = verf

    def __repr__(self):
        out = []
        if self.file_wcc is not None:
            out += [f'file_wcc={self.file_wcc!r}']
        if self.count is not None:
            out += [f'count={self.count!r}']
        if self.committed is not None:
            out += [f'committed={const.STABLE_HOW.get(self.committed, self.committed)}']
        if self.verf is not None:
            out += [f'verf={self.verf!r}']
        return f"write3resok({', '.join(out)})"


class write3res:
    # XDR definition:
    # union write3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         write3resok resok;
    #     default:
    #         wcc_data resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"write3res({', '.join(out)})"


class createhow3:
    # XDR definition:
    # union createhow3 switch(createmode3 mode) {
    #     case UNCHECKED:
    #     case GUARDED:
    #         sattr3 obj_attributes;
    #     case EXCLUSIVE:
    #         createverf3 verf;
    # };
    def __init__(self, mode=None, obj_attributes=None, verf=None):
        self.mode = mode
        self.obj_attributes = obj_attributes
        self.verf = verf

    def __repr__(self):
        out = []
        if self.mode is not None:
            out += [f'mode={const.CREATEMODE3.get(self.mode, self.mode)}']
        if self.obj_attributes is not None:
            out += [f'obj_attributes={self.obj_attributes!r}']
        if self.verf is not None:
            out += [f'verf={self.verf!r}']
        return f"createhow3({', '.join(out)})"


class create3args:
    # XDR definition:
    # struct create3args {
    #     diropargs3 where;
    #     createhow3 how;
    # };
    def __init__(self, where=None, how=None):
        self.where = where
        self.how = how

    def __repr__(self):
        out = []
        if self.where is not None:
            out += [f'where={self.where!r}']
        if self.how is not None:
            out += [f'how={self.how!r}']
        return f"create3args({', '.join(out)})"


class create3resok:
    # XDR definition:
    # struct CREATE3resok {
    #     post_op_fh3 obj;
    #     post_op_attr obj_attributes;
    #     wcc_data dir_wcc;
    # };
    def __init__(self, obj=None, obj_attributes=None, dir_wcc=None):
        self.obj = obj
        self.obj_attributes = obj_attributes
        self.dir_wcc = dir_wcc

    def __repr__(self):
        out = list()
        if self.obj is not None:
            out += [f'obj={self.obj!r}']
        if self.obj_attributes is not None:
            out += [f'obj_attributes={self.obj_attributes!r}']
        if self.dir_wcc is not None:
            out += [f'dir_wcc={self.dir_wcc!r}']
        return f"create3resok({', '.join(out)})"


class create3res:
    # XDR definition:
    # union CREATE3res switch (nfsstat3 status) {
    #     case NFS3_OK:
    #         CREATE3resok resok;
    #     default:
    #         CREATE3resfail resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = list()
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"create3res({', '.join(out)})"


class mkdir3args:
    # XDR definition:
    # struct mkdir3args {
    #     diropargs3 where;
    #     sattr3 attributes;
    # };
    def __init__(self, where=None, attributes=None):
        self.where = where
        self.attributes = attributes

    def __repr__(self):
        out = []
        if self.where is not None:
            out += [f'where={self.where!r}']
        if self.attributes is not None:
            out += [f'attributes={self.attributes!r}']
        return f"mkdir3args({', '.join(out)})"


class symlinkdata3:
    # XDR definition:
    # struct symlinkdata3 {
    #     sattr3 symlink_attributes;
    #     nfspath3 symlink_data;
    # };
    def __init__(self, symlink_attributes=None, symlink_data=None):
        self.symlink_attributes = symlink_attributes
        self.symlink_data = symlink_data

    def __repr__(self):
        out = []
        if self.symlink_attributes is not None:
            out += [f'symlink_attributes={self.symlink_attributes!r}']
        if self.symlink_data is not None:
            out += [f'symlink_data={self.symlink_data!r}']
        return f"symlinkdata3({', '.join(out)})"


class symlink3args:
    # XDR definition:
    # struct symlink3args {
    #     diropargs3 where;
    #     symlinkdata3 symlink;
    # };
    def __init__(self, where=None, symlink=None):
        self.where = where
        self.symlink = symlink

    def __repr__(self):
        out = []
        if self.where is not None:
            out += [f'where={self.where!r}']
        if self.symlink is not None:
            out += [f'symlink={self.symlink!r}']
        return f"symlink3args({', '.join(out)})"


class devicedata3:
    # XDR definition:
    # struct devicedata3 {
    #     sattr3 dev_attributes;
    #     specdata3 spec;
    # };
    def __init__(self, dev_attributes=None, spec=None):
        self.dev_attributes = dev_attributes
        self.spec = spec

    def __repr__(self):
        out = []
        if self.dev_attributes is not None:
            out += [f'dev_attributes={self.dev_attributes!r}']
        if self.spec is not None:
            out += [f'spec={self.spec!r}']
        return f"devicedata3({', '.join(out)})"


class mknoddata3:
    # XDR definition:
    # union mknoddata3 switch(ftype3 type) {
    #     case NF3CHR:
    #     case NF3BLK:
    #         devicedata3 device;
    #     case NF3SOCK:
    #     case NF3FIFO:
    #         sattr3 pipe_attributes;
    #     default:
    #         void;
    # };
    def __init__(self, type=None, device=None, pipe_attributes=None):
        self.type = type
        self.device = device
        self.pipe_attributes = pipe_attributes

    def __repr__(self):
        out = []
        if self.type is not None:
            out += [f'type={const.FTYPE3.get(self.type, self.type)}']
        if self.device is not None:
            out += [f'device={self.device!r}']
        if self.pipe_attributes is not None:
            out += [f'pipe_attributes={self.pipe_attributes!r}']
        return f"mknoddata3({', '.join(out)})"


class mknod3args:
    # XDR definition:
    # struct mknod3args {
    #     diropargs3 where;
    #     mknoddata3 what;
    # };
    def __init__(self, where=None, what=None):
        self.where = where
        self.what = what

    def __repr__(self):
        out = []
        if self.where is not None:
            out += [f'where={self.where!r}']
        if self.what is not None:
            out += [f'what={self.what!r}']
        return f"mknod3args({', '.join(out)})"


class rename3args:
    # XDR definition:
    # struct rename3args {
    #     diropargs3 from;
    #     diropargs3 to;
    # };
    def __init__(self, from_v=None, to=None):
        self.from_v = from_v
        self.to = to

    def __repr__(self):
        out = []
        if self.from_v is not None:
            out += [f'from={self.from_v!r}']
        if self.to is not None:
            out += [f'to={self.to!r}']
        return f"rename3args({', '.join(out)})"


class rename3wcc:
    # XDR definition:
    # struct rename3wcc {
    #     wcc_data fromdir_wcc;
    #     wcc_data todir_wcc;
    # };
    def __init__(self, fromdir_wcc=None, todir_wcc=None):
        self.fromdir_wcc = fromdir_wcc
        self.todir_wcc = todir_wcc

    def __repr__(self):
        out = []
        if self.fromdir_wcc is not None:
            out += [f'fromdir_wcc={self.fromdir_wcc!r}']
        if self.todir_wcc is not None:
            out += [f'todir_wcc={self.todir_wcc!r}']
        return f"rename3wcc({', '.join(out)})"


class rename3res:
    # XDR definition:
    # union rename3res switch(nfsstat3 status) {
    #     case -1:
    #         void;
    #     default:
    #         rename3wcc res;
    # };
    def __init__(self, status=None):
        self.status = status

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        return f"rename3res({', '.join(out)})"


class link3args:
    # XDR definition:
    # struct link3args {
    #     nfs_fh3 file;
    #     diropargs3 link;
    # };
    def __init__(self, file=None, link=None):
        self.file = file
        self.link = link

    def __repr__(self):
        out = []
        if self.file is not None:
            out += [f'file={self.file!r}']
        if self.link is not None:
            out += [f'link={self.link!r}']
        return f"link3args({', '.join(out)})"


class link3wcc:
    # XDR definition:
    # struct link3wcc {
    #     post_op_attr file_attributes;
    #     wcc_data linkdir_wcc;
    # };
    def __init__(self, file_attributes=None, linkdir_wcc=None):
        self.file_attributes = file_attributes
        self.linkdir_wcc = linkdir_wcc

    def __repr__(self):
        out = []
        if self.file_attributes is not None:
            out += [f'file_attributes={self.file_attributes!r}']
        if self.linkdir_wcc is not None:
            out += [f'linkdir_wcc={self.linkdir_wcc!r}']
        return f"link3wcc({', '.join(out)})"


class link3res:
    # XDR definition:
    # union link3res switch(nfsstat3 status) {
    #     case -1:
    #         void;
    #     default:
    #         link3wcc res;
    # };
    def __init__(self, status=None):
        self.status = status

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        return f"link3res({', '.join(out)})"


class readdir3args:
    # XDR definition:
    # struct readdir3args {
    #     nfs_fh3 dir;
    #     uint64 cookie;
    #     cookieverf3 cookieverf;
    #     uint32 count;
    # };
    def __init__(self, dir=None, cookie=None, cookieverf=None, count=None):
        self.dir = dir
        self.cookie = cookie
        self.cookieverf = cookieverf
        self.count = count

    def __repr__(self):
        out = []
        if self.dir is not None:
            out += [f'dir={self.dir!r}']
        if self.cookie is not None:
            out += [f'cookie={self.cookie!r}']
        if self.cookieverf is not None:
            out += [f'cookieverf={self.cookieverf!r}']
        if self.count is not None:
            out += [f'count={self.count!r}']
        return f"readdir3args({', '.join(out)})"


class entry3:
    # XDR definition:
    # struct entry3 {
    #     uint64 fileid;
    #     filename3 name;
    #     uint64 cookie;
    #     entry3 nextentry<1>;
    # };
    def __init__(self, fileid=None, name=None, cookie=None, nextentry=None):
        self.fileid = fileid
        self.name = name
        self.cookie = cookie
        self.nextentry = nextentry

    def __repr__(self):
        out = []
        if self.fileid is not None:
            out += [f'fileid={self.fileid!r}']
        if self.name is not None:
            out += [f'name={self.name!r}']
        if self.cookie is not None:
            out += [f'cookie={self.cookie!r}']
        if self.nextentry is not None:
            out += [f'nextentry={self.nextentry!r}']
        return f"entry3({', '.join(out)})"


class dirlist3:
    # XDR definition:
    # struct dirlist3 {
    #     entry3 entries<1>;
    #     bool eof;
    # };
    def __init__(self, entries=None, eof=None):
        self.entries = entries
        self.eof = eof

    def __repr__(self):
        out = []
        if self.entries is not None:
            out += [f'entries={self.entries!r}']
        if self.eof is not None:
            out += [f'eof={self.eof!r}']
        return f"dirlist3({', '.join(out)})"


class readdir3resok:
    # XDR definition:
    # struct readdir3resok {
    #     post_op_attr dir_attributes;
    #     cookieverf3 cookieverf;
    #     dirlist3 reply;
    # };
    def __init__(self, dir_attributes=None, cookieverf=None, reply=None):
        self.dir_attributes = dir_attributes
        self.cookieverf = cookieverf
        self.reply = reply

    def __repr__(self):
        out = []
        if self.dir_attributes is not None:
            out += [f'dir_attributes={self.dir_attributes!r}']
        if self.cookieverf is not None:
            out += [f'cookieverf={self.cookieverf!r}']
        if self.reply is not None:
            out += [f'reply={self.reply!r}']
        return f"readdir3resok({', '.join(out)})"


class readdir3res:
    # XDR definition:
    # union readdir3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         readdir3resok resok;
    #     default:
    #         post_op_attr resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"readdir3res({', '.join(out)})"


class readdirplus3args:
    # XDR definition:
    # struct readdirplus3args {
    #     nfs_fh3 dir;
    #     uint64 cookie;
    #     cookieverf3 cookieverf;
    #     uint32 dircount;
    #     uint32 maxcount;
    # };
    def __init__(self, dir=None, cookie=None, cookieverf=None, dircount=None, maxcount=None):
        self.dir = dir
        self.cookie = cookie
        self.cookieverf = cookieverf
        self.dircount = dircount
        self.maxcount = maxcount

    def __repr__(self):
        out = []
        if self.dir is not None:
            out += [f'dir={self.dir!r}']
        if self.cookie is not None:
            out += [f'cookie={self.cookie!r}']
        if self.cookieverf is not None:
            out += [f'cookieverf={self.cookieverf!r}']
        if self.dircount is not None:
            out += [f'dircount={self.dircount!r}']
        if self.maxcount is not None:
            out += [f'maxcount={self.maxcount!r}']
        return f"readdirplus3args({', '.join(out)})"


class entryplus3:
    # XDR definition:
    # struct entryplus3 {
    #     uint64 fileid;
    #     filename3 name;
    #     uint64 cookie;
    #     post_op_attr name_attributes;
    #     post_op_fh3 name_handle;
    #     entryplus3 nextentry<1>;
    # };
    def __init__(self, fileid=None, name=None, cookie=None, name_attributes=None, name_handle=None, nextentry=None):
        self.fileid = fileid
        self.name = name
        self.cookie = cookie
        self.name_attributes = name_attributes
        self.name_handle = name_handle
        self.nextentry = nextentry

    def __repr__(self):
        out = []
        if self.fileid is not None:
            out += [f'fileid={self.fileid!r}']
        if self.name is not None:
            out += [f'name={self.name!r}']
        if self.cookie is not None:
            out += [f'cookie={self.cookie!r}']
        if self.name_attributes is not None:
            out += [f'name_attributes={self.name_attributes!r}']
        if self.name_handle is not None:
            out += [f'name_handle={self.name_handle!r}']
        if self.nextentry is not None:
            out += [f'nextentry={self.nextentry!r}']
        return f"entryplus3({', '.join(out)})"


class dirlistplus3:
    # XDR definition:
    # struct dirlistplus3 {
    #     entryplus3 entries<1>;
    #     bool eof;
    # };
    def __init__(self, entries=None, eof=None):
        self.entries = entries
        self.eof = eof

    def __repr__(self):
        out = []
        if self.entries is not None:
            out += [f'entries={self.entries!r}']
        if self.eof is not None:
            out += [f'eof={self.eof!r}']
        return f"dirlistplus3({', '.join(out)})"


class readdirplus3resok:
    # XDR definition:
    # struct readdirplus3resok {
    #     post_op_attr dir_attributes;
    #     cookieverf3 cookieverf;
    #     dirlistplus3 reply;
    # };
    def __init__(self, dir_attributes=None, cookieverf=None, reply=None):
        self.dir_attributes = dir_attributes
        self.cookieverf = cookieverf
        self.reply = reply

    def __repr__(self):
        out = []
        if self.dir_attributes is not None:
            out += [f'dir_attributes={self.dir_attributes!r}']
        if self.cookieverf is not None:
            out += [f'cookieverf={self.cookieverf!r}']
        if self.reply is not None:
            out += [f'reply={self.reply!r}']
        return f"readdirplus3resok({', '.join(out)})"


class readdirplus3res:
    # XDR definition:
    # union readdirplus3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         readdirplus3resok resok;
    #     default:
    #         post_op_attr resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"readdirplus3res({', '.join(out)})"


class fsstat3resok:
    # XDR definition:
    # struct fsstat3resok {
    #     post_op_attr obj_attributes;
    #     uint64 tbytes;
    #     uint64 fbytes;
    #     uint64 abytes;
    #     uint64 tfiles;
    #     uint64 ffiles;
    #     uint64 afiles;
    #     uint32 invarsec;
    # };
    def __init__(self, obj_attributes=None, tbytes=None, fbytes=None, abytes=None, tfiles=None, ffiles=None,
                 afiles=None, invarsec=None):
        self.obj_attributes = obj_attributes
        self.tbytes = tbytes
        self.fbytes = fbytes
        self.abytes = abytes
        self.tfiles = tfiles
        self.ffiles = ffiles
        self.afiles = afiles
        self.invarsec = invarsec

    def __repr__(self):
        out = []
        if self.obj_attributes is not None:
            out += [f'obj_attributes={self.obj_attributes!r}']
        if self.tbytes is not None:
            out += [f'tbytes={self.tbytes!r}']
        if self.fbytes is not None:
            out += [f'fbytes={self.fbytes!r}']
        if self.abytes is not None:
            out += [f'abytes={self.abytes!r}']
        if self.tfiles is not None:
            out += [f'tfiles={self.tfiles!r}']
        if self.ffiles is not None:
            out += [f'ffiles={self.ffiles!r}']
        if self.afiles is not None:
            out += [f'afiles={self.afiles!r}']
        if self.invarsec is not None:
            out += [f'invarsec={self.invarsec!r}']
        return f"fsstat3resok({', '.join(out)})"


class fsstat3res:
    # XDR definition:
    # union fsstat3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         fsstat3resok resok;
    #     default:
    #         post_op_attr resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"fsstat3res({', '.join(out)})"


class fsinfo3resok:
    # XDR definition:
    # struct fsinfo3resok {
    #     post_op_attr obj_attributes;
    #     uint32 rtmax;
    #     uint32 rtpref;
    #     uint32 rtmult;
    #     uint32 wtmax;
    #     uint32 wtpref;
    #     uint32 wtmult;
    #     uint32 dtpref;
    #     uint64 maxfilesize;
    #     nfstime3 time_delta;
    #     uint32 properties;
    # };
    def __init__(self, obj_attributes=None, rtmax=None, rtpref=None, rtmult=None, wtmax=None, wtpref=None,
                 wtmult=None, dtpref=None, maxfilesize=None, time_delta=None, properties=None):
        self.obj_attributes = obj_attributes
        self.rtmax = rtmax
        self.rtpref = rtpref
        self.rtmult = rtmult
        self.wtmax = wtmax
        self.wtpref = wtpref
        self.wtmult = wtmult
        self.dtpref = dtpref
        self.maxfilesize = maxfilesize
        self.time_delta = time_delta
        self.properties = properties

    def __repr__(self):
        out = []
        if self.obj_attributes is not None:
            out += [f'obj_attributes={self.obj_attributes!r}']
        if self.rtmax is not None:
            out += [f'rtmax={self.rtmax!r}']
        if self.rtpref is not None:
            out += [f'rtpref={self.rtpref!r}']
        if self.rtmult is not None:
            out += [f'rtmult={self.rtmult!r}']
        if self.wtmax is not None:
            out += [f'wtmax={self.wtmax!r}']
        if self.wtpref is not None:
            out += [f'wtpref={self.wtpref!r}']
        if self.wtmult is not None:
            out += [f'wtmult={self.wtmult!r}']
        if self.dtpref is not None:
            out += [f'dtpref={self.dtpref!r}']
        if self.maxfilesize is not None:
            out += [f'maxfilesize={self.maxfilesize!r}']
        if self.time_delta is not None:
            out += [f'time_delta={self.time_delta!r}']
        if self.properties is not None:
            out += [f'properties={self.properties!r}']
        return f"fsinfo3resok({', '.join(out)})"


class fsinfo3res:
    # XDR definition:
    # union fsinfo3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         fsinfo3resok resok;
    #     default:
    #         post_op_attr resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"fsinfo3res({', '.join(out)})"


class pathconf3resok:
    # XDR definition:
    # struct pathconf3resok {
    #     post_op_attr obj_attributes;
    #     uint32 linkmax;
    #     uint32 name_max;
    #     bool no_trunc;
    #     bool chown_restricted;
    #     bool case_insensitive;
    #     bool case_preserving;
    # };
    def __init__(self, obj_attributes=None, linkmax=None, name_max=None, no_trunc=None, chown_restricted=None,
                 case_insensitive=None, case_preserving=None):
        self.obj_attributes = obj_attributes
        self.linkmax = linkmax
        self.name_max = name_max
        self.no_trunc = no_trunc
        self.chown_restricted = chown_restricted
        self.case_insensitive = case_insensitive
        self.case_preserving = case_preserving

    def __repr__(self):
        out = []
        if self.obj_attributes is not None:
            out += [f'obj_attributes={self.obj_attributes!r}']
        if self.linkmax is not None:
            out += [f'linkmax={self.linkmax!r}']
        if self.name_max is not None:
            out += [f'name_max={self.name_max!r}']
        if self.no_trunc is not None:
            out += [f'no_trunc={self.no_trunc!r}']
        if self.chown_restricted is not None:
            out += [f'chown_restricted={self.chown_restricted!r}']
        if self.case_insensitive is not None:
            out += [f'case_insensitive={self.case_insensitive!r}']
        if self.case_preserving is not None:
            out += [f'case_preserving={self.case_preserving!r}']
        return f"pathconf3resok({', '.join(out)})"


class pathconf3res:
    # XDR definition:
    # union pathconf3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         pathconf3resok resok;
    #     default:
    #         post_op_attr resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"pathconf3res({', '.join(out)})"


class commit3args:
    # XDR definition:
    # struct commit3args {
    #     nfs_fh3 file;
    #     uint64 offset;
    #     uint32 count;
    # };
    def __init__(self, file=None, offset=None, count=None):
        self.file = file
        self.offset = offset
        self.count = count

    def __repr__(self):
        out = []
        if self.file is not None:
            out += [f'file={self.file!r}']
        if self.offset is not None:
            out += [f'offset={self.offset!r}']
        if self.count is not None:
            out += [f'count={self.count!r}']
        return f"commit3args({', '.join(out)})"


class commit3resok:
    # XDR definition:
    # struct commit3resok {
    #     wcc_data file_wcc;
    #     writeverf3 verf;
    # };
    def __init__(self, file_wcc=None, verf=None):
        self.file_wcc = file_wcc
        self.verf = verf

    def __repr__(self):
        out = []
        if self.file_wcc is not None:
            out += [f'file_wcc={self.file_wcc!r}']
        if self.verf is not None:
            out += [f'verf={self.verf!r}']
        return f"commit3resok({', '.join(out)})"


class commit3res:
    # XDR definition:
    # union commit3res switch(nfsstat3 status) {
    #     case NFS3_OK:
    #         commit3resok resok;
    #     default:
    #         wcc_data resfail;
    # };
    def __init__(self, status=None, resok=None):
        self.status = status
        self.resok = resok

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'status={const.NFSSTAT3.get(self.status, self.status)}']
        if self.resok is not None:
            out += [f'resok={self.resok!r}']
        return f"commit3res({', '.join(out)})"


class setaclargs:
    # XDR definition:
    # struct setaclargs {
    #     diropargs3 dargs;
    #     write3args wargs;
    # };
    def __init__(self, dargs=None, wargs=None):
        self.dargs = dargs
        self.wargs = wargs

    def __repr__(self):
        out = []
        if self.dargs is not None:
            out += [f'dargs={self.dargs!r}']
        if self.wargs is not None:
            out += [f'wargs={self.wargs!r}']
        return f"setaclargs({', '.join(out)})"


class mountres3_ok:
    # XDR definition:
    # struct mountres3_ok {
    #     fhandle3 fhandle;
    #     int auth_flavors<>;
    # };
    def __init__(self, fhandle=None, auth_flavors=None):
        self.fhandle = fhandle
        self.auth_flavors = auth_flavors

    def __repr__(self):
        out = []
        if self.fhandle is not None:
            out += [f'fhandle={self.fhandle!r}']
        if self.auth_flavors is not None:
            out += [f'auth_flavors={self.auth_flavors!r}']
        return f"mountres3_ok({', '.join(out)})"


class mountres3:
    # XDR definition:
    # union mountres3 switch(mountstat3 fhs_status) {
    #     case MNT3_OK:
    #         mountres3_ok mountinfo;
    #     default:
    #         void;
    # };
    def __init__(self, fhs_status=None, mountinfo=None):
        self.status = fhs_status
        self.mountinfo = mountinfo

    def __repr__(self):
        out = []
        if self.status is not None:
            out += [f'fhs_status={const.MOUNTSTAT3.get(self.status, self.status)}']
        if self.mountinfo is not None:
            out += [f'mountinfo={self.mountinfo!r}']
        return f"mountres3({', '.join(out)})"


class mountbody:
    # XDR definition:
    # struct mountbody {
    #     name ml_hostname;
    #     dirpath ml_directory;
    #     mountlist ml_next;
    # };
    def __init__(self, ml_hostname=None, ml_directory=None, ml_next=None):
        self.ml_hostname = ml_hostname
        self.ml_directory = ml_directory
        self.ml_next = ml_next

    def __repr__(self):
        out = []
        if self.ml_hostname is not None:
            out += [f'ml_hostname={self.ml_hostname!r}']
        if self.ml_directory is not None:
            out += [f'ml_directory={self.ml_directory!r}']
        if self.ml_next is not None:
            out += [f'ml_next={self.ml_next!r}']
        return f"mountbody({', '.join(out)})"


class groupnode:
    # XDR definition:
    # struct groupnode {
    #     name gr_name;
    #     groups gr_next;
    # };
    def __init__(self, gr_name=None, gr_next=None):
        self.gr_name = gr_name
        self.gr_next = gr_next

    def __repr__(self):
        out = []
        if self.gr_name is not None:
            out += [f'gr_name={self.gr_name!r}']
        if self.gr_next is not None:
            out += [f'gr_next={self.gr_next!r}']
        return f"groupnode({', '.join(out)})"


class exportnode:
    # XDR definition:
    # struct exportnode {
    #     dirpath ex_dir;
    #     groups ex_groups;
    #     exports ex_next;
    # };
    def __init__(self, ex_dir=None, ex_groups=None, ex_next=None):
        self.ex_dir = ex_dir
        self.ex_groups = ex_groups
        self.ex_next = ex_next

    def __repr__(self):
        out = []
        if self.ex_dir is not None:
            out += [f'ex_dir={self.ex_dir!r}']
        if self.ex_groups is not None:
            out += [f'ex_groups={self.ex_groups!r}']
        if self.ex_next is not None:
            out += [f'ex_next={self.ex_next!r}']
        return f"exportnode({', '.join(out)})"
