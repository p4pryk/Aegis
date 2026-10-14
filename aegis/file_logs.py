"""Bounded, read-only syslog tailers. Cursors and normalized events commit together."""
import hashlib, os, pathlib, stat, time
from system_sources import family, parse, text_record

class Files:
    def __init__(self,engine,paths):
        self.engine=engine;self.paths=paths;self.handles={};self.health={};self.last_poll=0
    def close(self):
        for stream in self.handles.values():stream.close()
        self.handles={}
    def trusted(self,info,path):
        return stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
    def open(self,path):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        stream=os.fdopen(fd,'rb');info=os.fstat(fd)
        if not self.trusted(info,path):
            stream.close();raise ValueError('Expected an approved owner and a non-writable regular log file')
        return stream
    def poll(self,force=False):
        now=time.time()
        if not force and now-self.last_poll<.2:return 0
        self.last_poll=now;count=0
        # One authoritative file per category, avoiding auth/kernel/cron copies in syslog.
        available=set()
        for category,path in self.paths.items():
            try:
                info=os.stat(path,follow_symlinks=False)
                if self.trusted(info,path):available.add(category)
            except OSError:pass
        for category,path in self.paths.items():
            h=self.health.setdefault(category,dict(name=category+' file',path=path,read=0,parsed=0,unrecognized=0,duplicates=0,stale=0,invalid=0))
            key=self.cursor_key(category,path)
            try:
                cursor=self.engine.store.state(key) or {};gap=cursor.get('gap',False)
                stream=self.handles.get(path)
                if stream is None:
                    stream=self.open(path);self.handles[path]=stream
                info=os.fstat(stream.fileno())
                if not self.trusted(info,path):raise ValueError('Log permissions changed')
                identity=[info.st_dev,info.st_ino]
                position=cursor.get('offset',0)
                if cursor.get('identity')!=identity:
                    gap=bool(cursor) or info.st_size>1048576
                    position=max(0,info.st_size-1048576)
                    if position:stream.seek(position);stream.readline(8193);position=stream.tell()
                    cursor={'identity':identity,'offset':position,'generation':cursor.get('generation',0)+1,'gap':gap}
                stream.seek(position)
                anchor=cursor.get('anchor')
                if info.st_size<position or (anchor and self.anchor(stream,position)!=anchor):
                    position=0;gap=True;cursor.update(generation=cursor.get('generation',0)+1,discard=False)
                stream.seek(position)
                with self.engine.store.atomic():
                    for _ in range(25):
                        start=stream.tell();raw=stream.readline(8193)
                        if not raw:break
                        if cursor.get('discard'):
                            cursor['discard']=not raw.endswith(b'\n');position=stream.tell();continue
                        if len(raw)>8192:
                            h['invalid']+=1;gap=True;cursor['discard']=not raw.endswith(b'\n');position=stream.tell();continue
                        if not raw.endswith(b'\n'):
                            stream.seek(start);break  # Finish the line after the producer appends its newline.
                        position=stream.tell();h['read']+=1;count+=1;h['last_record_at']=now
                        identifier='file:'+hashlib.sha256((path+':'+str(identity)+':'+str(cursor['generation'])+':'+str(start)).encode()).hexdigest()
                        self.accept(category,raw,identifier,now,available,h)
                    cursor.update(identity=identity,offset=position,anchor=self.anchor(stream,position),gap=gap)
                    self.engine.store.state(key,cursor)
                # Drain the old inode before switching on rename rotation. Never open compressed archives.
                current=os.stat(path,follow_symlinks=False)
                if [current.st_dev,current.st_ino]!=identity and position>=os.fstat(stream.fileno()).st_size:
                    stream.close();self.handles.pop(path,None)
                pending=max(0,os.fstat(stream.fileno()).st_size-position) if not stream.closed else 0
                h.update(pending=pending,unit='bytes',checked_at=now,lag_seconds=max(0,now-h.get('pending_since',now)) if pending else 0)
                if pending:h.setdefault('pending_since',now)
                else:h.pop('pending_since',None)
                h.update(status='GAP' if gap else 'LAGGING' if pending and h['lag_seconds']>=5 else 'LIVE' if now-h.get('last_record_at',0)<30 else 'QUIET',reason='Rotation/truncation or bounded startup replay: continuity is not guaranteed' if gap else 'File is readable; producer liveness is not independently verified')
            except (OSError,ValueError) as exc:
                h.update(status='MISSING' if isinstance(exc,FileNotFoundError) else 'DOWN',reason=type(exc).__name__+': source unavailable or unsafe',checked_at=now,pending=0,unit='bytes',lag_seconds=0)
        return count
    def cursor_key(self,category,path):
        return 'file_cursor_'+hashlib.sha256(path.encode()).hexdigest()[:16]
    def accept(self,category,raw,identifier,now,available,h):
        try:record=text_record(raw.decode('utf-8').rstrip('\n'),now)
        except UnicodeError:record=None
        if not record:h['unrecognized']+=1;return
        program,stamp,message,inferred=record;target=family(program)
        if category=='system' and target!='system' and target in available:
            h['duplicates']+=1;return
        if not -5<=now-stamp<=600:h['stale']+=1;return
        event=parse(program,message,stamp,identifier,self.paths[category])
        if event:
            event['details']['timestamp_inferred']=inferred
            from system_sources import ingest
            ingest(self.engine,event);h['parsed']+=1
        else:h['unrecognized']+=1
    @staticmethod
    def anchor(stream,position):
        stream.seek(max(0,position-64));return hashlib.sha256(stream.read(min(64,position))).hexdigest()
    def sources(self):
        return [dict(h) for h in self.health.values()]
