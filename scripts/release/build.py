#!/usr/bin/env python3
"""Build complete source archives and the dependency-free Lambda ZIP from an exact Git commit."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def build(version, output, ref='HEAD'):
    if not __import__('re').fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('version must be vX.Y.Z')
    commit=subprocess.check_output(['git','rev-parse',ref+'^{commit}'],cwd=ROOT,text=True).strip()
    version_file=subprocess.check_output(['git','show',commit+':VERSION'],cwd=ROOT,text=True).strip()
    if version_file!=version[1:]: raise ValueError('Tag and VERSION disagree')
    epoch=int(subprocess.check_output(['git','show','-s','--format=%ct',commit],cwd=ROOT,text=True).strip())
    archive=subprocess.check_output(['git','archive','--format=tar',commit],cwd=ROOT)
    source=tarfile.open(fileobj=io.BytesIO(archive))
    files={member.name:source.extractfile(member).read() for member in source.getmembers() if member.isfile()}
    if any(member.issym() or member.islnk() for member in source.getmembers()): raise ValueError('Release does not accept symlinked source files')
    output.mkdir(parents=True,exist_ok=True)
    stem='awsec2config-'+version
    # git archive includes all tracked .github, scripts, runtime, tests, configuration and docs.
    zip_path=output/(stem+'-source.zip')
    with zipfile.ZipFile(zip_path,'w',compression=zipfile.ZIP_DEFLATED) as package:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(stem+'/'+name,date_time=(2020,1,1,0,0,0)); info.external_attr=0o100644<<16
            info.compress_type=zipfile.ZIP_DEFLATED; package.writestr(info,data)
    tar_bytes=io.BytesIO()
    with tarfile.open(fileobj=tar_bytes,mode='w') as package:
        for name,data in sorted(files.items()):
            info=tarfile.TarInfo(stem+'/'+name); info.size=len(data); info.mode=0o644; info.mtime=epoch
            package.addfile(info,io.BytesIO(data))
    (output/(stem+'-source.tar.gz')).write_bytes(gzip.compress(tar_bytes.getvalue(),mtime=0))
    with zipfile.ZipFile(output/(stem+'-lambda.zip'),'w',compression=zipfile.ZIP_DEFLATED) as package:
        for name,data in sorted(files.items()):
            if name.startswith('lambda_src/') and name.endswith('.py'):
                info=zipfile.ZipInfo(name.removeprefix('lambda_src/'),date_time=(2020,1,1,0,0,0))
                info.compress_type=zipfile.ZIP_DEFLATED; info.external_attr=0o100644<<16; package.writestr(info,data)
    payloads=[output/(stem+suffix) for suffix in ('-source.zip','-source.tar.gz','-lambda.zip')]
    digests={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in payloads}
    manifest={'version':version,'commit':commit,'commit_epoch':epoch,'sha256':digests,'source_files':sorted(files),
              'runtime_dependency':'AWS Lambda Python 3.12 bundled boto3; no vendored third-party runtime required'}
    manifest_path=output/'RELEASE-MANIFEST.json'; manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
    digests[manifest_path.name]=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    (output/'SHA256SUMS.txt').write_text(''.join(f'{sha}  {name}\n' for name,sha in sorted(digests.items())))
    print(json.dumps({'commit':commit,'artifacts':list(digests)},indent=2))
    return manifest


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',required=True); parser.add_argument('--output',type=Path,default=ROOT/'dist'); parser.add_argument('--ref',default='HEAD')
    args=parser.parse_args(); build(args.version,args.output,args.ref)
