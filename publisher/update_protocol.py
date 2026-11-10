"""Shared release format. No application data or credentials belong in a release."""
import base64, hashlib, json, os, re, shutil, stat, subprocess, zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

PRODUCT='qimao-prompt-workbench'
MAX_PACKAGE=64*1024*1024
MAX_EXPANDED=256*1024*1024
CHANNELS=('stable','beta')

class UpdateError(Exception):pass

def canonical(obj):return json.dumps({k:v for k,v in obj.items() if k!='signature'},ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def write_json(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.tmp');tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2));os.replace(tmp,path)
def node_crypto(op,**kwargs):
    candidates=[os.environ.get('QIMAO_NODE',''),shutil.which('node'),str(Path.home()/'.local/bin/node'),'/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node','/Applications/Codex.app/Contents/Resources/cua_node/bin/node']
    node=next((n for n in candidates if n and os.access(n,os.X_OK)),None)
    if not node:raise UpdateError('未找到 Node.js 签名运行时，请安装 Node.js 20 或更高版本')
    p=subprocess.run([node,str(Path(__file__).with_name('update_crypto.js'))],input=json.dumps(dict(op=op,**kwargs)),text=True,capture_output=True,timeout=20)
    if p.returncode:raise UpdateError('更新数字签名无效或签名运行时不可用')
    return json.loads(p.stdout)
def sign(obj,key):return dict(obj,signature=node_crypto('sign',key=key,payload=base64.b64encode(canonical(obj)).decode())['signature'])
def verify(obj,key):
    if not isinstance(obj,dict) or not isinstance(obj.get('signature'),str):raise UpdateError('更新文件缺少数字签名')
    node_crypto('verify',key=key,payload=base64.b64encode(canonical(obj)).decode(),signature=obj['signature'])
def version(value):
    if not isinstance(value,str) or not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)',value):raise UpdateError('版本号必须为三段数字，例如1.7.0')
    return tuple(map(int,value.split('.')))
def url(value):
    p=urlparse(str(value));local=p.hostname in ('localhost','127.0.0.1','::1')
    if (p.scheme!='https' and not (p.scheme=='http' and local)) or not p.hostname or p.username or p.password or p.query or p.fragment:raise UpdateError('更新地址须为HTTPS网址，本机测试可使用127.0.0.1的HTTP地址；勿包含密码或查询参数')
    return value
def code_path(value):
    p=PurePosixPath(value)
    if not value or '\\' in value or p.is_absolute() or '..' in p.parts or str(p)!=value:return False
    if any(part.startswith('.') for part in p.parts):return False
    if any(part in ('data','maintenance-backups','__pycache__','preview','updates','node_modules') for part in p.parts):return False
    return value=='SKILL.md' or value.startswith('agents/') or value=='scripts/workbench.py' or value.startswith('scripts/workbench/')
def manifest_check(m,key,channel=None):
    verify(m,key)
    if m.get('schema')!=1 or m.get('product')!=PRODUCT:raise UpdateError('不是七猫工作台的更新清单')
    if m.get('channel') not in CHANNELS or (channel and m['channel']!=channel):raise UpdateError('更新渠道不匹配')
    version(m.get('version'));url(m.get('package_url'))
    if type(m.get('size')) is not int or not 0<m['size']<=MAX_PACKAGE or not re.fullmatch('[0-9a-f]{64}',str(m.get('sha256',''))):raise UpdateError('更新包大小或SHA-256无效')
    if not isinstance(m.get('notes'),list) or len(m['notes'])>50 or any(not isinstance(n,str) or len(n)>2000 for n in m['notes']):raise UpdateError('更新说明格式无效')
    if len(base64.b64encode(json.dumps(m,ensure_ascii=False).encode()))>32000:raise UpdateError('更新说明总长度过长，请缩短说明文字')
    return m
def inspect_package(path,key,expected=None):
    path=Path(path)
    if not 0<path.stat().st_size<=MAX_PACKAGE:raise UpdateError('更新包为空或超过64MB')
    if expected and (path.stat().st_size!=expected['size'] or sha(path.read_bytes())!=expected['sha256']):raise UpdateError('更新包大小或SHA-256不匹配')
    try:
        with zipfile.ZipFile(path) as z:
            infos=z.infolist();names=[i.filename for i in infos]
            if len(names)>5000 or len(names)!=len(set(names)) or sum(i.file_size for i in infos)>MAX_EXPANDED:raise UpdateError('更新包重复文件、数量或解压大小异常')
            if 'release.json' not in names or z.getinfo('release.json').file_size>1024*1024:raise UpdateError('缺少有效的签名发布清单')
            release=json.loads(z.read('release.json'));verify(release,key)
            if release.get('product')!=PRODUCT or release.get('schema')!=1:raise UpdateError('更新包产品不匹配')
            version(release.get('version'))
            if release.get('channel') not in CHANNELS:raise UpdateError('更新包渠道无效')
            if expected and any(release.get(k)!=expected.get(k) for k in ('version','channel','product')):raise UpdateError('内外发布信息不一致')
            files=release.get('files',{})
            if not isinstance(files,dict) or set(names)!={'release.json',*files}:raise UpdateError('更新文件与签名清单不一致')
            required={'SKILL.md','scripts/workbench.py','scripts/workbench/server.py','scripts/workbench/web/index.html','scripts/workbench/update-public.pem','scripts/workbench/version.json'}
            if not required.issubset(files):raise UpdateError('更新包缺少工作台必需文件')
            for info in infos:
                mode=info.external_attr>>16
                if info.is_dir() or (stat.S_IFMT(mode) not in (0,stat.S_IFREG)) or info.flag_bits&1:raise UpdateError('更新包含链接、特殊文件或加密文件')
                if info.filename=='release.json':continue
                spec=files[info.filename]
                if not code_path(info.filename) or not isinstance(spec,dict) or sha(z.read(info))!=spec.get('sha256') or spec.get('mode') not in (0o644,0o755):raise UpdateError('更新文件路径、权限或SHA-256校验失败')
            if z.read('scripts/workbench/update-public.pem').decode().strip()!=key.strip():raise UpdateError('更新包不能替换发布公钥')
            v=json.loads(z.read('scripts/workbench/version.json'))
            skill=z.read('SKILL.md').decode()
            if v.get('version')!=release['version'] or f'version: "{release["version"]}"' not in skill:raise UpdateError('工作台与Skill版本不一致')
            return release
    except (zipfile.BadZipFile,KeyError,ValueError,UnicodeError,TypeError,AttributeError) as e:raise UpdateError('更新包格式损坏') from e
