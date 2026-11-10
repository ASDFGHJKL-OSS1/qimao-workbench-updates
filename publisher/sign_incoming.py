"""仅执行受信任的发布代码；上传的程序文件不执行。"""
import base64,hashlib,io,json,os,re,stat,subprocess,tempfile,urllib.request,zipfile
from pathlib import Path
from update_protocol import code_path,sign,inspect_package,write_json,version,sha,MAX_PACKAGE,MAX_EXPANDED,PRODUCT
ROOT=Path(__file__).resolve().parents[1]
def api(path):
 req=urllib.request.Request('https://api.github.com/repos/'+os.environ['GITHUB_REPOSITORY']+'/'+path,headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
 with urllib.request.urlopen(req,timeout=45) as r:return json.load(r)
def load_request(p):
 req=json.loads(p.read_text());ident=req.get('id','')
 if not re.fullmatch('[0-9a-f]{32}',ident) or p.name!=ident+'.json':raise ValueError('发布请求编号无效')
 if req.get('channel')!='stable':raise ValueError('只能发布正式版本')
 blobs=req.get('blobs',[])
 if not isinstance(blobs,list) or not 1<=len(blobs)<=128 or any(not re.fullmatch('[0-9a-f]{40}',str(b)) for b in blobs):raise ValueError('上传分块无效')
 data=bytearray()
 for b in blobs:
  data.extend(base64.b64decode(api('git/blobs/'+b)['content']))
  if len(data)>MAX_PACKAGE:raise ValueError('程序包超过64MB')
 if sha(data)!=req.get('sha256'):raise ValueError('上传分块校验不一致')
 return req,bytes(data)
def validate(data,public):
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  infos=z.infolist();names=[i.filename for i in infos]
  if len(names)>5000 or len(names)!=len(set(names)) or sum(i.file_size for i in infos)>MAX_EXPANDED:raise ValueError('文件数、解压大小或重复文件异常')
  files={};modes={}
  for i in infos:
   if not code_path(i.filename) or i.is_dir() or i.flag_bits&1 or stat.S_IFMT(i.external_attr>>16) not in (0,stat.S_IFREG):raise ValueError('程序包含非法文件')
   if Path(i.filename).name in ('admin-auth.json','auth.json','config.toml','.env'):raise ValueError('不允许上传凭据')
   files[i.filename]=z.read(i);modes[i.filename]=0o755 if i.external_attr>>16&0o111 else 0o644
  required={'SKILL.md','scripts/workbench.py','scripts/workbench/server.py','scripts/workbench/web/index.html','scripts/workbench/update-public.pem','scripts/workbench/version.json'}
  if not required<=files.keys():raise ValueError('程序包缺少必要文件')
  if files['scripts/workbench/update-public.pem'].decode().strip()!=public.strip():raise ValueError('禁止更换发布公钥')
  return files,modes

def publish(request_path):
 public=(ROOT/'publisher/update-public.pem').read_text();req,data=load_request(request_path)
 current=json.loads((ROOT/'channels/stable/latest.json').read_text())
 if req.get('base_version')!=current['version']:raise ValueError('发布基线已改变，请先更新工作台后再发布')
 files,modes=validate(data,public)
 v=version(current['version']);new='.'.join(map(str,(*v[:2],v[2]+1)))
 files['scripts/workbench/version.json']=json.dumps({'product':PRODUCT,'version':new},ensure_ascii=False,indent=2).encode()
 text=files['SKILL.md'].decode();text,n=re.subn(r'(?m)^(  version:) "[0-9]+\.[0-9]+\.[0-9]+"',r'\1 "'+new+'"',text,count=1)
 if n!=1:raise ValueError('技能版本标记缺失')
 files['SKILL.md']=text.encode()
 import datetime
 when=datetime.datetime.now(datetime.timezone.utc).isoformat();key=os.environ['SIGNING_PRIVATE_KEY']
 notes=req.get('notes') or ['工作台功能更新']
 if not isinstance(notes,list) or len(notes)>50 or any(not isinstance(n,str) or len(n)>2000 for n in notes):raise ValueError('更新说明无效')
 release=sign({'schema':1,'product':PRODUCT,'version':new,'channel':'stable','published_at':when,'notes':notes,'files':{n:{'sha256':sha(b),'mode':modes[n]} for n,b in files.items()}},key)
 out=ROOT/'packages'/f'qimao-workbench-{new}-stable.zip';out.parent.mkdir(exist_ok=True)
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  for n,b in files.items():
   i=zipfile.ZipInfo(n);i.external_attr=(stat.S_IFREG|modes[n])<<16;i.compress_type=zipfile.ZIP_DEFLATED;z.writestr(i,b)
  z.writestr('release.json',json.dumps(release,ensure_ascii=False))
 m=sign({'schema':1,'product':PRODUCT,'version':new,'channel':'stable','published_at':when,'notes':notes,'package_url':'https://asdfghjkl-oss1.github.io/qimao-workbench-updates/packages/'+out.name,'sha256':sha(out.read_bytes()),'size':out.stat().st_size,'request_id':req['id']},key)
 inspect_package(out,public,m);write_json(ROOT/'channels/stable/latest.json',m)
 (ROOT/'index.html').write_text('<!doctype html><meta charset="utf-8"><h1>七猫工作台更新</h1><p>正式版本 '+new+'</p>')
 print('已签名发布 v'+new)
if __name__=='__main__':
 changed=subprocess.check_output(['git','diff-tree','--no-commit-id','--name-only','-r','HEAD'],cwd=ROOT,text=True).splitlines()
 paths=[ROOT/p for p in changed if re.fullmatch(r'incoming/[0-9a-f]{32}\.json',p)]
 if len(paths)!=1:raise SystemExit('一次只接受一个管理员发布请求')
 publish(paths[0])
