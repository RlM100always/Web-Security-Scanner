let csrfToken='';

export function setCsrfToken(value:string|null|undefined){
  csrfToken=value||'';
}

export function getCsrfToken(){
  return csrfToken;
}

export async function api(path:string,opts:RequestInit={}){
  const headers:any={'Content-Type':'application/json',...(opts.headers||{})};
  const method=(opts.method||'GET').toUpperCase();
  if(csrfToken&&!['GET','HEAD','OPTIONS'].includes(method))headers['X-CSRF-Token']=csrfToken;
  const r=await fetch('/api/v1'+path,{credentials:'include',...opts,headers});
  const text=await r.text();let d:any={};
  try{d=text?JSON.parse(text):{}}catch{d={error:text||'Request failed'}}
  if(!r.ok){const e:any=new Error(d.error||'Request failed');e.data=d;e.status=r.status;throw e}
  return d;
}

export function csrfHeaders():Record<string,string>{
  return csrfToken?{'X-CSRF-Token':csrfToken}:{};
}
