"""Text-only adapters. No tools, wallet credentials, redirects, or proxy inheritance."""
import json,os,re,urllib.parse,urllib.request,urllib.error
PROVIDERS={
 'nemotron':('http://127.0.0.1:5051/v1/chat/completions','NEMOTRON_API_KEY','chat'),
 'openai':('https://api.openai.com/v1/chat/completions','OPENAI_API_KEY','openai'),
 'grok':('https://api.x.ai/v1/chat/completions','XAI_API_KEY','chat'),
 'claude':('https://api.anthropic.com/v1/messages','ANTHROPIC_API_KEY','claude'),
 'ollama':('http://127.0.0.1:11434/api/chat','','ollama'),
 'custom':('','TRU_AGENT_API_KEY','chat'),
}
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None

def settings(provider,endpoint,model,key_env=None,allow_remote=False):
 if provider not in PROVIDERS:raise ValueError('Unknown provider')
 default,env,wire=PROVIDERS[provider];endpoint=endpoint or default
 p=urllib.parse.urlsplit(endpoint)
 if (not p.hostname or p.username or p.password or p.query or p.fragment
     or any(c.isspace() or ord(c)<32 for c in endpoint) or any(c in endpoint for c in '[]()') and p.hostname!='::1'):
  raise ValueError('Endpoint must be a plain URL without credentials, query, fragment or Markdown')
 local=p.hostname in ('127.0.0.1','::1')
 if p.scheme not in ('http','https') or (p.scheme=='http' and not local):raise ValueError('Remote endpoints require HTTPS')
 if local and not p.port:raise ValueError('Loopback endpoint needs explicit port')
 if not local and not allow_remote:raise ValueError('Remote provider sends prompts and saved memories off-host: use --allow-remote explicitly')
 if provider in ('openai','grok','claude'):
  target=urllib.parse.urlsplit(default)
  if (p.scheme,p.netloc,p.path)!=(target.scheme,target.netloc,target.path):raise ValueError('Official provider endpoint is fixed; use custom for other chat-completions services')
 elif provider=='ollama' and p.path!='/api/chat':raise ValueError('Ollama native adapter requires /api/chat')
 elif provider!='ollama' and not p.path.endswith('/chat/completions'):raise ValueError('Chat adapter requires a /chat/completions endpoint')
 env=env if key_env is None else key_env
 if env and not re.fullmatch('[A-Z][A-Z0-9_]{0,79}',env):raise ValueError('Invalid API-key environment variable name')
 if not isinstance(model,str) or not model.strip() or len(model)>200 or any(ord(c)<32 for c in model):raise ValueError('Supply your actual supported model ID')
 return {'provider':provider,'endpoint':endpoint,'model':model,'api_key_env':env,'allow_remote':bool(allow_remote)}

def validate(config):
 return settings(config.get('provider','nemotron'),config['endpoint'],config['model'],config.get('api_key_env'),config.get('allow_remote',False))

def build(config,messages):
 c=validate(config);provider=c['provider'];wire=PROVIDERS[provider][2]
 headers={'Content-Type':'application/json'};key=os.environ.get(c['api_key_env'],'') if c['api_key_env'] else ''
 if provider in ('openai','grok','claude') and not key:raise ValueError('Missing provider credential in '+c['api_key_env'])
 if '\r' in key or '\n' in key:raise ValueError('Invalid API credential')
 if wire=='claude':
  headers['anthropic-version']='2023-06-01'
  if key:headers['x-api-key']=key
  payload={'model':c['model'],'system':messages[0]['content'],'messages':messages[1:],'max_tokens':512,'stream':False}
 elif wire=='ollama':
  if key:headers['Authorization']='Bearer '+key
  payload={'model':c['model'],'messages':messages,'stream':False,'options':{'num_predict':512}}
 else:
  if key:headers['Authorization']='Bearer '+key
  payload={'model':c['model'],'messages':messages,'stream':False}
  payload['max_completion_tokens' if wire=='openai' else 'max_tokens']=512
 return c,headers,payload

def parse(provider,result):
 if not isinstance(result,dict) or result.get('error'):raise ValueError('Provider returned an error/invalid response')
 try:
  if provider=='claude':
   text='\n'.join(x['text'] for x in result['content'] if x.get('type')=='text')
  elif provider=='ollama':text=result['message']['content']
  else:text=result['choices'][0]['message']['content']
 except (KeyError,TypeError,IndexError):raise ValueError('Provider did not return supported text content') from None
 if not isinstance(text,str) or not text.strip() or len(text)>16000:raise ValueError('Provider returned empty or oversized text')
 return text

def complete(config,messages):
 c,headers,payload=build(config,messages)
 req=urllib.request.Request(c['endpoint'],data=json.dumps(payload,ensure_ascii=False).encode(),headers=headers,method='POST')
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 try:
  with opener.open(req,timeout=90) as r:data=r.read(1048577)
 except urllib.error.HTTPError as e:raise ValueError('Provider HTTP '+str(e.code)+'; check model/authentication. No chat turn saved.') from None
 except (urllib.error.URLError,TimeoutError):raise ValueError('Provider unavailable or timed out. No chat turn saved.') from None
 if len(data)>1048576:raise ValueError('Provider response exceeds 1 MiB')
 return parse(c['provider'],json.loads(data))
