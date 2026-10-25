"""`recguard` command line: serve the API, print dev secrets, verify an audit chain."""
from __future__ import annotations
import argparse, json, os, secrets, shlex, sys

DEV_SCOPES={
    'serve':['recommend:serve','metrics:read','audit:read','policy:read'],
    'present':['recommend:present'],
    'event':['telemetry:write'],
    'outcome':['outcomes:write'],
    'learner':['learning:admin'],
    'data':['data:admin'],
    'policy':['policy:write','policy:read'],
}


def dev_env(tenant:str):
    tokens={secrets.token_urlsafe(32):{'tenant_id':'*' if k=='policy' else tenant,'scopes':v} for k,v in DEV_SCOPES.items()}
    print('## DEVELOPMENT ONLY — do not use these secrets in a deployed installation.')
    print('export RECGUARD_SIGNING_KEY='+shlex.quote(secrets.token_urlsafe(48)))
    print('export RECGUARD_TOKENS_JSON='+shlex.quote(json.dumps(tokens)))
    print('export RECGUARD_DB='+shlex.quote('recguard-dev.db'))
    print('## token list:')
    for token,info in tokens.items():
        print('#',info['tenant_id'],','.join(info['scopes']),token)


def main(argv=None):
    parser=argparse.ArgumentParser(prog='recguard')
    sub=parser.add_subparsers(dest='cmd',required=True)
    s=sub.add_parser('serve',help='run the HTTP API (needs the `server` extra)')
    s.add_argument('--host',default='127.0.0.1');s.add_argument('--port',type=int,default=8765)
    d=sub.add_parser('dev-env',help='print throwaway local secrets');d.add_argument('--tenant',default='demo')
    a=sub.add_parser('audit',help='verify a tenant audit chain in a database file')
    a.add_argument('tenant');a.add_argument('--db',default=os.getenv('RECGUARD_DB','recguard.db'))
    a.add_argument('--expected-head')
    args=parser.parse_args(argv)
    if args.cmd=='dev-env':
        dev_env(args.tenant)
    elif args.cmd=='serve':
        try:import uvicorn
        except ImportError:sys.exit("install the server extra: pip install 'recguard-kernel[server]'")
        uvicorn.run('recguard.api:from_environment',factory=True,host=args.host,port=args.port,workers=1)
    elif args.cmd=='audit':
        key=os.environ.get('RECGUARD_SIGNING_KEY')
        if not key:sys.exit('RECGUARD_SIGNING_KEY is required')
        from .storage import Store
        result=Store(args.db,key.encode()).audit_verify(args.tenant,args.expected_head)
        print(json.dumps(result));sys.exit(0 if result['valid'] else 1)


if __name__=='__main__':
    main()
