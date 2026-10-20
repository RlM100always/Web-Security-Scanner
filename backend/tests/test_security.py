import os,sys
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))
from app.security.targets import normalize_url,validate_target,TargetValidationError,same_origin

def test_normalize(): assert normalize_url('example.com')=='https://example.com/'
def test_private_blocked():
    try: validate_target('http://127.0.0.1',False); assert False
    except TargetValidationError: pass
def test_same_origin(): assert same_origin('https://a.test/x','https://a.test/y')
