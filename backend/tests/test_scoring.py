import os,sys
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))
from app.scanner.checks import mk
from app.scanner.engine import calculate_score
def test_score_penalty():
 f=mk('x','X','C','FAIL','HIGH','HIGH','https://example.com','e','d','i','r',[])
 assert calculate_score([f])==90
