"""Small non-destructive HTTP load smoke test for your own SentinelScope deployment."""
import argparse
import statistics
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

def hit(url,timeout):
    started=time.perf_counter()
    try:
        with urllib.request.urlopen(url,timeout=timeout) as r:
            r.read(512)
            return r.status,(time.perf_counter()-started)*1000
    except Exception:
        return 0,(time.perf_counter()-started)*1000

def main():
    p=argparse.ArgumentParser()
    p.add_argument("url",help="Health URL, e.g. http://127.0.0.1:5000/health")
    p.add_argument("--requests",type=int,default=100)
    p.add_argument("--concurrency",type=int,default=10)
    p.add_argument("--timeout",type=float,default=5)
    a=p.parse_args()
    if a.requests>5000 or a.concurrency>100:
        raise SystemExit("Safety cap: <=5000 requests and <=100 concurrent workers")
    started=time.perf_counter()
    with ThreadPoolExecutor(max_workers=a.concurrency) as ex:
        results=[f.result() for f in as_completed([ex.submit(hit,a.url,a.timeout) for _ in range(a.requests)])]
    elapsed=time.perf_counter()-started
    lat=[x[1] for x in results];ok=sum(1 for code,_ in results if 200<=code<400)
    lat_sorted=sorted(lat)
    p95=lat_sorted[min(len(lat_sorted)-1,int(len(lat_sorted)*.95))]
    print(f"requests={len(results)} ok={ok} failed={len(results)-ok} elapsed_s={elapsed:.2f} rps={len(results)/elapsed:.1f}")
    print(f"latency_ms mean={statistics.mean(lat):.1f} median={statistics.median(lat):.1f} p95={p95:.1f} max={max(lat):.1f}")

if __name__=="__main__":main()
