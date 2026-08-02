"""Offline builder for the server-side AES profiling template."""
import argparse
from pathlib import Path
from trace_loader import load_plaintexts, load_traces
from template_store import build_template_model, default_template_path, save_template_model, template_status

def load_file(path:Path,plaintext:bool=False):
    data=path.read_bytes()
    return load_plaintexts(data,path.name) if plaintext else load_traces(data,path.name)

def main():
    parser=argparse.ArgumentParser(description="建立 SCA 平台伺服器端 Template Attack 模型")
    parser.add_argument("--aes",type=int,choices=(128,256),required=True,help="AES 版本")
    parser.add_argument("--traces",type=Path,required=True,help="profiling traces (.npy/.csv/.h5/.trs)")
    parser.add_argument("--plaintexts",type=Path,required=True,help="profiling plaintexts/text-in (.npy/.csv/.h5)")
    parser.add_argument("--keys",type=Path,required=True,help="每條 profiling trace 的已知 key")
    parser.add_argument("--output",type=Path,help="輸出 .npz；預設 api/templates/aesXXX_default.npz")
    parser.add_argument("--poi",type=int,default=10,help="每個 byte 的 POI 數，預設 10")
    parser.add_argument("--regularization",type=float,default=1e-6,help="covariance 正則化比例")
    args=parser.parse_args()
    traces=load_file(args.traces); plaintexts=load_file(args.plaintexts,True); keys=load_file(args.keys,True)
    print(f"Profiling data: traces={traces.shape}, plaintexts={plaintexts.shape}, keys={keys.shape}")
    model=build_template_model(args.aes,traces,plaintexts,keys,args.poi,args.regularization)
    path=save_template_model(model,args.output or default_template_path(args.aes))
    status=template_status(args.aes) if args.output is None else {"ready":True,"path":str(path)}
    print(f"Template ready: {status['ready']}")
    print(f"Saved to: {path}")
    print("請重新啟動 FastAPI，或重新整理平台的模板狀態。")

if __name__=="__main__": main()