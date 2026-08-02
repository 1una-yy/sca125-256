"""Build, save, load, and score server-side profiling templates.

The saved NPZ contains statistical templates only (POIs, means, covariances,
and SNR). End users therefore only upload target traces and plaintexts.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import numpy as np
from scipy.stats import multivariate_normal
from aes256_utils import AES_Sbox, compute_state_before_rk1, hw_table

MODEL_VERSION = 1
DEFAULT_POI_NUM = 10
DEFAULT_REGULARIZATION = 1e-6
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
K256 = np.arange(256, dtype=np.uint8)

def default_template_path(aes_bits: int) -> Path:
    if aes_bits not in (128, 256): raise ValueError("aes_bits 必須是 128 或 256")
    return TEMPLATE_DIR / f"aes{aes_bits}_default.npz"

def _validate_profiling_arrays(aes_bits, traces, plaintexts, keys, poi_num):
    traces=np.asarray(traces,dtype=np.float64); plaintexts=np.asarray(plaintexts,dtype=np.uint8); keys=np.asarray(keys,dtype=np.uint8)
    if traces.ndim!=2 or traces.shape[0]<2: raise ValueError(f"profiling traces 必須是 (N, L) 且 N >= 2，目前為 {traces.shape}")
    if plaintexts.ndim!=2 or plaintexts.shape[1]!=16: raise ValueError(f"profiling plaintexts 必須是 (N, 16)，目前為 {plaintexts.shape}")
    expected=16 if aes_bits==128 else 32
    if keys.ndim!=2 or keys.shape[1]!=expected: raise ValueError(f"AES-{aes_bits} profiling keys 必須是 (N, {expected})，目前為 {keys.shape}")
    if traces.shape[0]!=plaintexts.shape[0] or traces.shape[0]!=keys.shape[0]: raise ValueError(f"profiling traces/plaintexts/keys 筆數必須一致：{traces.shape[0]}/{plaintexts.shape[0]}/{keys.shape[0]}")
    if not np.isfinite(traces).all(): raise ValueError("profiling traces 含有 NaN 或 Infinity")
    if not 1<=poi_num<=traces.shape[1]: raise ValueError(f"poi_num 必須介於 1 與 trace length {traces.shape[1]} 之間")
    return traces,plaintexts,keys

def _build_phase_model(traces, labels, poi_num, regularization):
    num_traces,trace_length=traces.shape
    if labels.shape!=(num_traces,16): raise ValueError(f"HW labels 必須是 ({num_traces}, 16)，目前為 {labels.shape}")
    signal=np.zeros((16,trace_length)); noise=np.zeros((16,trace_length)); counts=np.zeros((16,9),dtype=np.int64)
    for b in range(16):
        group_means=np.zeros((9,trace_length)); group_vars=np.zeros((9,trace_length))
        for hw in range(9):
            group=traces[labels[:,b]==hw]; counts[b,hw]=len(group)
            if len(group): group_means[hw]=group.mean(axis=0); group_vars[hw]=group.var(axis=0)
        prob=counts[b]/num_traces
        signal[b]=np.sum(group_means**2*prob[:,None],axis=0)-np.sum(group_means*prob[:,None],axis=0)**2
        noise[b]=np.sum(group_vars*prob[:,None],axis=0)
    with np.errstate(divide="ignore",invalid="ignore"): snr=np.where(noise>0,signal/noise,0.0)
    snr=np.nan_to_num(snr,nan=0.0,posinf=0.0,neginf=0.0); poi=np.argsort(snr,axis=1)[:,-poi_num:]
    minimum=poi_num+2; sparse=np.argwhere(counts<minimum)
    if sparse.size:
        b,hw=sparse[0]; raise ValueError(f"profiling traces 不足以建立穩定 covariance：byte {b} / HW {hw} 只有 {counts[b,hw]} 條，至少需要 {minimum} 條。請增加 profiling traces。")
    means=np.zeros((16,9,poi_num)); covs=np.zeros((16,9,poi_num,poi_num))
    for b in range(16):
        trace_poi=traces[:,poi[b]]
        for hw in range(9):
            group=trace_poi[labels[:,b]==hw]; means[b,hw]=group.mean(axis=0)
            cov=np.atleast_2d(np.cov(group,rowvar=False,ddof=1)); scale=max(float(np.mean(np.diag(cov))),1e-12)
            cov+=np.eye(poi_num)*(regularization*scale); covs[b,hw]=cov
    return {"snr":snr,"poi":poi.astype(np.int32),"mean":means,"covariance":covs,"counts":counts}

def build_template_model(aes_bits, traces, plaintexts, keys, poi_num=DEFAULT_POI_NUM, regularization=DEFAULT_REGULARIZATION):
    if aes_bits not in (128,256): raise ValueError("aes_bits 必須是 128 或 256")
    if regularization<=0: raise ValueError("regularization 必須大於 0")
    traces,plaintexts,keys=_validate_profiling_arrays(aes_bits,traces,plaintexts,keys,poi_num)
    phase1=_build_phase_model(traces,hw_table[AES_Sbox[plaintexts^keys[:,:16]]],poi_num,regularization)
    model={"model_version":np.array(MODEL_VERSION,dtype=np.int32),"aes_bits":np.array(aes_bits,dtype=np.int32),"trace_length":np.array(traces.shape[1],dtype=np.int32),"profiling_traces":np.array(traces.shape[0],dtype=np.int32),"poi_num":np.array(poi_num,dtype=np.int32),"regularization":np.array(regularization,dtype=np.float64),"created_utc":np.array(datetime.now(timezone.utc).isoformat())}
    model.update({f"phase1_{name}":value for name,value in phase1.items()})
    if aes_bits==256:
        state=compute_state_before_rk1(plaintexts,keys[:,:16])
        phase2=_build_phase_model(traces,hw_table[AES_Sbox[state^keys[:,16:32]]],poi_num,regularization)
        model.update({f"phase2_{name}":value for name,value in phase2.items()})
    return model

def save_template_model(model, path=None):
    aes_bits=int(np.asarray(model["aes_bits"]).item()); target=Path(path) if path is not None else default_template_path(aes_bits)
    target.parent.mkdir(parents=True,exist_ok=True); np.savez_compressed(target,**model); return target.resolve()

def load_template_model(aes_bits, path=None):
    target=Path(path) if path is not None else default_template_path(aes_bits)
    if not target.is_file(): raise ValueError(f"伺服器尚未建立 AES-{aes_bits} profiling template。請由管理者先執行 build_template.py。")
    with np.load(target,allow_pickle=False) as saved: model={name:saved[name].copy() for name in saved.files}
    if int(model.get("model_version",-1))!=MODEL_VERSION: raise ValueError(f"不支援的 template model version：{model.get('model_version')}")
    if int(model.get("aes_bits",0))!=aes_bits: raise ValueError(f"模板 AES 版本不符：預期 {aes_bits}")
    return model

def template_status(aes_bits):
    path=default_template_path(aes_bits)
    if not path.is_file(): return {"aes_bits":aes_bits,"ready":False,"file":path.name,"reason":"not_built"}
    try:
        model=load_template_model(aes_bits,path)
        return {"aes_bits":aes_bits,"ready":True,"file":path.name,"trace_length":int(model["trace_length"]),"profiling_traces":int(model["profiling_traces"]),"poi_num":int(model["poi_num"]),"created_utc":str(model["created_utc"])}
    except Exception as exc: return {"aes_bits":aes_bits,"ready":False,"file":path.name,"reason":str(exc)}

def validate_target_against_model(model,traces):
    expected=int(model["trace_length"])
    if traces.ndim!=2: raise ValueError(f"target traces 必須是 (N, L)，目前為 {traces.shape}")
    if traces.shape[1]!=expected: raise ValueError(f"目標 Trace 與預建模板的採樣長度不一致：目標 {traces.shape[1]}，模板 {expected}。請使用相同量測設定，或重新建立模板。")
    if not np.isfinite(traces).all(): raise ValueError("target traces 含有 NaN 或 Infinity")

def score_template_phase(model,phase,target_traces,source_bytes):
    prefix=f"phase{phase}_"; poi=model[prefix+"poi"]; means=model[prefix+"mean"]; covs=model[prefix+"covariance"]
    n=target_traces.shape[0]
    if source_bytes.shape!=(n,16): raise ValueError(f"source bytes 必須是 ({n}, 16)，目前為 {source_bytes.shape}")
    scores=np.zeros((16,256)); rows=np.arange(n)[:,None]
    for b in range(16):
        target_poi=target_traces[:,poi[b]]
        log_pdf=np.column_stack([multivariate_normal.logpdf(target_poi,mean=means[b,hw],cov=covs[b,hw],allow_singular=False) for hw in range(9)])
        hypothetical_hw=hw_table[AES_Sbox[source_bytes[:,b,None]^K256[None,:]]]
        scores[b]=log_pdf[rows,hypothetical_hw].sum(axis=0)
    guesses=np.argmax(scores,axis=1).astype(np.uint8)
    return scores,guesses