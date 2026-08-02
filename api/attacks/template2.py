"""AES-256 two-phase Template Attack using a server-side profiling template."""
import os, sys
import matplotlib.pyplot as plt
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from aes256_utils import compute_state_before_rk1
from attack_base import BaseAttack, AttackInput, AttackResult, registry
from template_store import build_template_model, load_template_model, score_template_phase, validate_target_against_model

class TemplateAttack(BaseAttack):
    name="template256"
    display_name="Template Attack (server profiling template) — AES-256"
    description="使用伺服器預先建立的 AES-256 兩階段 HW 高斯模板；使用者只需上傳目標 traces 與 plaintexts。"
    POI_NUM=10

    def validate(self,data:AttackInput):
        super().validate(data)
        supplied=[data.template_traces is not None,data.template_plaintexts is not None,data.template_keys is not None]
        if any(supplied) and not all(supplied):
            raise ValueError("若要臨時建立模板，template traces/plaintexts/keys 三個檔案必須全部提供")

    def run(self,data:AttackInput)->AttackResult:
        self.validate(data)
        target_t=(data.preprocessed_traces if data.preprocessed_traces is not None else data.traces).astype(np.float64)
        target_p=data.plaintexts[:,:16].astype(np.uint8)
        if data.template_traces is not None:
            model=build_template_model(256,data.template_traces,data.template_plaintexts,data.template_keys,self.POI_NUM)
            source="uploaded_profiling_data"
        else:
            model=load_template_model(256); source="server_prebuilt"
        validate_target_against_model(model,target_t)
        scores1,key1=score_template_phase(model,1,target_t,target_p)
        target_state=compute_state_before_rk1(target_p,key1)
        scores2,key2=score_template_phase(model,2,target_t,target_state)
        full_key=key1.tolist()+key2.tolist(); snr1=model["phase1_snr"]; snr2=model["phase2_snr"]
        fig,axes=plt.subplots(4,8,figsize=(32,16))
        for b in range(16):
            axes[b//4,b%4].plot(snr1[b]); axes[b//4,b%4].set_title(f"P1 Byte {b} SNR",fontsize=8)
            axes[b//4,(b%4)+4].plot(snr2[b]); axes[b//4,(b%4)+4].set_title(f"P2 Byte {b+16} SNR",fontsize=8)
        plt.suptitle("Template Attack — AES-256 server profiling template",fontsize=14); plt.tight_layout()
        return AttackResult(algorithm=self.name,key_hex=bytes(full_key).hex(),key_bytes=full_key,num_traces=target_t.shape[0],trace_length=target_t.shape[1],plot_base64=self.plot_to_base64(fig),extra={"template_source":source,"profiling_traces":int(model["profiling_traces"]),"poi_num":int(model["poi_num"]),"phase1_key":bytes(key1).hex(),"phase2_key":bytes(key2).hex(),"phase1_key_scores":scores1.max(axis=1).tolist(),"phase2_key_scores":scores2.max(axis=1).tolist()})

registry.register(TemplateAttack())