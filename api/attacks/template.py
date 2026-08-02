"""AES-128 Template Attack using a server-side profiling template."""
import os, sys
import matplotlib.pyplot as plt
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from attack_base import BaseAttack, AttackInput, AttackResult, registry
from template_store import build_template_model, load_template_model, score_template_phase, validate_target_against_model

class TemplateAttack(BaseAttack):
    name="template"
    display_name="Template Attack (server profiling template)"
    description="使用伺服器預先建立的 AES-128 HW 高斯模板；使用者只需上傳目標 traces 與 plaintexts。"
    POI_NUM=10

    def validate(self,data:AttackInput):
        super().validate(data)
        supplied=[data.template_traces is not None,data.template_plaintexts is not None,data.template_keys is not None]
        if any(supplied) and not all(supplied):
            raise ValueError("若要臨時建立模板，template traces/plaintexts/keys 三個檔案必須全部提供")

    def run(self,data:AttackInput)->AttackResult:
        self.validate(data)
        target_t=(data.preprocessed_traces if data.preprocessed_traces is not None else data.traces).astype(np.float64)
        target_p=data.plaintexts.astype(np.uint8)
        if data.template_traces is not None:
            model=build_template_model(128,data.template_traces,data.template_plaintexts,data.template_keys,self.POI_NUM)
            source="uploaded_profiling_data"
        else:
            model=load_template_model(128); source="server_prebuilt"
        validate_target_against_model(model,target_t)
        scores,guess=score_template_phase(model,1,target_t,target_p)
        snr=model["phase1_snr"]
        fig,axes=plt.subplots(4,4,figsize=(24,16))
        for b in range(16):
            axes[b//4,b%4].plot(snr[b]); axes[b//4,b%4].set_title(f"Byte {b} SNR")
            axes[b//4,b%4].set_xlabel("Samples"); axes[b//4,b%4].set_ylabel("SNR")
        plt.suptitle("Template Attack — AES-128 server profiling template",fontsize=14); plt.tight_layout()
        return AttackResult(algorithm=self.name,key_hex=bytes(guess).hex(),key_bytes=guess.tolist(),num_traces=target_t.shape[0],trace_length=target_t.shape[1],plot_base64=self.plot_to_base64(fig),extra={"template_source":source,"profiling_traces":int(model["profiling_traces"]),"poi_num":int(model["poi_num"]),"key_scores":scores.max(axis=1).tolist()})

registry.register(TemplateAttack())