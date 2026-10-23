/**
 * AI 小助手 - 增強版本（可拖動 + 預設打開）
 * 用於旁通道攻擊分析平臺
 */

(function(window) {
  'use strict';

  const DEFAULTS = {
    apiEndpoint: '/api/ai/chat',
    platformName: '旁通道攻擊分析平臺',
    language: 'zh-TW',
    maxHistoryLength: 10,
    autoOpen: false,
    draggable: true,  // 可拖動
    showQuickQuestions: true,   // 是否顯示「常見問題」快捷按鈕
    quickQuestions: null,       // 自訂題庫；null = 使用下方內建 DEFAULT_FAQ
    quickTitle: '常見問題',
    quickVisible: 4,             // 常見問題預設只顯示前幾題，其餘按「更多」展開
    answerDelay: 450            // 固定回覆的「思考」動畫時間 (ms)，設 0 則立即顯示
  };

  /**
   * 固定題庫：點擊後直接顯示固定答案（不呼叫 API）
   * 欄位：id 唯一代號 / label 按鈕文字 / question 顯示成使用者提問 /
   *       answer 固定回覆 / related 回覆下方的「相關問題」(填 id)
   * 想新增題目，直接在這裡多加一個物件即可；
   * 或在 AITutor.init({ quickQuestions: [...] }) 傳入自己的題庫。
   */
  const DEFAULT_FAQ = [
    {
      id: 'start',
      label: '從哪裡開始',
      question: '第一次使用，要從哪裡開始？',
      answer: `只要照著上方的 3 個步驟走就可以了：

1. 選擇資料：第一次建議選「使用現有資料集」→ AES-128 → 100 條，不用準備任何檔案。
2. 選擇分析方法：在左邊的 CPA 卡片按「＋ 加入」，再按「開始分析」。
3. 查看結果：每一格是推出的金鑰的一小段（位元組），點一格就能看它的分析圖。

如果想知道每一格是猜對還是猜錯，可以在第一步填入「正確金鑰」來對答案。`,
      related: ['sca', 'cpa', 'result']
    },
    {
      id: 'result',
      label: '怎麼看結果',
      question: '結果頁要怎麼看？',
      answer: `結果頁由上到下可以這樣看：

• 一排小方格：平台推出的金鑰，每一格是一個位元組（例如 2B）。
  綠色 ✓ 代表和正確金鑰相同，紅色 ✗ 代表猜錯；淺綠代表沒有填正確金鑰，無法對答案。
• 點任一格：下方會出現那一格的分析圖。正確答案通常會在某個時間點冒出明顯比較高的尖峰。
• 洩漏位置圖（SNR）：尖峰越高，代表晶片在那個時間點洩漏越多資訊。
• 猜對比例：猜對幾格；猜錯很多時，可以改選條數更多的資料再試一次。

你也可以直接問我「這張圖代表什麼」，我會根據目前的分析結果說明。`,
      related: ['rank', 'cpa', 'snr']
    },
    {
      id: 'rank',
      label: '位元組與排名',
      question: '什麼是位元組（byte）與排名（rank）？',
      answer: `• 位元組（byte）：電腦裡的一小格資料，可以表示 0–255 的數字，通常寫成兩個 16 進位字元（0–9、A–F），例如 2B。
  AES-128 的金鑰有 16 個位元組，AES-256 有 32 個。

• 排名（rank）：每一格有 256 種可能的答案，平台會依「可能性」把它們排序。正確答案排第 1 名就代表猜中；數字越小，代表攻擊越成功。

• 關注點（POI）：波形上洩漏最明顯的那幾個時間點，很多分析方法會特別看這些點。`,
      related: ['result', 'ge']
    },
    {
      id: 'mlkem',
      label: '什麼是 ML-KEM',
      question: '什麼是 ML-KEM-768？',
      answer: `ML-KEM 是美國 NIST 在 2024 年公布的新一代加密標準（FIPS 203），設計目的是連未來的量子電腦也難以破解，所以又被稱為「後量子加密」。768 是它的安全等級版本。

它的私鑰是由很多個小數字組成的（專業上稱為 NTT 係數）。在本平台中：
• 使用實驗室已錄好的 300 條耗電波形；
• 每次用 CPA 找出其中相鄰的 2 個數字，並和實驗紀錄的真值比對；
• 這只代表找出部分私鑰，不代表整把私鑰被破解。

這個實驗說明：就算演算法本身很安全，實作時的耗電仍可能洩漏秘密。`,
      related: ['cpa', 'sca']
    },
    {
      id: 'sca',
      label: '什麼是旁通道攻擊',
      question: '什麼是旁通道攻擊（SCA）？',
      answer: `旁通道攻擊（Side-Channel Attack）不是去破解加密演算法本身，而是利用設備運算時「不小心洩漏」的物理資訊，例如功耗、電磁輻射、執行時間。

因為晶片處理的資料不同，功耗也會有細微差異。攻擊者量測大量功耗波形（Trace），再用統計方法推測出金鑰。

本平臺就是讓你用 CPA、DPA、MIA、Template、SNR 以及 AI 模型，實際體驗這個過程。`,
      related: ['trace', 'hw', 'cpa']
    },
    {
      id: 'trace',
      label: 'Trace 與 Plaintext',
      question: '什麼是 Trace 與 Plaintext？',
      answer: `• Trace（功耗波形）：設備每執行一次加密，示波器所記錄的一條功耗曲線，由許多採樣點組成。
• Plaintext（明文）：該次加密所輸入的資料。

攻擊時，對每個可能的金鑰猜測，用 Plaintext 算出預測的中間值，再拿去和 Trace 比對。Trace 數量越多，統計結果通常越穩定。`,
      related: ['cpa', 'snr']
    },
    {
      id: 'cpa',
      label: '什麼是 CPA',
      question: '什麼是 CPA？',
      answer: `CPA（Correlation Power Analysis，相關功耗分析）

原理：針對每個金鑰猜測，先預測 S-Box 輸出的漢明重量，再和每個採樣點計算 Pearson 相關係數。相關峰值最高的猜測，通常就是正確的 key byte。

特色：最適合入門理解「資料相依功耗洩漏」；Trace 越多，通常越容易看出穩定的峰值。`,
      related: ['hw', 'dpa', 'mia']
    },
    {
      id: 'dpa',
      label: '什麼是 DPA',
      question: '什麼是 DPA（DoM / PCC）？',
      answer: `DPA（Differential Power Analysis，差分功耗分析）

• DPA-DoM（均值差分析）：依猜測的 S-Box 最低位元是 0 或 1，把波形分成兩組，比較兩組平均波形的差。差異最大的猜測較可能正確。
• DPA-PCC（二元相關分析）：使用同樣的最低位元假設，但改用 Pearson 相關係數衡量吻合程度。

兩者並排比較，可以看出「分組比差」與「計算相關」的差別。`,
      related: ['cpa', 'mia']
    },
    {
      id: 'mia',
      label: '什麼是 MIA',
      question: '什麼是 MIA？',
      answer: `MIA（Mutual Information Analysis，互資訊分析）

原理：計算預測中間值與實際功耗之間的互資訊。CPA 只看線性相關，MIA 則可能捕捉到非線性的洩漏。

特色：適合進階比較線性與非線性洩漏；需要分箱與統計，通常比 CPA、DPA 等待更久。`,
      related: ['cpa', 'dpa']
    },
    {
      id: 'snr',
      label: '什麼是 SNR',
      question: '什麼是 SNR？',
      answer: `SNR（Signal-to-Noise Ratio，訊號雜訊比分析）

原理：利用已知金鑰，把 Trace 依中間值的漢明重量分組，比較「組間差異」與「組內雜訊」，找出最可能洩漏資訊的採樣點。

注意：它是診斷工具，用來定位洩漏點（POI）、評估量測品質，不會自行還原未知金鑰。`,
      related: ['template', 'trace']
    },
    {
      id: 'template',
      label: '什麼是 Template',
      question: '什麼是 Template Attack？',
      answer: `Template Attack（模板攻擊）

流程：
1. 先用「已知金鑰」的 profiling traces 找出 POI，為各個漢明重量類別建立高斯統計模型（模板）。
2. 再拿目標 Trace 與 Plaintext，用最大 log-likelihood 推測金鑰。

特色：只需要少量目標 Trace 就有機會成功，但模板必須來自相同晶片、韌體與量測設定。`,
      related: ['snr', 'mlp']
    },
    {
      id: 'mlp',
      label: '什麼是 MLP',
      question: '什麼是 MLP？',
      answer: `AI-MLP（Multi-Layer Perceptron，多層感知器）

原理：預訓練好的 MLP 把「整條 Trace」映射成 ID 或 Hamming Weight 類別的機率，再累積每個金鑰猜測的 log-likelihood，找出最可能的金鑰。

限制：本平臺只支援 AES-128 的單一目標 byte，需要伺服器上的資料集（ASCAD／CHES）與模型權重。

和 CNN 比較：MLP 是全連接網路，CNN 則擅長抓局部特徵。`,
      related: ['cnn', 'ge']
    },
    {
      id: 'cnn',
      label: '什麼是 CNN',
      question: '什麼是 CNN？',
      answer: `AI-CNN（Convolutional Neural Network，卷積神經網路）

原理：預訓練 CNN 從 Trace 中自動學習局部洩漏特徵，再把每條 Trace 對 S-Box 中間值類別的機率累積起來，計算 key guessing entropy。

限制：沿用伺服器的 ASCAD／CHES 資料集，只評估 AES-128 的單一目標 key byte。

適合用來比較深度學習與傳統統計攻擊（CPA、DPA 等）的差異。`,
      related: ['mlp', 'ge']
    },
    {
      id: 'hw',
      label: '漢明重量HW',
      question: '什麼是漢明重量HW（Hamming Weight）？',
      answer: `漢明重量（Hamming Weight，HW）就是一個數值轉成二進位後「1 的個數」。

例如 0b10110010 的 HW 是 4。

因為晶片處理的資料中 1 越多，功耗往往也有相應的變化，所以 HW 常被當作功耗的洩漏模型。CPA、SNR、Template 都會用到它。`,
      related: ['cpa', 'snr']
    },
    {
      id: 'ge',
      label: 'Guessing Entropy',
      question: '什麼是 Guessing Entropy？',
      answer: `Guessing Entropy（猜測熵）用來衡量攻擊的成功程度：把所有金鑰猜測依分數排序後，看「正確金鑰」平均排在第幾名。

名次越前面（數值越小）、並隨 Trace 增加快速下降，代表攻擊越有效。

本平臺的 AI-CNN／AI-MLP 會用它來評估模型表現。`,
      related: ['mlp', 'cnn']
    },
    {
      id: 'aes256',
      label: 'AES-128 vs AES-256',
      question: 'AES-128 和 AES-256 的攻擊有什麼不同？',
      answer: `• AES-128：金鑰有 16 bytes，一般逐 byte 還原。
• AES-256：金鑰有 32 bytes，本平臺的 CPA 等攻擊採「兩階段」方式還原整把金鑰。
• ML-KEM-768：新一代的後量子加密，本平臺只分析私鑰中的一小部分。

第一次使用建議先選 AES-128，速度最快、結果也最容易看懂。
另外，AI-CNN／AI-MLP 目前只支援 AES-128 的單一目標 byte。`,
      related: ['cpa', 'mlkem']
    }
  ];

  class AITutorWidget {
    constructor(config = {}) {
      this.config = { ...DEFAULTS, ...config };
      this.isOpen = false;
      this.isLoading = false;
      this.conversationHistory = [];
      this.isDragging = false;
      this.dragStartX = 0;
      this.dragStartY = 0;
      this.offsetX = 0;
      this.offsetY = 0;
      this.faq = Array.isArray(this.config.quickQuestions) && this.config.quickQuestions.length
        ? this.config.quickQuestions
        : DEFAULT_FAQ;

      this.init();
    }

    init() {
      this.setupDOM();
      this.attachEventListeners();
      this.loadHistory();
      this.renderQuickQuestions();

      // 預設打開
      //if (this.config.autoOpen) {
      //  setTimeout(() => this.open(), 300);
      //}
    }

    setupDOM() {
      if (document.getElementById('ai-tutor-bubble')) {
        this.bubble = document.getElementById('ai-tutor-bubble');
      } else {
        this.bubble = this.createBubbleDOM();
        document.body.appendChild(this.bubble);
      }

      this.toggleBtn = this.bubble.querySelector('.ai-tutor-btn');
      this.tag = this.bubble.querySelector('.ai-tutor-tag');
      this.panel = this.bubble.querySelector('.ai-tutor-panel');
      this.header = this.bubble.querySelector('.ai-tutor-header');
      this.content = this.bubble.querySelector('.ai-tutor-content');
      this.input = this.bubble.querySelector('.ai-tutor-input');
      this.sendBtn = this.bubble.querySelector('.ai-tutor-send');
      this.closeBtn = this.bubble.querySelector('.ai-tutor-close');
      this.quick = this.bubble.querySelector('.ai-quick');
      this.quickList = this.bubble.querySelector('.ai-quick-list');
      this.quickToggle = this.bubble.querySelector('.ai-quick-toggle');
    }

    createBubbleDOM() {
      const bubble = document.createElement('div');
      bubble.id = 'ai-tutor-bubble';
      bubble.className = 'ai-tutor-bubble';
      bubble.innerHTML = `
        <style>
          .ai-tutor-bubble {
            position: fixed;
            bottom: 28px;
            right: 28px;
            z-index: 999999;
            font-family: 'Noto Sans TC', -apple-system, BlinkMacSystemFont, sans-serif;
          }

          .ai-tutor-launcher {
            display: flex;
            align-items: center;
            gap: 10px;
          }

          .ai-tutor-bubble.is-open .ai-tutor-launcher {
            display: none;
          }

          .ai-tutor-tag {
            position: relative;
            background: #fff;
            border: 1px solid #e0e2ea;
            color: #1a1d2e;
            border-radius: 14px;
            padding: 8px 12px;
            font-family: inherit;
            text-align: left;
            cursor: pointer;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
            animation: aiTagIn 0.4s ease 0.4s both;
            transition: background 0.15s ease;
          }

          .ai-tutor-tag:hover {
            background: #f4f0ff;
          }

          .ai-tutor-tag::after {
            content: '';
            position: absolute;
            right: -7px;
            top: 50%;
            width: 12px;
            height: 12px;
            background: inherit;
            border-right: 1px solid #e0e2ea;
            border-top: 1px solid #e0e2ea;
            transform: translateY(-50%) rotate(45deg);
          }

          .ai-tutor-tag strong {
            display: block;
            font-size: 13px;
            font-weight: 500;
          }

          .ai-tutor-btn {
            position: relative;
            width: 66px;
            height: 66px;
            border-radius: 50%;
            background: linear-gradient(135deg, #7755d9, #6b4fc1);
            border: none;
            padding: 0;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 12px rgba(119, 85, 217, 0.3);
            transition: transform 0.25s ease, box-shadow 0.25s ease;
          }

          .ai-tutor-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 6px 18px rgba(119, 85, 217, 0.45);
          }

          .ai-tutor-btn.open {
            display: none;
          }

          .ai-robot {
            width: 46px;
            height: 46px;
            overflow: visible;
            animation: aiFloat 2.6s ease-in-out infinite;
          }

          .ai-robot-arm {
            transform-origin: 54px 30px;
            animation: aiWave 4s ease-in-out infinite;
          }

          @keyframes aiFloat {
            0%, 100% { transform: translateY(1px); }
            50% { transform: translateY(-3px); }
          }

          @keyframes aiWave {
            0%, 65%, 100% { transform: rotate(0deg); }
            74% { transform: rotate(-28deg); }
            82% { transform: rotate(6deg); }
            90% { transform: rotate(-22deg); }
          }

          .ai-robot-eyes {
            transform-origin: 32px 29px;
            animation: aiBlink 4s infinite;
          }

          @keyframes aiBlink {
            0%, 92%, 100% { transform: scaleY(1); }
            95% { transform: scaleY(0.1); }
          }

          @keyframes aiTagIn {
            from { opacity: 0; transform: translateX(12px); }
            to { opacity: 1; transform: none; }
          }

          @media (prefers-reduced-motion: reduce) {
            .ai-robot, .ai-robot-eyes, .ai-robot-arm, .ai-tutor-tag {
              animation: none !important;
            }
          }

          .ai-tutor-panel {
            position: absolute;
            bottom: 80px;
            right: 0;
            width: 380px;
            max-height: 600px;
            background: #fff;
            border: 1px solid #d8c9ff;
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12);
            display: none;
            flex-direction: column;
            overflow: hidden;
            animation: slideUp 0.3s ease;
          }

          .ai-tutor-panel.open {
            display: flex;
          }

          @keyframes slideUp {
            from {
              opacity: 0;
              transform: translateY(20px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }

          .ai-tutor-header {
            padding: 12px 14px 12px 16px;
            background: #fff;
            border-bottom: 1px solid #e0e2ea;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: grab;
            user-select: none;
          }

          .ai-tutor-header:active {
            cursor: grabbing;
          }

          .ai-tutor-header-title {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 700;
            color: #1a1d2e;
            margin: 0;
          }

          .ai-tutor-header-title::before {
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #7755d9;
          }

          .ai-tutor-close {
            background: none;
            border: none;
            font-size: 18px;
            color: #7a7f9a;
            cursor: pointer;
            padding: 0;
            width: 26px;
            height: 26px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
          }

          .ai-tutor-close:hover {
            background: #f0f1f4;
            color: #1a1d2e;
          }

          .ai-tutor-content {
            flex: 1;
            min-height: 160px;
            overflow-y: auto;
            padding: 14px 16px;
            display: flex;
            flex-direction: column;
            gap: 10px;
          }

          .ai-message {
            display: flex;
            animation: fadeIn 0.2s ease;
          }

          @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
          }

          .ai-message.bot {
            justify-content: flex-start;
          }

          .ai-message.user {
            justify-content: flex-end;
          }

          .ai-bubble {
            max-width: 88%;
            white-space: pre-wrap;
            padding: 9px 12px;
            border-radius: 10px;
            font-size: 13px;
            line-height: 1.7;
            word-wrap: break-word;
          }

          .ai-message.bot .ai-bubble {
            background: #f0f1f4;
            color: #1a1d2e;
          }

          .ai-message.user .ai-bubble {
            background: #7755d9;
            color: #fff;
          }

          .ai-loading {
            display: flex;
            gap: 4px;
            align-items: center;
            height: 24px;
            padding: 0 4px;
          }

          .ai-loading span {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #7a7f9a;
            animation: pulse 1.4s ease-in-out infinite;
          }

          .ai-loading span:nth-child(1) { animation-delay: -0.32s; }
          .ai-loading span:nth-child(2) { animation-delay: -0.16s; }

          @keyframes pulse {
            0%, 60%, 100% { opacity: 0.3; }
            30% { opacity: 1; }
          }

          .ai-tutor-footer {
            padding: 10px 12px 12px;
          }

          .ai-input-wrap {
            display: flex;
            align-items: flex-end;
            gap: 6px;
            border: 1px solid #c8ccd8;
            border-radius: 10px;
            padding: 4px 4px 4px 10px;
            background: #fff;
          }

          .ai-input-wrap:focus-within {
            border-color: #7755d9;
          }

          .ai-tutor-input {
            flex: 1;
            border: none;
            padding: 6px 0;
            font-family: 'Noto Sans TC', sans-serif;
            font-size: 13px;
            color: #1a1d2e;
            background: transparent;
            resize: none;
            max-height: 80px;
          }

          .ai-tutor-input:focus {
            outline: none;
          }

          .ai-tutor-input::placeholder {
            color: #7a7f9a;
          }

          .ai-tutor-send {
            background: #7755d9;
            border: none;
            color: #fff;
            width: 30px;
            height: 30px;
            border-radius: 7px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background 0.15s ease;
            flex-shrink: 0;
          }

          .ai-tutor-send svg {
            width: 15px;
            height: 15px;
          }

          .ai-tutor-send:hover:not(:disabled) {
            background: #51349e;
          }

          .ai-tutor-send:disabled {
            opacity: 0.5;
            cursor: not-allowed;
          }

          /* ===== 常見問題（固定題目） ===== */
          .ai-quick {
            padding: 10px 12px 0;
            border-top: 1px solid #e0e2ea;
          }

          .ai-quick-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 11px;
            color: #7a7f9a;
          }

          .ai-quick-toggle {
            background: none;
            border: none;
            color: #7755d9;
            font-size: 11px;
            font-family: inherit;
            cursor: pointer;
            padding: 0;
          }

          .ai-quick-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 7px;
          }

          .ai-quick-list .ai-chip.extra {
            display: none;
          }

          .ai-quick.expanded .ai-quick-list .ai-chip.extra {
            display: inline-block;
          }

          .ai-chip {
            border: 1px solid #e0e2ea;
            background: #fff;
            color: #1a1d2e;
            border-radius: 999px;
            padding: 4px 10px;
            font-size: 12px;
            font-family: inherit;
            line-height: 1.4;
            cursor: pointer;
            transition: border-color 0.15s ease, color 0.15s ease;
          }

          .ai-chip:hover:not(:disabled) {
            border-color: #7755d9;
            color: #51349e;
          }

          .ai-chip:disabled {
            opacity: 0.5;
            cursor: not-allowed;
          }

          .ai-related {
            margin-top: 8px;
            font-size: 12px;
            color: #7a7f9a;
            white-space: normal;
          }

          .ai-related-link {
            background: none;
            border: none;
            padding: 0;
            margin: 0 0 0 6px;
            font: inherit;
            color: #7755d9;
            cursor: pointer;
          }

          .ai-related-link:hover:not(:disabled) {
            text-decoration: underline;
          }

          @media (max-width: 480px) {
            .ai-tutor-panel {
              width: 320px;
              max-height: 500px;
            }
          }
        </style>

        <div class="ai-tutor-launcher">
          <button class="ai-tutor-tag" type="button">
            <strong>有問題問我</strong>
          </button>
          <button class="ai-tutor-btn" type="button" title="打開 AI 小助手" aria-label="打開 AI 小助手">
            <svg class="ai-robot" viewBox="0 0 64 64" aria-hidden="true">
              <line x1="32" y1="6" x2="32" y2="14" stroke="#fff" stroke-width="3" stroke-linecap="round"/>
              <circle cx="32" cy="6" r="3.5" fill="#fff"/>
              <rect x="7" y="25" width="6" height="11" rx="3" fill="#fff"/>
              <rect class="ai-robot-arm" x="51" y="25" width="6" height="11" rx="3" fill="#fff"/>
              <rect x="12" y="14" width="40" height="32" rx="11" fill="#fff"/>
              <rect x="17" y="20" width="30" height="19" rx="8" fill="#51349e"/>
              <g class="ai-robot-eyes">
                <circle cx="26" cy="29" r="3.4" fill="#b6e8d0"/>
                <circle cx="38" cy="29" r="3.4" fill="#b6e8d0"/>
              </g>
              <path d="M27 34.5 q5 3 10 0" stroke="#b6e8d0" stroke-width="2" fill="none" stroke-linecap="round"/>
              <rect x="22" y="48" width="20" height="9" rx="4" fill="#fff" opacity=".9"/>
            </svg>
          </button>
        </div>
        <div class="ai-tutor-panel">
          <div class="ai-tutor-header">
            <h3 class="ai-tutor-header-title">小助手</h3>
            <button class="ai-tutor-close" type="button" title="關閉">×</button>
          </div>

          <div class="ai-tutor-content">
            <div class="ai-message bot">
              <div class="ai-bubble">你好，看不懂的名詞或結果都可以問我。\n可以點下方的常見問題，或直接輸入。</div>
            </div>
          </div>

          <div class="ai-quick" style="display:none">
            <div class="ai-quick-head">
              <span class="ai-quick-title"></span>
              <button class="ai-quick-toggle" type="button">更多</button>
            </div>
            <div class="ai-quick-list"></div>
          </div>

          <div class="ai-tutor-footer">
            <div class="ai-input-wrap">
              <textarea
                class="ai-tutor-input"
                placeholder="輸入問題，例如：CPA 是什麼？"
                rows="1"
              ></textarea>
              <button class="ai-tutor-send" type="button" title="送出" aria-label="送出">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 19V5M5 12l7-7 7 7"/></svg>
              </button>
            </div>
          </div>
        </div>
      `;

      return bubble;
    }

    attachEventListeners() {
      this.toggleBtn.addEventListener('click', () => this.toggle());
      if (this.tag) this.tag.addEventListener('click', () => this.open());
      this.closeBtn.addEventListener('click', () => this.close());
      this.sendBtn.addEventListener('click', () => this.sendMessage());

      this.input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          this.sendMessage();
        }
      });

      this.input.addEventListener('input', () => {
        this.input.style.height = 'auto';
        this.input.style.height = Math.min(this.input.scrollHeight, 80) + 'px';
      });

      // 常見問題：點擊按鈕（含回覆下方的「相關問題」）
      this.panel.addEventListener('click', (e) => {
        const chip = e.target.closest('[data-faq]');
        if (chip) this.askQuick(chip.dataset.faq);
      });

      this.quickToggle.addEventListener('click', () => {
        const expanded = this.quick.classList.toggle('expanded');
        this.quickToggle.textContent = expanded ? '收起' : '更多';
      });

      // 拖動功能
      if (this.config.draggable) {
        this.header.addEventListener('mousedown', (e) => this.startDrag(e));
        document.addEventListener('mousemove', (e) => this.drag(e));
        document.addEventListener('mouseup', () => this.endDrag());
      }
    }

    startDrag(e) {
      this.isDragging = true;
      this.dragStartX = e.clientX;
      this.dragStartY = e.clientY;

      const rect = this.panel.getBoundingClientRect();
      this.offsetX = rect.left;
      this.offsetY = rect.top;
    }

    drag(e) {
      if (!this.isDragging) return;

      const deltaX = e.clientX - this.dragStartX;
      const deltaY = e.clientY - this.dragStartY;

      const newX = this.offsetX + deltaX;
      const newY = this.offsetY + deltaY;

      // 限制在視窗內
      const maxX = window.innerWidth - this.panel.offsetWidth;
      const maxY = window.innerHeight - this.panel.offsetHeight;

      const clampedX = Math.max(0, Math.min(newX, maxX));
      const clampedY = Math.max(0, Math.min(newY, maxY));

      this.panel.style.position = 'fixed';
      this.panel.style.left = clampedX + 'px';
      this.panel.style.top = clampedY + 'px';
      this.panel.style.right = 'auto';
      this.panel.style.bottom = 'auto';
    }

    endDrag() {
      this.isDragging = false;
    }

    toggle() {
      if (this.isOpen) {
        this.close();
      } else {
        this.open();
      }
    }

    open() {
      this.isOpen = true;
      this.panel.classList.add('open');
      this.toggleBtn.classList.add('open');
      this.bubble.classList.add('is-open');
      this.input.focus();
    }

    close() {
      this.isOpen = false;
      this.panel.classList.remove('open');
      this.toggleBtn.classList.remove('open');
      this.bubble.classList.remove('is-open');
    }

    // ===== 常見問題（固定題目 → 固定答案） =====
    renderQuickQuestions() {
      if (!this.config.showQuickQuestions || !this.faq.length) return;

      this.quick.style.display = '';
      this.bubble.querySelector('.ai-quick-title').textContent = this.config.quickTitle;
      this.quickList.innerHTML = '';

      const visible = this.config.quickVisible || this.faq.length;
      this.faq.forEach((item, index) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = index < visible ? 'ai-chip' : 'ai-chip extra';
        btn.dataset.faq = item.id;
        btn.textContent = item.label || item.question;
        this.quickList.appendChild(btn);
      });
      this.quickToggle.style.display = this.faq.length > visible ? '' : 'none';
    }

    setChipsDisabled(disabled) {
      this.panel.querySelectorAll('.ai-chip').forEach((c) => { c.disabled = disabled; });
    }

    async askQuick(id) {
      const item = this.faq.find((q) => q.id === id);
      if (!item || this.isLoading) return;

      if (!this.isOpen) this.open();

      this.isLoading = true;
      this.sendBtn.disabled = true;
      this.setChipsDisabled(true);

      this.addMessage(item.question, 'user');
      const loadingId = this.showLoading();

      if (this.config.answerDelay > 0) {
        await new Promise((resolve) => setTimeout(resolve, this.config.answerDelay));
      }

      this.removeLoading(loadingId);
      this.addMessage(item.answer, 'bot', { related: item.related });

      // 寫入對話紀錄，之後使用者接著追問時，AI 能看到這段上下文
      this.conversationHistory.push(
        { role: 'user', content: item.question },
        { role: 'model', content: item.answer }
      );
      if (this.conversationHistory.length > this.config.maxHistoryLength) {
        this.conversationHistory = this.conversationHistory.slice(-this.config.maxHistoryLength);
      }
      this.saveHistory();

      this.isLoading = false;
      this.sendBtn.disabled = false;
      this.setChipsDisabled(false);
    }

    async sendMessage() {
      const message = this.input.value.trim();
      if (!message || this.isLoading) return;

      this.input.value = '';
      this.input.style.height = 'auto';
      this.sendBtn.disabled = true;
      this.isLoading = true;

      this.setChipsDisabled(true);
      this.addMessage(message, 'user');
      const loadingId = this.showLoading();

      try {
        const response = await this.callAPI(message);
        this.removeLoading(loadingId);
        this.addMessage(response, 'bot');
      } catch (error) {
        this.removeLoading(loadingId);
        this.addMessage(
          `❌ 發生錯誤：${error.message || '無法連線到服務'}`,
          'bot'
        );
        console.error('AI Tutor Error:', error);
      } finally {
        this.isLoading = false;
        this.sendBtn.disabled = false;
        this.setChipsDisabled(false);
      }
    }

    async callAPI(userMessage) {
      this.conversationHistory.push({
        role: 'user',
        content: userMessage
      });

      try {
        const response = await fetch(this.config.apiEndpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            messages: this.conversationHistory
          }),
          timeout: 30000
        });

        if (!response.ok) {
          throw new Error(`API 錯誤: ${response.statusText}`);
        }

        const data = await response.json();
        const assistantMessage = data.content;

        this.conversationHistory.push({
          role: 'model',
          content: assistantMessage
        });

        if (this.conversationHistory.length > this.config.maxHistoryLength) {
          this.conversationHistory = this.conversationHistory.slice(-this.config.maxHistoryLength);
        }

        this.saveHistory();
        return assistantMessage;
      } catch (error) {
        throw new Error(error.message || '無法連線到 AI 服務');
      }
    }

    addMessage(text, role, options = {}) {
      const message = document.createElement('div');
      message.className = `ai-message ${role}`;

      const bubble = document.createElement('div');
      bubble.className = 'ai-bubble';
      bubble.textContent = text;

      // 回覆下方的「相關問題」按鈕
      if (role === 'bot' && Array.isArray(options.related) && options.related.length) {
        const items = options.related
          .map((rid) => this.faq.find((q) => q.id === rid))
          .filter(Boolean);

        if (items.length) {
          const box = document.createElement('div');
          box.className = 'ai-related';
          box.appendChild(document.createTextNode('相關：'));

          items.forEach((item) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'ai-chip ai-related-link';
            btn.dataset.faq = item.id;
            btn.textContent = item.label || item.question;
            box.appendChild(btn);
          });

          bubble.appendChild(box);
        }
      }

      message.appendChild(bubble);

      this.content.appendChild(message);
      this.scrollToBottom();
    }

    showLoading() {
      const id = Math.random().toString(36);
      const message = document.createElement('div');
      message.className = 'ai-message bot';
      message.id = `loading-${id}`;

      const bubble = document.createElement('div');
      bubble.className = 'ai-loading';
      bubble.innerHTML = '<span></span><span></span><span></span>';

      message.appendChild(bubble);
      this.content.appendChild(message);
      this.scrollToBottom();

      return id;
    }

    removeLoading(id) {
      const element = document.getElementById(`loading-${id}`);
      if (element) {
        element.remove();
      }
    }

    scrollToBottom() {
      this.content.scrollTop = this.content.scrollHeight;
    }

    saveHistory() {
      try {
        const historyToSave = this.conversationHistory.slice(-5);
        localStorage.setItem(
          'ai-tutor-history',
          JSON.stringify(historyToSave)
        );
      } catch (error) {
        console.warn('無法保存對話歷史:', error);
      }
    }

    loadHistory() {
      try {
        const saved = localStorage.getItem('ai-tutor-history');
        if (saved) {
          this.conversationHistory = JSON.parse(saved);
        }
      } catch (error) {
        console.warn('無法載入對話歷史:', error);
      }
    }
  }

  // 全域 API
  window.AITutor = {
    instance: null,

    init: function(config = {}) {
      this.instance = new AITutorWidget(config);
      return this.instance;
    },

    open: function() {
      if (this.instance) this.instance.open();
    },

    close: function() {
      if (this.instance) this.instance.close();
    },

    toggle: function() {
      if (this.instance) this.instance.toggle();
    },

    // 以程式觸發某個固定題目，例如 AITutor.askQuick('cpa')
    askQuick: function(id) {
      if (this.instance) this.instance.askQuick(id);
    },

    sendMessage: function(message) {
      if (this.instance) {
        this.instance.input.value = message;
        this.instance.sendMessage();
      }
    }
  };

})(window);
