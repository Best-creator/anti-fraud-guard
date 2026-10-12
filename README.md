# 金融反诈智能守护系统

> 睿抗赛事第三赛题 · 面向校园与金融消费场景的智能反诈教育平台

把**咨询识别 → 实时劝阻 → 举报研判 → 训练提升**接成一条完整闭环，并通过管理后台完成知识补齐、规则发布与持续更新。

---

## 核心设计：大模型做理解，规则做判定

反诈场景说错话的代价是真实的，所以本系统**不让大模型负责判定**。

```
用户输入
   ↓
intent_router            风险优先的意图路由，输出结构化 RouteDecision
   ↓
ScamRuleEngine           25 类诈骗规则包匹配，输出类型/阶段/风险分/命中依据
   ↓
realtime_dissuasion_engine  按「当前最高危动作」纠偏，选择干预目标
   ↓
结构化输出               达到阈值后走确定性模板，不依赖模型自由发挥
```

### 意图路由：风险优先

路由不是「科普 / 求助」二分类，而是输出完整决策对象：

- `primary_intent` — `anti_fraud_qa` / `risk_help` / `emergency_help` / `risk_fact_clarification`
- `workflow_mode` — `knowledge_answer` / `risk_case_flow` / `clarification` / `fallback`
- `safety_signals` — 已转账、已给验证码、已屏幕共享、已下载 App、已点链接、已填证件
- `risk_prefill` — 候选骗局类型、当前危险动作、可预填槽位

判定优先级：**已发生暴露或损失** > **对方正在要求危险动作** > **具体场景风险咨询** > **泛化科普** > **事实不足待补槽**。

问句不等于科普。用户问「我在兼职群看到点赞返佣靠谱吗」仍会进入风险研判。

### 事件链抽取：四层理解

一句话里同时存在多个事件时，需要合并理解：

| 层 | 识别内容 |
| --- | --- |
| 风险诱饵事件 | 中奖、退款、贷款、兼职、投资、租房、就业班、游戏交易 |
| 对方要求事件 | 「他让我 / 要我 / 需要我」后面的危险动作 |
| 用户执行事件 | 「我已经 / 我给他 / 我填了 / 我点进去了」 |
| 上下文合并 | 前半句宾语 + 后半句动作 → 单一槽位 |

> 「他说要我提供身份证信息，我给他提供了」
> → `has_provided_identity_or_bank = true`，直接进 `emergency_help`

外加**否定保护**：识别到「我没有提供」「还没填」「没转账」时只保留预警，不升级为紧急暴露——避免对只是随口一问的用户造成误伤。

### 干预目标按动作纠偏

模板不与骗局类型硬绑定，而是跟随**当下最危险的动作**：

| 干预目标 | 触发场景 |
| --- | --- |
| `stop_transfer` | 垫付、充值、补单、押金、培训费、服务费 |
| `stop_code_leak` | 索要验证码、短信码、动态码、支付码 |
| `stop_screen_share` | 正在开启屏幕共享 / 远程控制 |
| `stop_app_install` | 要求下载指定 App |
| `stop_click_link` | 钓鱼链接、二维码 |
| `call_police` | 已发生实际损失 |

这避免了「只说验证码却提示关闭屏幕共享」这类跨场景串模板。

---

## 主要能力

| 模块 | 说明 |
| --- | --- |
| 知识问答 | BGE-M3 + Milvus 混合向量检索，本地知识库优先，大模型仅做总结 |
| 实时劝阻 | 多轮风险状态机，7 阶段推进到止损与解除核验 |
| 举报研判 | URL 规则、域名黑白名单、LLM 研判、证据链固化 |
| 防骗训练营 | 200 题 / 20 类题库 + 三档难度实时骗局模拟（LLM 扮演骗子） |
| 语音交互 | FunASR 识别 + Kokoro 合成，provider 可插拔，无第三方 Key 也能跑通 |
| 截图研判 | Qwen 视觉模型 OCR + 视觉风险分析 |
| 管理后台 | 知识导入、规则发布、审核工作台、审计日志与回滚 |

### 训练营评分逻辑

实时模拟的评分不看选择题对错，而看用户是否在**自由对话**中被诱导做出高危动作（转账、给验证码、下载 App、点链接、共享屏幕）。

段位：0-19 白银 / 20-59 黄金 / 60-139钻石 / 140+ 王者。

---

## 技术栈

- **后端** — FastAPI、Uvicorn、LangChain / LangGraph、PyMongo、PyMilvus
- **模型** — BGE-M3（本地向量）、Kokoro（本地 TTS）、FunASR（本地 ASR）、DeepSeek / Qwen（API）
- **存储** — MongoDB（业务状态）、Milvus（向量检索）
- **前端** — 原生 HTML/CSS/JS Web 端、微信小程序、Vue mobile-app

**脱离大模型仍可完成核心判定**——规则与知识完全本地化，适合银行 App 前置拦截、校园场景、客服坐席，支持离线演示与生产降级。

---

## 快速开始

### 1. 依赖

- Python 3.11+
- Docker Desktop（MongoDB / Milvus）
- 微信开发者工具（仅调试小程序时需要）

### 2. 环境变量

```bash
cp .env.example .env
```

填写：

```env
# DeepSeek：主聊天、路由、RAG 总结
OPENAI_BASE_URL=https://api.deepseek.com
OPENAI_API_KEY=

# Qwen 视觉：聊天页截图 OCR 与视觉风险分析
VISION_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
VISION_API_KEY=
```

> 不填 Key 也能启动，系统会走本地规则兜底，回答质量会下降。
> **`.env` 含真实密钥，已被 `.gitignore` 排除，请勿提交。**

### 3. 安装依赖

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

或使用 `uv.lock` 复现：

```bash
uv sync
```

### 4. 启动数据库

```bash
docker compose up -d
```

### 5. 启动服务

```bash
./scripts/start_local_services.sh          # macOS / Linux
# Windows PowerShell 见 scripts\start-delivery-services.ps1
```

访问：

| 地址 | 说明 |
| --- | --- |
| http://127.0.0.1:8001/chat.html | 智能反诈咨询 |
| http://127.0.0.1:8000/import.html | 知识导入 / 管理 |
| http://127.0.0.1:8001/admin/review.html | 管理后台审核台 |

停止：

```bash
./scripts/stop_local_services.sh            # 仅后端
./scripts/stop_local_services.sh --docker  # 含Mongo/Milvus
```

### 微信小程序

导入 `miniprogram/` 目录，在「详情 / 本地设置」勾选「不校验合法域名…」。

真机预览时 `127.0.0.1` 指向手机自身，需在「我的」页改为电脑局域网 IP，如 `http://192.168.1.8:8001`。

---

## 可选能力

| 能力 | 说明 | 未配置时 |
| --- | --- | --- |
| BGE-M3 向量模型 | 需按 `MODEL_DOWNLOADS.md` 单独下载 | 设 `ANTI_FRAUD_EMBEDDING_BACKEND=hash` 兜底，检索变弱 |
| FunASR 语音识别 | 监听 `127.0.0.1:10096` | 文字咨询、训练营、风险检测不受影响 |
| Kokoro TTS | 模型未随仓库分发 | 回退浏览器 `SpeechSynthesis` |

---

## 扩展方式

**新增骗局类型** —— 无需改动主流程，只需在 `app/query_process/rules/scam_packages/` 增加 JSON 规则包，配置 `aliases`、`features`、`rules`（`all` / `any` / `min_any` + 风险分 + 干预目标 + 话术模板）。

**新增训练题** —— 调整 `scripts/generate_training_levels.py` 中的 `SCAM_PACKAGES` 后重新生成，脚本会同步写入训练营与旧 game_process 两份种子数据。

**接入云 ASR/TTS** —— 在 `app/modules/voice/providers/` 实现 provider 接口并注册，配置项见 `.env.example`。

**规则在线配置** —— 运行链路支持 MongoDB 在线配置与本地 JSON 回退双轨，便于灰度发布与应急降级。

---

## 测试

```bash
python -m unittest discover -s test  -p "test_risk_engine.py"
python -m unittest discover -s test  -p "test_realtime_dissuasion_engine.py"
python -m unittest discover -s test  -p "test_emergency_dissuasion_workflow.py"
python -m unittest discover -s test  -p "test_unified_anti_fraud_assistant.py"
python -m unittest discover -s test  -p "test_student_personal_scenarios.py"
python -m unittest discover -s tests -p "test_report_intel_tool.py"
```

覆盖范围：多轮意图路由、规则命中、干预目标选择、法条引用、答案位置均衡、被骗低分 / 安全高分、URL 研判、记忆层。

---

## 项目结构

```
app/
  anti_fraud/          数据结构与 schema
  clients/             MongoDB / Milvus 访问层
  conf/                模型、嵌入、Milvus 配置
  import_process/      知识导入（LangGraph 流程）
  lm/                  LLM 与嵌入封装
  modules/
    knowledge_assistant/  知识问答与对话 Agent
    training_camp/        防骗训练营
    emergency_dissuasion/ 紧急劝阻
    report_intel_tool/    举报线索研判
    suspicious_report/    可疑举报规则
    voice/                语音 provider（ASR / TTS）
    vision_ocr/           截图 OCR 与视觉研判
  query_process/
    agent/            状态机、记忆管理
    rules/            诈骗规则包 JSON
    services/         路由、规则引擎、风险引擎、编排
    api/              FastAPI 路由
    page/             Web 页面
miniprogram/           微信小程序
mobile-app/            Vue 移动端
data/                  知识库、举报研判库、测试用例
scripts/               启动、数据库、题库生成、部署脚本
test/ tests/           单元测试
doc/                   模块设计文档
```

---

## 免责声明

本项目仅用于反诈教育、风险预警与技术研究。系统输出为风险提示与防范建议，**不构成任何法律或投资意见**。实际遭遇诈骗请立即拨打 110 并联系银行或支付平台止付。