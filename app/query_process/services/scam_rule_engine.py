"""Unified configurable anti-fraud rule engine.

This service is the single deterministic risk-evaluation entry point used by:
- the compact LangGraph risk workflow,
- the legacy ``node_rule_engine`` wrapper,
- the public ``/risk/check`` service.

It keeps the old JSON/Mongo ``risk_rules`` format, and additionally supports
local Scam Package JSON files under ``app/query_process/rules/scam_packages``.
No dynamic expression evaluation is used; rule conditions stay as safe
``all/any/min_any`` feature sets.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from app.anti_fraud.schema import RISK_FEATURES, RISK_FEATURE_SYNONYMS, normalize_risk_features
from app.core.logger import logger
from app.query_process.agent.nodes.node_rule_engine import _load_rules
from app.query_process.services.input_normalizer import (
    build_context_text,
    extract_amounts,
    extract_urls,
    normalize_text,
)


CORE_FRAUD_TYPE_ALIASES: List[Tuple[str, List[str]]] = [
    ("杀猪盘诈骗", ["网恋", "交友", "恋爱", "对象", "情感", "婚恋"]),
    ("屏幕共享/远程控制诈骗", ["屏幕共享", "共享屏幕", "会议软件", "远程控制", "远程协助", "控制手机", "控制电脑"]),
    ("验证码/账户盗刷诈骗", ["验证码", "短信码", "动态码", "登录码", "支付码", "人脸识别"]),
    ("冒充熟人诈骗", ["领导", "亲友", "同学", "同事", "室友", "舍友", "朋友借钱", "熟人借钱", "亲戚借钱", "换号", "新账号", "新微信号", "新的微信号", "不方便电话"]),
    ("虚假中奖/免费礼品诈骗", ["中奖", "领奖", "兑奖", "免费领", "抽中", "福利礼品"]),
    ("虚假购物服务诈骗", ["卖家", "演唱会票", "门票", "二手", "低价", "定金", "订金", "加私聊", "不能走平台", "不走平台"]),
    ("刷单返利诈骗", ["刷单", "做任务", "返佣", "垫付", "补单", "兼职", "点赞任务"]),
    ("游戏交易诈骗", ["游戏", "游戏装备", "游戏账号", "装备给", "账号给", "虚拟资产", "代充", "皮肤", "账号交易", "低价充值", "代练", "点券"]),
    ("冒充公检法诈骗", ["公安", "警察", "检察院", "法院", "公检法", "安全账户", "涉案", "洗钱", "违法物品", "违禁品", "涉案物品", "违法包裹", "涉嫌违法"]),
    ("虚假投资理财诈骗", ["投资", "理财", "稳赚", "高收益", "内幕", "虚拟币"]),
    ("网络贷款诈骗", ["贷款", "借款", "放款", "刷流水", "包装费", "会员费", "校园贷", "学生贷款", "资料费"]),
    ("冒充客服诈骗", ["自称客服", "平台客服", "快递客服", "电商客服", "客服来电", "退款", "理赔", "快递", "售后", "取消会员", "百万保障"]),
    ("钓鱼链接诈骗", ["链接", "网址", "二维码", "login", "verify", "security"]),
]

BRUSHING_CONTEXT_PATTERN = re.compile(r"(刷单|做任务|点赞任务|关注任务|点赞|关注|淘宝刷单|返佣|返利|返钱|返现|补单|连单|联单)")
STRONG_ACQUAINTANCE_PATTERN = re.compile(r"(冒充|自称|领导|亲友|同学|同事|室友|舍友|朋友借钱|熟人借钱|亲戚借钱|换号|新微信号|不方便电话|代付|周转)")
INVESTMENT_CONTEXT_PATTERN = re.compile(r"(投资|理财|虚拟币|股票|基金|带单|老师|导师|稳赚|高收益|内幕|投资平台|投资App|交易平台)")
INVESTMENT_HIGH_RISK_PATTERN = re.compile(r"(提现失败|不能提现|提不出来|无法提现|账户冻结|解冻费|税费|继续入金|继续充值|继续交|下载.{0,8}(App|APP|app|软件|平台)|充值|入金)")
ROMANCE_CONTEXT_PATTERN = re.compile(r"(杀猪盘|网恋|恋爱|婚恋|暧昧|对象|男女朋友|男朋友|女朋友|情感|每天关心|交友)")
LOAN_CONTEXT_PATTERN = re.compile(
    r"(网络贷款|贷款|放款|贷款App|贷款APP|贷款app|贷款软件|借款平台|借款App|借款APP|借款app|借款软件|"
    r"银行卡填错|放款前|刷流水|包装费|会员费|资料费|校园贷|学生贷款|注销贷款|提升额度)"
)
GAME_TRADE_CONTEXT_PATTERN = re.compile(r"(游戏群|游戏交易|游戏装备|游戏账号|装备|账号交易|皮肤|点券|代充|验货|卖号|买号|担保交易)")
CAMPUS_LOAN_CONTEXT_PATTERN = re.compile(r"(校园贷|注销校园贷|注销贷款|征信|影响征信|清空额度|学生贷款|校园额度|学生账户)")

BASE_FEATURE_SCORES: Dict[str, int] = {
    "陌生人引导": 10,
    "任务返佣": 25,
    "已发生转账": 45,
    "索要验证码": 35,
    "索要银行卡或身份信息": 35,
    "索要银行流水或卡号": 40,
    "冒充公检法": 45,
    "涉案违法物品恐吓": 45,
    "冒充客服": 30,
    "要求垫付资金": 35,
    "承诺返利": 20,
    "小额返利": 15,
    "高收益诱导": 30,
    "保本稳赚承诺": 25,
    "无法提现": 40,
    "点击陌生链接": 25,
    "私下交易": 30,
    "低价代充": 25,
    "账号密码索取": 35,
    "诱导下载陌生APP": 35,
    "贷款前收费": 35,
    "校园贷包装": 25,
    "屏幕共享": 40,
    "远程控制": 40,
    "要求继续补单": 40,
    "要求缴纳解冻费": 40,
    "要求删除证据": 30,
}

INTERVENTION_GOAL_ALIASES = {
    "stop_screen_sharing": "stop_screen_share",
    "stop_screen_share": "stop_screen_share",
    "stop_remote_control": "stop_screen_share",
    "stop_transfer": "stop_transfer",
    "stop_payment": "stop_transfer",
    "stop_code_leak": "stop_code_leak",
    "stop_verification_code": "stop_code_leak",
    "stop_sensitive_info": "stop_sensitive_info",
    "stop_sensitive_information": "stop_sensitive_info",
    "stop_app_install": "stop_app_install",
    "stop_click_link": "stop_click_link",
    "call_police": "call_police",
    "preserve_evidence": "preserve_evidence",
    "ask_clarification": "ask_clarification",
}

DEFAULT_ADVICE_TEMPLATE_IDS = {
    "PKG_SERVICE_CODE_001": "ADV_CODE_HIGH_001",
    "PKG_SERVICE_SCREEN_001": "ADV_SERVICE_SCREEN_HIGH_001",
    "PKG_JOB_FEE_HIGH_001": "ADV_JOB_FEE_HIGH_001",
}


def risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "极高风险"
    if score >= 60:
        return "高风险"
    if score >= 30:
        return "中风险"
    if score > 0:
        return "低风险"
    return "风险未知"


def _rules_dir() -> Path:
    override = os.getenv("ANTI_FRAUD_RULES_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[1] / "rules"


def normalize_intervention_goal(value: Any) -> str:
    goal = str(value or "").strip()
    return INTERVENTION_GOAL_ALIASES.get(goal, goal)


def _dedupe(items: Iterable[Any], limit: int = 8) -> List[str]:
    result: List[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def rule_config_root() -> Path:
    return _rules_dir()


def reload_rule_config() -> Dict[str, Any]:
    """Hot-reload JSON/Mongo rule config without restarting the service."""
    load_scam_packages.cache_clear()
    cache_clear = getattr(_load_rules, "cache_clear", None)
    if callable(cache_clear):
        cache_clear()
    packages = load_scam_packages()
    return {
        "message": "规则配置已热更新",
        "rules_dir": str(_rules_dir()),
        "package_count": len(packages),
        "packages": [
            {
                "scam_id": package.get("scam_id", ""),
                "name": package.get("name", ""),
                "version": package.get("version", ""),
                "rule_count": len(package.get("rules") or []),
                "path": package.get("_package_path", ""),
            }
            for package in packages
        ],
    }


@lru_cache(maxsize=1)
def load_scam_packages() -> List[Dict[str, Any]]:
    """Load local Scam Package JSON files.

    Invalid packages are skipped with a warning so one experimental package
    cannot break production risk checks.
    """
    package_dir = _rules_dir() / "scam_packages"
    if not package_dir.exists():
        return []

    packages: List[Dict[str, Any]] = []
    for path in sorted(package_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("配置包顶层必须是对象")
            if not data.get("scam_id") or not data.get("name"):
                raise ValueError("配置包缺少 scam_id/name")
            data["_package_path"] = str(path)
            packages.append(data)
        except Exception as exc:
            logger.warning(f"Scam Package 加载失败，已跳过 {path}: {exc}")
    return packages


def _package_feature_docs() -> List[Dict[str, Any]]:
    features: List[Dict[str, Any]] = []
    for package in load_scam_packages():
        for item in package.get("features") or []:
            if not isinstance(item, dict) or not item.get("feature_name"):
                continue
            features.append(
                {
                    "feature_name": str(item.get("feature_name")),
                    "keywords": [str(word) for word in item.get("keywords") or [] if word],
                    "weight": int(item.get("weight", 20) or 20),
                    "explanation": str(item.get("explanation") or ""),
                    "fraud_type": str(package.get("name") or ""),
                    "source": f"scam_package:{package.get('scam_id')}",
                }
            )
    return features


def _package_rules() -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for package in load_scam_packages():
        fraud_type = str(package.get("name") or "")
        for item in package.get("rules") or []:
            if not isinstance(item, dict) or not item.get("rule_id"):
                continue
            score = int(item.get("risk_score", item.get("score", 0)) or 0)
            rule_fraud_type = str(item.get("fraud_type") or item.get("risk_scene") or fraud_type)
            doc = {
                "rule_id": str(item.get("rule_id")),
                "rule_name": str(item.get("rule_name") or item.get("name") or f"{rule_fraud_type}配置包规则"),
                "fraud_type": rule_fraud_type,
                "stages": item.get("stages") or item.get("risk_stages") or [],
                "conditions": item.get("conditions") or {},
                "risk_score": score,
                "score": score,
                "risk_level": str(item.get("risk_level") or item.get("min_level") or risk_level_from_score(score)),
                "intervention_goal": normalize_intervention_goal(item.get("intervention_goal") or item.get("intervention_action") or "stop_transfer"),
                "advice_template_id": str(item.get("advice_template_id") or item.get("advice_template") or ""),
                "explanation": str(item.get("explanation") or ""),
                "suggested_action": str(
                    item.get("suggested_action")
                    or item.get("dissuasion_text")
                    or item.get("intervention_text")
                    or item.get("reply_template")
                    or ""
                ),
                "enabled": item.get("enabled", True),
                "source": f"scam_package:{package.get('scam_id')}",
            }
            rules.append(doc)
    return rules


def infer_fraud_types(text: str) -> List[str]:
    """Infer candidate scam types from core aliases and Scam Packages."""
    lowered = (text or "").lower()
    mapping: List[Tuple[str, List[str]]] = list(CORE_FRAUD_TYPE_ALIASES)
    for package in load_scam_packages():
        aliases = [str(item) for item in package.get("aliases") or [] if item]
        mapping.append((str(package.get("name") or ""), aliases + [str(package.get("name") or "")]))

    result: List[str] = []
    seen = set()
    for fraud_type, words in mapping:
        if not fraud_type:
            continue
        if any(word and word.lower() in lowered for word in words):
            if fraud_type not in seen:
                result.append(fraud_type)
                seen.add(fraud_type)
    return result or ["未知"]


def _prioritize_specific_fraud_types(text: str, fraud_types: List[str]) -> List[str]:
    """Move more specific scam scenes ahead of broad relationship labels."""
    text = text or ""
    brushing_context = bool(BRUSHING_CONTEXT_PATTERN.search(text))
    strong_acquaintance = bool(STRONG_ACQUAINTANCE_PATTERN.search(text))
    if brushing_context and not strong_acquaintance:
        fraud_types = [item for item in fraud_types if item != "冒充熟人诈骗"]
    priority: List[str] = []
    investment_context = bool(INVESTMENT_CONTEXT_PATTERN.search(text))
    romance_context = bool(ROMANCE_CONTEXT_PATTERN.search(text))
    loan_context = bool(LOAN_CONTEXT_PATTERN.search(text))
    game_trade_context = bool(GAME_TRADE_CONTEXT_PATTERN.search(text))
    campus_loan_context = bool(CAMPUS_LOAN_CONTEXT_PATTERN.search(text))
    if brushing_context and not loan_context:
        fraud_types = [item for item in fraud_types if item != "网络贷款诈骗"]
    if investment_context and not loan_context:
        fraud_types = [item for item in fraud_types if item != "网络贷款诈骗"]
    if investment_context and not romance_context:
        fraud_types = [item for item in fraud_types if item not in {"杀猪盘诈骗", "情感交友诱导投资诈骗"}]
    if game_trade_context:
        fraud_types = [item for item in fraud_types if item not in {"网络贷款诈骗", "冒充熟人诈骗"}]
    if campus_loan_context and not game_trade_context:
        fraud_types = [item for item in fraud_types if item != "游戏交易诈骗"]
    virtual_currency_laundering_context = bool(
        re.search(r"(USDT|usdt|虚拟币|虚拟货币|数字货币|钱包地址|链上转账|买U|U商)", text)
        and re.search(r"(跑分|刷流水|代收|收款|收款码|代收代付|帮忙过账|转一圈|高佣金|日结)", text)
    )
    live_private_trade_context = bool(
        re.search(r"(直播间|直播带货|直播购物|私域|福利群|群接龙|加客服微信|小程序下单)", text)
        and re.search(r"(扫码付款|私下付款|微信转账|支付宝转账|不走平台|低价|内部价|福利价|清仓|限时秒杀)", text)
    )
    if virtual_currency_laundering_context:
        fraud_types = [item for item in fraud_types if item != "网络贷款诈骗"]
    if live_private_trade_context and not re.search(r"(退款|理赔|取消会员|百万保障|快递|售后退款)", text):
        fraud_types = [item for item in fraud_types if item != "冒充客服诈骗"]
    if investment_context and (INVESTMENT_HIGH_RISK_PATTERN.search(text) or "虚假投资理财诈骗" in fraud_types):
        priority.append("虚假投资理财诈骗")
    if re.search(r"(中奖|领奖|兑奖|免费领|抽中|福利礼品|盲盒)", text):
        priority.append("虚假中奖/免费礼品诈骗")
    if re.search(r"(助学金|奖助学金|奖学金|学费退费|教育补贴|补贴到账|资助金)", text):
        priority.append("奖助学金/学费退费诈骗")
    if re.search(r"(求职|实习|招聘|就业班|推荐实习|就业推荐|新媒体运营|运营就业班|培训费|培训贷|入职押金|保offer|不就业全额退款)", text):
        priority.append("求职实习招聘诈骗")
    if re.search(r"(航班|机票|火车票|车次|退票|退改签|航班取消|航班延误|退票理赔|改签理赔)", text):
        priority.append("机票火车票退改签诈骗")
    if re.search(r"(两卡|跑分|出租银行卡|出借银行卡|出租电话卡|收款码|帮忙收款|转出去)", text):
        priority.append("两卡出租出借与跑分诈骗")
    if virtual_currency_laundering_context:
        priority.append("虚拟货币洗钱跑分诈骗")
    if live_private_trade_context:
        priority.append("直播带货/私域交易诈骗")
    if brushing_context:
        priority.append("刷单返利诈骗")
    if game_trade_context:
        priority.append("游戏交易诈骗")
    if re.search(r"(安全账户|公检法|涉案|洗钱|通缉令|逮捕令|违法物品|违禁品|涉案物品|违法包裹|涉嫌违法)", text):
        priority.append("冒充公检法诈骗")
    if re.search(r"(解冻费|刷流水|放款前|贷款App|贷款APP|校园贷|征信|注销校园贷|清空额度)", text, re.IGNORECASE) and loan_context and not investment_context and not brushing_context:
        priority.append("网络贷款诈骗")

    reordered: List[str] = []
    for item in priority + fraud_types:
        if item and item not in reordered:
            reordered.append(item)
    return reordered or fraud_types


def _is_true(value: Any) -> bool:
    return value is True or str(value).lower() == "true"


def _is_small_rebate_returned(slots: Dict[str, Any], features: Iterable[str] | None = None, text: str = "") -> bool:
    features = set(features or [])
    merged = f"{text or ''} {' '.join(features)}"
    if not _is_true(slots.get("has_paid")):
        return False
    if not (_is_true(slots.get("has_received_rebate")) or "小额返利" in features):
        return False
    if _is_true(slots.get("has_unrecovered_loss")):
        return False
    return not re.search(r"(没返|未返|提现失败|不能提现|提不出来|无法提现|冻结|解冻费|钱没回来|损失|亏了)", merged)


def _extra_features(text: str, slots: Dict[str, Any]) -> List[str]:
    compact = re.sub(r"\s+", "", text or "")
    current_action = str(slots.get("current_requested_action") or "")
    features: List[str] = []
    if re.search(r"返\s*\d+", text) or re.search(r"\d+\s*返\s*\d+", text):
        features.append("承诺返利")
    if re.search(r"(返了|返过|返钱|返现|返佣|返利)", text):
        features.append("承诺返利")
    if re.search(r"(点赞|关注|短视频|刷单|做任务).{0,18}(赚钱|返利|返佣|返钱|一单|每单)|((一单|每单).{0,8}(赚|返).{0,8}\d+)", text):
        features.append("任务返佣")
    if re.search(
        r"(前|头)?[一二两三\d]+单.{0,16}(返了|返还|返回给我|返给我|返现|返钱|返佣|到账|赚了)"
        r"|小额.{0,6}(返利|返现|返钱|返佣)"
        r"|(已经|已|刚刚|刚才)?.{0,10}(返了|返还了|返回给我了?|返给我了?|返现了|返钱了|返佣了|到账了|赚了)\s*\d*",
        text,
    ):
        features.append("小额返利")
    if re.search(r"(提现|提钱|出款).{0,10}(失败|冻结|提不出来|不能|无法|才可以|才能|继续|再)|(.{0,10}(才可以|才能).{0,6}(提现|出款))", text):
        features.append("无法提现")
    if _is_true(slots.get("has_continue_payment_request")):
        features.append("要求继续补单")
    if re.search(r"(让我|叫我|要求|要我|必须|准备|马上|现在|继续|再).{0,20}(转账|汇款|付款|付钱|打款|充值|补单|垫付|垫钱|借钱|借款|借他|借她|周转|代付|帮他付|帮忙转|交钱|保证金|解冻费|税费)", compact):
        features.append("要求垫付资金")
    if any(word in text for word in ["保证金", "押金", "定金", "订金", "解冻费", "手续费", "税费", "刷流水"]):
        features.append("要求垫付资金")
    if re.search(r"(已经|已|刚|刚刚)[^，。；,;]{0,12}(转账|转钱|付款|付钱|支付|充值|打款|汇款|交钱|交费|缴费)\s*\d*", text):
        features.append("已发生转账")
    if re.search(r"(已经|已|刚|刚刚)?\s*(给|向)?[^，。；,;]{0,12}(转了|转过|转账了|付了|付款了|打款|汇了|充值了|补单了|垫付了|交了)\s*\d*", text):
        features.append("已发生转账")
    if _is_true(slots.get("has_paid")) and not _is_small_rebate_returned(slots, features, text):
        features.append("已发生转账")
    if (
        _is_true(slots.get("has_transferred_virtual_asset"))
        or re.search(r"(游戏装备|游戏账号|装备|账号|皮肤|游戏币|点券|虚拟资产).{0,20}(给他了|给对方了|给了|交给.*了|转给.*了|发给.*了|都给|已经给)", text)
        or re.search(r"(给他了|给对方了|给了|交给.*了|转给.*了|发给.*了|都给|已经给).{0,12}(游戏装备|游戏账号|装备|账号|皮肤|游戏币|点券|虚拟资产)", text)
        or re.search(r"(游戏装备|游戏账号|装备|账号|皮肤|游戏币|点券|虚拟资产)[\s\S]{0,80}(已经|已|都|全都).{0,12}(给他|给对方|给了|交给|转给|发给)", text)
    ):
        features.append("虚拟资产已交付")
    if _is_true(slots.get("counterparty_disappeared")) or re.search(r"(失联|拉黑|不回消息|联系不上|删好友|跑路)", text):
        features.append("交易对象失联")
    if re.search(r"(游戏装备|游戏账号|装备|账号|皮肤|游戏币|点券|虚拟资产)", text):
        features.append("私下游戏交易")
    if re.search(r"(价值|估值).{0,8}\d+\s*(万|w|W|元|块)|\d+\s*(万|w|W).{0,8}(装备|账号|皮肤|虚拟资产|价值)", text):
        features.append("高价值虚拟资产")
    if re.search(r"(低价代充|半价点券|低价皮肤|内部点券|便宜充值)", text):
        features.append("低价代充装备诱导")
    if re.search(r"(先|要求|让我|叫我).{0,12}(给|交|发|转).{0,12}(游戏装备|装备|游戏账号|账号|皮肤|点券|虚拟资产|验货)", text) or "先给他验货" in text:
        features.append("交付虚拟资产要求")
    if re.search(r"(微信密码|账号密码|登录密码|支付密码|把.{0,8}密码.{0,8}(告诉|发给|给)|要.{0,8}密码|索要.{0,8}密码)", text):
        features.append("账号密码索取")
    if re.search(r"(账号密码|验号|先给账号|扫码登录)", text):
        features.append("游戏账号密码索取")
    if re.search(r"(游戏|账号|装备|皮肤|点券).{0,16}(保证金|解冻费|手续费|担保费|中介费|认证金)", text):
        features.append("游戏交易保证金解冻费")
    if _is_true(slots.get("has_shared_code")) or "验证码" in current_action:
        features.append("索要验证码")
    if "密码" in current_action:
        features.append("账号密码索取")
    if re.search(
        r"(让我|叫我|要求|要我|问我要|索要|需要我|说让我|说要我).{0,30}(银行卡|银行卡号|卡号|银行流水|身份证|身份证号|身份信息|个人信息|实名信息|敏感信息)",
        compact,
    ) or any(word in current_action for word in ["银行卡", "银行卡号", "卡号", "银行流水", "身份证", "身份信息", "个人信息", "敏感信息"]):
        features.append("索要银行卡或身份信息")
        if any(word in f"{compact}{current_action}" for word in ["银行流水", "卡号", "银行卡号"]):
            features.append("索要银行流水或卡号")
    if re.search(r"(违法物品|违禁品|涉案物品|违法包裹|涉嫌违法|网购.{0,8}违法)", compact):
        features.append("涉案违法物品恐吓")
        features.append("冒充公检法")
    if _is_true(slots.get("has_screen_share")):
        features.append("屏幕共享")
    if _is_true(slots.get("has_downloaded_app")):
        features.append("诱导下载陌生APP")
    if _is_true(slots.get("has_provided_identity_or_bank")):
        features.append("索要银行卡或身份信息")
    if any(word in text for word in ["投资App", "投资APP", "投资app", "投资软件"]):
        features.extend(["陌生投资平台", "诱导下载陌生APP"])
    if re.search(r"\d+\s*%.*收益|收益.*\d+\s*%", text):
        features.append("高收益诱导")
    if any(word in text for word in ["税费", "缴税"]):
        features.append("要求缴纳解冻费")
    if "安全账户" in text:
        features.extend(["冒充公检法", "要求垫付资金"])
    return features


GENERIC_PACKAGE_KEYWORDS = {
    "验证码",
    "短信码",
    "动态码",
    "登录码",
    "支付码",
    "银行卡",
    "身份证",
    "支付密码",
    "二维码",
    "链接",
    "网址",
    "http",
    "https",
    "屏幕共享",
    "共享屏幕",
    "会议软件",
    "远程协助",
    "远程控制",
    "安装会议软件",
    "我教你操作",
    "保证金",
    "押金",
    "定金",
    "订金",
    "手续费",
    "服务费",
    "培训费",
    "课程费",
    "资料费",
    "体检费",
    "报名费",
    "税费",
    "先交",
    "先付",
    "缴费",
    "交钱",
    "解冻费",
    "认证费",
    "下载",
    "下载App",
    "下载APP",
    "下载app",
    "App",
    "APP",
    "app",
    "软件",
    "平台",
    "充值",
    "老师",
    "导师",
    "提现失败",
}


ROMANCE_INVESTMENT_CONTEXT_PATTERN = ROMANCE_CONTEXT_PATTERN


def _package_has_required_context(package: Dict[str, Any], text: str) -> bool:
    """Prevent broad package keywords from leaking into unrelated scenes."""
    scam_id = str(package.get("scam_id") or "")
    if scam_id == "scam_fake_loan":
        return bool(LOAN_CONTEXT_PATTERN.search(text or ""))
    if str(package.get("scam_id") or "") == "scam_romance_investment":
        return bool(ROMANCE_INVESTMENT_CONTEXT_PATTERN.search(text or ""))
    return True


def _package_context_active(package: Dict[str, Any], text: str) -> bool:
    lowered = (text or "").lower()
    anchors = [str(package.get("name") or "")]
    anchors.extend(str(item) for item in package.get("aliases") or [] if item)
    if any(anchor and anchor.lower() in lowered for anchor in anchors):
        return True
    for item in package.get("features") or []:
        if not isinstance(item, dict):
            continue
        for keyword in item.get("keywords") or []:
            keyword = str(keyword or "")
            if keyword and keyword not in GENERIC_PACKAGE_KEYWORDS and keyword.lower() in lowered:
                return True
    return False


def _package_features(text: str) -> List[str]:
    features: List[str] = []
    for package in load_scam_packages():
        if not _package_has_required_context(package, text):
            continue
        if not _package_context_active(package, text):
            continue
        for item in package.get("features") or []:
            if not isinstance(item, dict) or not item.get("feature_name"):
                continue
            if any(str(keyword or "") and str(keyword) in text for keyword in item.get("keywords") or []):
                features.append(str(item["feature_name"]))
    return features


def _remove_negated_features(text: str, features: List[str]) -> List[str]:
    negated_patterns = {
        "已发生转账": [r"(还没|没有|没|未)[^，。；,;]{0,10}(转账|转钱|转过钱|转过|转了|付款|付钱|付过|充值|打款|补单|交钱)"],
        "要求垫付资金": [r"(还没|没有|没|未)[^，。；,;]{0,10}(转账|转钱|转过钱|转过|转了|付款|付钱|付过|充值|打款|补单|垫付|垫钱|交钱)"],
        "要求继续补单": [r"(还没|没有|没|未)[^，。；,;]{0,10}(补单|联单|连单)"],
        "索要验证码": [r"(还没|没有|没|未)[^，。；,;]{0,8}(给|发|填|提供)?[^，。；,;]{0,8}(验证码|短信码|动态码)"],
        "屏幕共享": [r"(还没|没有|没|未|不再|不会)[^，。；,;]{0,12}(屏幕共享|共享屏幕|远程控制|远程协助)"],
        "远程控制": [r"(还没|没有|没|未|不再|不会)[^，。；,;]{0,12}(屏幕共享|共享屏幕|远程控制|远程协助)"],
        "诱导下载陌生APP": [r"(还没|没有|没|未)[^，。；,;]{0,8}(下载|安装)[^，。；,;]{0,8}(App|APP|app|软件)"],
        "点击陌生链接": [r"(还没|没有|没|未)[^，。；,;]{0,8}(点|点击|打开|进入)[^，。；,;]{0,8}(链接|网址|二维码)"],
        "索要银行卡或身份信息": [r"(还没|没有|没|未)[^，。；,;]{0,8}(填|给|提供|上传|告诉)[^，。；,;]{0,12}(银行卡|身份证|人脸识别|微信密码|登录密码|支付密码|账号密码|敏感信息)"],
        "账号密码索取": [r"(还没|没有|没|未)[^，。；,;]{0,8}(给|发|提供|告诉)[^，。；,;]{0,12}(微信密码|登录密码|支付密码|账号密码|密码)"],
    }
    false_positive_patterns = {
        "索要银行卡或身份信息": [
            r"银行卡.{0,8}(涉案|冻结|异常|洗钱|风险)",
            r"(涉案|冻结|异常|洗钱|风险).{0,8}银行卡",
        ],
    }
    kept: List[str] = []
    for feature in features:
        patterns = negated_patterns.get(feature, []) + false_positive_patterns.get(feature, [])
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
            continue
        if feature not in kept:
            kept.append(feature)
    return kept


def _feature_order(features: Iterable[str]) -> List[str]:
    ordered: List[str] = []
    known_order = list(RISK_FEATURES) + [item["feature_name"] for item in _package_feature_docs()]
    feature_set = set(features)
    for feature in known_order:
        if feature in feature_set and feature not in ordered:
            ordered.append(feature)
    for feature in features:
        if feature not in ordered:
            ordered.append(feature)
    return ordered


def extract_risk_features(text: str, context: Dict[str, Any] | None = None) -> List[str]:
    context = context or {}
    slots = context.get("slots") or {}
    initial = context.get("risk_features") or context.get("normalized_risk_features") or []
    merged_text = build_context_text(text, context)
    features = normalize_risk_features(list(initial) + _extra_features(merged_text, slots), merged_text)
    features.extend(_package_features(merged_text))
    return _feature_order(_remove_negated_features(merged_text, features))


def _feature_score(feature: str) -> int:
    if feature in BASE_FEATURE_SCORES:
        return BASE_FEATURE_SCORES[feature]
    for item in _package_feature_docs():
        if item["feature_name"] == feature:
            return int(item.get("weight", 20) or 20)
    return 10


def _infer_stage(features: List[str], slots: Dict[str, Any], text: str) -> str:
    action = str(slots.get("current_requested_action") or "")
    if _is_small_rebate_returned(slots, features, text):
        return "小额返利诱导阶段"
    if _is_true(slots.get("has_paid")) or _is_true(slots.get("has_transferred_virtual_asset")) or "已发生转账" in features or "虚拟资产已交付" in features:
        return "损失发生阶段"
    if any(item in features for item in ["无法提现", "要求缴纳解冻费", "要求继续补单"]) or any(word in action for word in ["解冻费", "继续补单"]):
        return "提现受阻阶段"
    if any(item in features for item in ["要求垫付资金", "贷款前收费"]) or any(word in action for word in ["转账", "充值", "保证金", "缴纳"]):
        return "资金转账前阶段"
    if any(item in features for item in ["索要验证码", "账号密码索取", "索要银行卡或身份信息", "索要银行流水或卡号", "屏幕共享", "远程控制"]):
        return "信息索取阶段"
    if any(item in features for item in ["诱导下载陌生APP", "点击陌生链接"]):
        return "引流诱导阶段"
    if any(item in features for item in ["小额返利", "承诺返利", "高收益诱导", "保本稳赚承诺"]):
        return "建立信任阶段"
    if any(word in text for word in ["什么是", "怎么识别", "如何防范", "科普", "案例"]):
        return "科普学习"
    return "初步接触阶段" if features else "未知"


def _stage_match(rule: Dict[str, Any], current_stage: str) -> bool:
    rule_stages = [str(item) for item in rule.get("stages") or [] if item]
    if not rule_stages or not current_stage or current_stage == "未知":
        return True
    if current_stage in rule_stages:
        return True
    broad_groups = {
        "损失发生阶段": {"损失发生阶段", "止损报警阶段", "资金转账阶段"},
        "提现受阻阶段": {"提现受阻阶段", "损失发生阶段", "资金转账阶段"},
        "资金转账前阶段": {"资金转账前阶段", "资金转账阶段", "信息索取阶段"},
        "信息索取阶段": {"信息索取阶段", "信息泄露阶段", "资金转账前阶段"},
        "引流诱导阶段": {"引流诱导阶段", "初步接触阶段", "建立信任阶段"},
        "建立信任阶段": {"建立信任阶段", "小额试探阶段", "引流诱导阶段"},
        "小额返利诱导阶段": {"小额返利诱导阶段", "建立信任阶段", "小额试探阶段", "资金转账前阶段", "资金转账阶段", "引流诱导阶段"},
    }
    return bool(broad_groups.get(current_stage, {current_stage}) & set(rule_stages))


def _condition_features(rule: Dict[str, Any]) -> List[str]:
    conditions = rule.get("conditions") or {}
    return list(conditions.get("all") or []) + list(conditions.get("any") or [])


def _keyword_groups(conditions: Dict[str, Any]) -> List[List[str]]:
    groups: List[List[str]] = []
    for group in conditions.get("must_include_any") or []:
        words = [str(word).strip() for word in _as_list(group) if str(word).strip()]
        if words:
            groups.append(words)
    return groups


def _keyword_conditions_match(conditions: Dict[str, Any], text: str) -> Tuple[bool, List[str]]:
    """Match config-only keyword groups such as [["客服"], ["退款"]]."""
    groups = _keyword_groups(conditions)
    must_all = [str(word).strip() for word in _as_list(conditions.get("must_include_all")) if str(word).strip()]
    include_any = [str(word).strip() for word in _as_list(conditions.get("include_any")) if str(word).strip()]

    if not groups and not must_all and not include_any:
        return True, []

    hits: List[str] = []
    for word in must_all:
        if word not in text:
            return False, []
        hits.append(word)

    for group in groups:
        hit = next((word for word in group if word in text), "")
        if not hit:
            return False, []
        hits.append(hit)

    if include_any:
        hit = next((word for word in include_any if word in text), "")
        if not hit:
            return False, []
        hits.append(hit)

    return True, _dedupe(hits, limit=12)


def _all_rules() -> List[Dict[str, Any]]:
    rules = [rule for rule in _load_rules() if rule.get("enabled", True) is not False]
    rules.extend(rule for rule in _package_rules() if rule.get("enabled", True) is not False)
    return rules


def _match_rules(
    features: List[str],
    fraud_types: List[str],
    stage: str,
    text: str,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    feature_set = set(features)
    fraud_type_set = set(fraud_types)
    allowed_features = set(RISK_FEATURES) | {item["feature_name"] for item in _package_feature_docs()}
    matched: List[Dict[str, Any]] = []
    warnings: List[str] = []

    fraud_type_order = {
        fraud_type: index
        for index, fraud_type in enumerate(item for item in fraud_types if item and item != "未知")
    }
    horizontal_types = {"钓鱼链接诈骗", "验证码/账户盗刷诈骗", "屏幕共享/远程控制诈骗"}

    try:
        rules = _all_rules()
    except Exception as exc:
        return [], [f"风险规则读取失败：{exc}"]

    for rule in rules:
        invalid = [feature for feature in _condition_features(rule) if feature not in allowed_features]
        if invalid:
            warnings.append(f"跳过非法规则 {rule.get('rule_id', '')}，未知特征：{invalid}")
            continue
        fraud_type = str(rule.get("fraud_type") or "")
        if fraud_type == "冒充熟人诈骗" and BRUSHING_CONTEXT_PATTERN.search(text or "") and not STRONG_ACQUAINTANCE_PATTERN.search(text or ""):
            continue
        if not _stage_match(rule, stage):
            continue

        conditions = rule.get("conditions") or {}
        keyword_match, keyword_hits = _keyword_conditions_match(conditions, text)
        has_keyword_conditions = bool(_keyword_groups(conditions) or conditions.get("must_include_all") or conditions.get("include_any"))
        if fraud_type and fraud_type_set and "未知" not in fraud_type_set and fraud_type not in fraud_type_set and not has_keyword_conditions:
            continue
        if not keyword_match:
            continue

        all_conditions = conditions.get("all") or []
        any_conditions = conditions.get("any") or []
        min_any = int(conditions.get("min_any", 0) or 0)
        all_matched = [item for item in all_conditions if item in feature_set]
        any_matched = [item for item in any_conditions if item in feature_set]
        if len(all_matched) == len(all_conditions) and len(any_matched) >= min_any:
            score = int(rule.get("risk_score", rule.get("score", 0)) or 0)
            matched_features = all_matched + any_matched
            if not matched_features and keyword_hits:
                matched_features = [f"关键词命中：{item}" for item in keyword_hits]
            matched.append(
                {
                    "rule_id": rule.get("rule_id", ""),
                    "rule_name": rule.get("rule_name", ""),
                    "fraud_type": fraud_type,
                    "risk_level": rule.get("risk_level", risk_level_from_score(score)),
                    "risk_score": score,
                    "matched_features": matched_features,
                    "matched_keywords": keyword_hits,
                    "explanation": rule.get("explanation", ""),
                    "suggested_action": rule.get("suggested_action", ""),
                    "intervention_goal": rule.get("intervention_goal", ""),
                    "source": rule.get("source", "risk_rules"),
                }
            )
    matched.sort(
        key=lambda item: (
            1 if str(item.get("fraud_type") or "") in horizontal_types else 0,
            fraud_type_order.get(str(item.get("fraud_type") or ""), 999),
            -int(item.get("risk_score", 0) or 0),
        )
    )
    return matched, warnings


def _evidence_for_features(text: str, features: List[str]) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    package_feature_map = {item["feature_name"]: item for item in _package_feature_docs()}
    for feature in features:
        keywords = list(RISK_FEATURE_SYNONYMS.get(feature, []))
        if feature in package_feature_map:
            keywords.extend(package_feature_map[feature].get("keywords") or [])
        hit = next((keyword for keyword in keywords if keyword and keyword in text), feature if feature in text else "")
        evidence.append(
            {
                "type": "feature",
                "name": feature,
                "source_text": hit,
                "score": _feature_score(feature),
            }
        )
    return evidence


def _default_intervention_goal(features: List[str], matched_rules: List[Dict[str, Any]], slots: Dict[str, Any] | None = None, text: str = "") -> str:
    # Prefer the concrete dangerous action in the current turn over the
    # highest-scoring broad rule. A generic "冒充公检法" rule may score higher,
    # but if the user is being asked for bank statements/card numbers, the next
    # intervention must stop sensitive-info disclosure rather than talk about
    # transfer.
    slots = slots or {}
    if ("已发生转账" in features and not _is_small_rebate_returned(slots, features, text)) or "虚拟资产已交付" in features:
        return "call_police"
    if any(item in features for item in ["出租出借两卡", "帮忙收款跑分", "出租账号收款码"]):
        for rule in matched_rules:
            if str(rule.get("fraud_type") or "") == "两卡出租出借与跑分诈骗" and rule.get("intervention_goal"):
                return str(rule.get("intervention_goal"))
    if "索要验证码" in features or "账号密码索取" in features:
        return "stop_code_leak"
    if "索要银行卡或身份信息" in features or "索要银行流水或卡号" in features:
        return "stop_sensitive_info"
    if "屏幕共享" in features or "远程控制" in features:
        return "stop_screen_share"
    if "要求垫付资金" in features or "要求缴纳解冻费" in features or "要求继续补单" in features:
        return "stop_transfer"
    if "诱导下载陌生APP" in features:
        return "stop_app_install"
    if matched_rules and matched_rules[0].get("intervention_goal"):
        return str(matched_rules[0].get("intervention_goal"))
    return "ask_clarification"


def _top_rule_for_goal(matched_rules: List[Dict[str, Any]], goal: str) -> Dict[str, Any]:
    if not matched_rules:
        return {}
    if goal:
        for rule in matched_rules:
            if str(rule.get("intervention_goal") or "") == goal:
                return rule
    return matched_rules[0]


def _advice_template_id(rule: Dict[str, Any]) -> str:
    explicit = str((rule or {}).get("advice_template_id") or "").strip()
    if explicit:
        return explicit
    return DEFAULT_ADVICE_TEMPLATE_IDS.get(str((rule or {}).get("rule_id") or ""), "")


def _is_learning_only_query(text: str) -> bool:
    learning_words = ["什么是", "是什么意思", "怎么识别", "如何识别", "怎么防范", "如何防范", "反诈作业", "科普", "案例"]
    risk_action_patterns = [
        r"让我(?!们)",
        r"叫我",
        r"要求我",
        r"要我",
        r"准备.{0,6}(转账|付款|充值|补单|给验证码|共享屏幕)",
        r"正在.{0,6}(转账|付款|充值|补单|给验证码|共享屏幕)",
        r"已经.{0,6}(转账|付款|充值|补单|给验证码|共享屏幕)",
        r"密码",
        r"转账",
        r"付款",
        r"充值",
        r"补单",
        r"保证金",
        r"解冻费",
        r"验证码",
        r"屏幕共享",
        r"远程控制",
        r"下载",
    ]
    return any(word in text for word in learning_words) and not any(re.search(pattern, text) for pattern in risk_action_patterns)


def _risk_relevant_history(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep prior risk facts but drop unrelated knowledge-learning turns."""
    filtered: List[Dict[str, Any]] = []
    for item in history or []:
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        text = str(item.get("text") or item.get("content") or "").strip()
        if not text:
            continue
        if _is_learning_only_query(text):
            continue
        filtered.append({**item, "text": text})
    return filtered


def _evaluate_rule_text_from_features(
    *,
    normalized: str,
    full_text: str,
    features: List[str],
    context: Dict[str, Any],
    route_decision: Dict[str, Any],
) -> Dict[str, Any]:
    """基于指定风险特征完成规则匹配、评分和干预目标选择。

    该函数是规则引擎的确定性核心。外部可以先用规则抽取候选，也可以先让
    LLM 裁判候选特征，再把“裁判后的特征”传回来重新计算 matched_rules。
    """
    slots = context.get("slots") or {}
    cleaned_features = [str(feature).strip() for feature in features if str(feature or "").strip()]
    features = _feature_order(cleaned_features)
    small_rebate_returned = _is_small_rebate_returned(slots, features, full_text)
    if small_rebate_returned:
        features = [feature for feature in features if feature != "已发生转账"]

    fraud_types = infer_fraud_types(full_text)
    context_fraud_types = [str(item) for item in context.get("possible_fraud_types") or [] if item]
    if context_fraud_types:
        merged_types: List[str] = []
        for item in context_fraud_types + fraud_types:
            if item and item != "未知" and item not in merged_types:
                merged_types.append(item)
        fraud_types = merged_types or fraud_types
    elif fraud_types == ["未知"]:
        fraud_types = context_fraud_types or ["未知"]

    stage = (
        _infer_stage(features, context.get("slots") or {}, full_text)
        if context.get("force_stage_recompute")
        else context.get("fraud_stage") or _infer_stage(features, context.get("slots") or {}, full_text)
    )
    fraud_types = _prioritize_specific_fraud_types(full_text, fraud_types)
    matched_rules, warnings = _match_rules(features, fraud_types, stage, full_text)

    feature_score = min(100, sum(_feature_score(feature) for feature in features))
    top_rule_score = matched_rules[0]["risk_score"] if matched_rules else 0
    score = max(feature_score, top_rule_score)
    risk_signals = route_decision.get("risk_signals") or {}
    if not small_rebate_returned and (
        risk_signals.get("confirmed_exposure_signal")
        or (route_decision.get("routing_decision") or {}).get("force_high_risk")
    ):
        score = max(score, 90)
    if context.get("slots") and any(
        _is_true(slots.get(slot))
        for slot in ["has_paid", "has_transferred_virtual_asset", "has_shared_code", "has_screen_share", "has_downloaded_app", "has_provided_identity_or_bank"]
        if not (slot == "has_paid" and small_rebate_returned)
    ):
        score = max(score, 90)
    if not matched_rules and _is_learning_only_query(normalized):
        score = min(score, 29)
    if small_rebate_returned:
        score = min(score, 86)
    score = min(100, score)

    intervention_goal = _default_intervention_goal(features, matched_rules, slots, full_text)
    top_rule = matched_rules[0] if matched_rules else {}
    fraud_type = top_rule["fraud_type"] if top_rule else fraud_types[0]
    if fraud_type and fraud_type != "未知":
        fraud_types = [fraud_type] + [item for item in fraud_types if item != fraud_type]
    rule_evidence = [
        {
            "type": "rule",
            "rule_id": rule.get("rule_id", ""),
            "name": rule.get("rule_name", ""),
            "score": rule.get("risk_score", 0),
            "matched_features": rule.get("matched_features", []),
            "matched_keywords": rule.get("matched_keywords", []),
            "explanation": rule.get("explanation", ""),
        }
        for rule in matched_rules[:5]
    ]
    evidence = _evidence_for_features(full_text, features) + rule_evidence
    advice = top_rule.get("suggested_action") or "当前信息仍需补充，请先暂停操作并通过官方渠道核实对方身份。"
    next_actions = [
        "不要继续转账、充值、垫付或交付账号/装备等虚拟资产",
        "不要提供验证码、银行卡、身份证或人脸识别信息",
        "保存聊天记录、对方账号、链接和转账凭证",
    ]
    if score >= 60 and not small_rebate_returned:
        next_actions.append("如已转账或泄露信息，尽快联系银行/支付平台止付并报警或拨打96110咨询")

    return {
        "engine_version": "scam-rule-engine-v1",
        "fraud_type": fraud_type,
        "scam_type": fraud_type,
        "possible_fraud_types": fraud_types,
        "risk_stage": stage,
        "fraud_stage": stage,
        "risk_score": score,
        "risk_level": top_rule.get("risk_level") or risk_level_from_score(score),
        "risk_features": features,
        "normalized_risk_features": features,
        "matched_rules": matched_rules,
        "evidence": evidence,
        "intervention_goal": intervention_goal,
        "advice_template_id": _advice_template_id(top_rule),
        "advice": advice,
        "next_actions": next_actions,
        "entities": {
            "urls": extract_urls(full_text),
            "amounts": extract_amounts(full_text),
        },
        "warnings": warnings,
    }


def evaluate_rule_text(
    text: str,
    context: Dict[str, Any] | None = None,
    route_decision: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Evaluate one text turn and return a structured risk result."""
    context = dict(context or {})
    route_decision = route_decision or context.get("route_decision") or {}
    normalized = normalize_text(text)
    full_text = build_context_text(normalized, context)
    features = extract_risk_features(normalized, context)
    return _evaluate_rule_text_from_features(
        normalized=normalized,
        full_text=full_text,
        features=features,
        context=context,
        route_decision=route_decision,
    )


def evaluate_rule_text_with_features(
    text: str,
    features: List[str],
    context: Dict[str, Any] | None = None,
    route_decision: Dict[str, Any] | None = None,
    force_stage_recompute: bool = False,
) -> Dict[str, Any]:
    """用外部裁判后的风险特征重新评估规则。

    与 ``evaluate_rule_text`` 不同，这里不会重新抽取风险特征，也不会再次做
    正则否定过滤。调用方已经完成语义裁判时，应使用该入口保证规则匹配、
    阶段和评分都基于同一份事实。
    """
    context = dict(context or {})
    if force_stage_recompute:
        context["force_stage_recompute"] = True
    route_decision = route_decision or context.get("route_decision") or {}
    normalized = normalize_text(text)
    full_text = build_context_text(normalized, context)
    return _evaluate_rule_text_from_features(
        normalized=normalized,
        full_text=full_text,
        features=features,
        context=context,
        route_decision=route_decision,
    )


def _build_rule_state_input(state: Dict[str, Any]) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """把 LangGraph state 转换成规则引擎输入。

    这里集中处理“只使用用户事实文本”的约束，避免不同节点自己拼上下文。
    """
    text = str(state.get("original_query") or "")
    scam_understanding = state.get("scam_understanding") or {}
    route_decision = state.get("route_decision") or {}
    risk_prefill = route_decision.get("risk_prefill") or {}
    semantic_frame = route_decision.get("semantic_frame") or {}
    case_state = state.get("case_state") or {}
    previous_fraud_type = (
        state.get("fraud_type")
        or case_state.get("fraud_type")
        or (case_state.get("scam_memory") or {}).get("primary_scam_type")
        or (case_state.get("scam_understanding") or {}).get("primary_scam_type")
        or ""
    )
    possible_fraud_types = (
        state.get("possible_fraud_types")
        or scam_understanding.get("possible_scam_types")
        or risk_prefill.get("fraud_candidates")
        or semantic_frame.get("fraud_candidates")
        or []
    )
    if previous_fraud_type and previous_fraud_type not in possible_fraud_types and previous_fraud_type != "未知":
        possible_fraud_types = [previous_fraud_type] + [item for item in possible_fraud_types if item != previous_fraud_type]
    case_fact_text = str(state.get("case_fact_text") or (state.get("case_state") or {}).get("case_fact_text") or "").strip()
    turn_rewrite = route_decision.get("turn_rewrite") or {}
    rewrite_parts = []
    rewritten_text = str(turn_rewrite.get("rewritten_text") or "").strip()
    if rewritten_text and rewritten_text != text:
        rewrite_parts.append(rewritten_text)
    case_description = str(semantic_frame.get("case_description") or "").strip()
    if case_description and case_description != text:
        rewrite_parts.append(case_description)
    for item in semantic_frame.get("evidence") or []:
        item_text = str(item or "").strip()
        if item_text and item_text != text:
            rewrite_parts.append(item_text)
    context = {
        "history": [] if case_fact_text else _risk_relevant_history(state.get("history") or []),
        # Rule matching must stay grounded in user-originated facts only.
        # Flattened history, memory summaries, LLM rewrites, and previous
        # feature lists may contain assistant warnings or model inferences such
        # as "不要共享屏幕/不要给验证码".  Feeding them back here turns warnings
        # into fake user evidence on later turns.
        "history_text": case_fact_text,
        "memory_summary": "",
        "rewritten_query": " ".join(_dedupe(rewrite_parts, limit=6)),
        "slots": state.get("slots") or {},
        "risk_features": [],
        "normalized_risk_features": [],
        "possible_fraud_types": possible_fraud_types,
        "fraud_stage": state.get("fraud_stage") or scam_understanding.get("stage") or "",
        "route_decision": route_decision,
    }
    return text, context, route_decision


def evaluate_rule_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a workflow state using the same engine as public risk checks."""
    text, context, route_decision = _build_rule_state_input(state)
    return evaluate_rule_text(text, context=context, route_decision=route_decision)


def evaluate_rule_state_with_features(
    state: Dict[str, Any],
    features: List[str],
    force_stage_recompute: bool = True,
) -> Dict[str, Any]:
    """用裁判后的风险特征重新评估整个 workflow state。"""
    text, context, route_decision = _build_rule_state_input(state)
    return evaluate_rule_text_with_features(
        text,
        features,
        context=context,
        route_decision=route_decision,
        force_stage_recompute=force_stage_recompute,
    )
