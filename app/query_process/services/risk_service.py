from typing import Any, Dict, List

from app.query_process.services.anti_fraud_engine import build_anti_fraud_engine_result
from app.query_process.services.scam_rule_engine import (
    evaluate_rule_text,
    infer_fraud_types,
    risk_level_from_score,
)
from app.query_process.services.suspicious_rules import (
    analyze_keyword_blacklist,
    analyze_url_features,
    build_report_advice,
    score_suspicious_item,
)


def evaluate_risk_text(text: str) -> Dict[str, Any]:
    result = evaluate_rule_text(text)
    response = {
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "scam_type": result["scam_type"],
        "fraud_type": result["fraud_type"],
        "risk_stage": result["risk_stage"],
        "possible_fraud_types": result["possible_fraud_types"],
        "risk_features": result["risk_features"],
        "normalized_risk_features": result["normalized_risk_features"],
        "matched_rules": result["matched_rules"],
        "evidence": result["evidence"],
        "intervention_goal": result["intervention_goal"],
        "advice_template_id": result.get("advice_template_id", ""),
        "advice": result["advice"],
        "next_actions": result["next_actions"],
        "entities": result["entities"],
        "engine_version": result["engine_version"],
        "warnings": result["warnings"],
    }
    response["anti_fraud_engine"] = build_anti_fraud_engine_result(
        input_text=text,
        route_decision={
            "primary_intent": "risk_help",
            "workflow_mode": "risk_case_flow",
            "confidence": 1.0,
            "reason": "public risk check",
        },
        risk_result=result,
    )
    response["risk_judgement_card"] = response["anti_fraud_engine"].get("risk_judgement_card", {})
    return response


def check_url_content(content: str) -> Dict[str, Any]:
    url_result = analyze_url_features(content)
    keyword_result = analyze_keyword_blacklist(content)
    risk = score_suspicious_item(url_result, keyword_result)
    score = int(risk.get("risk_score", 0) or 0)
    risk_rules: List[str] = []
    for item in (url_result.get("matched_rules") or []) + (keyword_result.get("matched_rules") or []):
        if item not in risk_rules:
            risk_rules.append(item)
    advice_list = build_report_advice(url_result, keyword_result, score)
    response = {
        "risk_score": score,
        "risk_level": risk_level_from_score(score),
        "risk_rules": risk_rules,
        "url_rules": url_result.get("matched_rules", []),
        "keyword_rules": keyword_result.get("matched_rules", []),
        "urls": url_result.get("urls", []),
        "should_click": score < 30,
        "suggest_report": score >= 30,
        "advice": "；".join(advice_list)
        if score >= 30
        else "未发现明显高危 URL 特征，但仍建议通过官方 App 或官网入口访问。",
    }
    response["anti_fraud_engine"] = build_anti_fraud_engine_result(
        input_text=content,
        route_decision={
            "primary_intent": "url_check",
            "workflow_mode": "url_check",
            "confidence": 1.0,
            "reason": "public url/content check",
        },
        url_result=response,
    )
    response["risk_judgement_card"] = response["anti_fraud_engine"].get("risk_judgement_card", {})
    return response
