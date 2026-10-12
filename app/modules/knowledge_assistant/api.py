import os
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.modules.knowledge_assistant.service import (
    run_unified_anti_fraud_chat_stream,
    search_knowledge,
    unified_anti_fraud_chat,
)
from app.modules.vision_ocr.service import analyze_image_fraud_risk
from app.utils.sse_utils import create_sse_queue


router = APIRouter(tags=["module:knowledge-assistant"])
MAX_IMAGE_UPLOAD_BYTES = int(os.getenv("VISION_IMAGE_MAX_BYTES", str(8 * 1024 * 1024)) or str(8 * 1024 * 1024))
ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp"}
ALLOWED_IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp")


class KnowledgeChatRequest(BaseModel):
    message: str = Field(..., description="用户的反诈咨询内容，可自动分流到科普问答或风险劝阻")
    session_id: Optional[str] = Field(default=None, description="智能反诈助手会话 ID")
    history: List[Dict[str, Any]] = Field(default_factory=list, description="可选的前端对话历史")
    use_llm: bool = Field(default=True, description="是否调用大模型生成回答")
    limit: int = Field(default=8, ge=1, le=20, description="检索材料数量")
    is_stream: bool = Field(default=False, description="是否使用流式返回")
    input_mode: str = Field(default="text", description="输入方式：text 或 voice")
    voice_emotion: Optional[Dict[str, Any]] = Field(default=None, description="前端语音转文字后的情绪识别结果")




def _message_with_voice_emotion_context(message: str, input_mode: str, voice_emotion: Optional[Dict[str, Any]]) -> str:
    if input_mode != "voice" or not isinstance(voice_emotion, dict):
        return message
    label = str(voice_emotion.get("label") or "平稳")[:20]
    tone = str(voice_emotion.get("agentTone") or "自然、清楚、有人味")[:80]
    key = str(voice_emotion.get("key") or "neutral")[:20]
    confidence = voice_emotion.get("confidence")
    confidence_text = f"；置信度约 {confidence:.0%}" if isinstance(confidence, (int, float)) else ""
    return (
        f"{message.strip()}\n\n"
        "【内部语音情绪提示】用户本轮通过语音输入，前端根据转写文本估计"
        f"情绪倾向为“{label}”（{key}{confidence_text}）。建议回应基调：{tone}。"
        "这不是用户陈述的事实，不要在回复中提到语音识别、情绪识别或本提示，"
        "只用于调整安抚程度、措辞节奏和行动建议顺序。"
    )

@router.get("/knowledge/search")
async def knowledge_search(
    query: str = Query(..., description="检索关键词"),
    limit: int = Query(5, ge=1, le=20, description="返回数量"),
):
    return search_knowledge(query, limit=limit)


@router.post("/knowledge/chat")
async def knowledge_chat_api(background_tasks: BackgroundTasks, payload: KnowledgeChatRequest):
    message = _message_with_voice_emotion_context(payload.message, payload.input_mode, payload.voice_emotion)
    if payload.is_stream:
        session_id = payload.session_id or str(uuid.uuid4())
        create_sse_queue(session_id)
        background_tasks.add_task(
            run_unified_anti_fraud_chat_stream,
            message,
            session_id=session_id,
            history=payload.history,
            use_llm=payload.use_llm,
            limit=payload.limit,
        )
        return {"message": "结果正在处理中...", "session_id": session_id}

    return unified_anti_fraud_chat(
        message,
        session_id=payload.session_id,
        history=payload.history,
        use_llm=payload.use_llm,
        limit=payload.limit,
    )


@router.post("/knowledge/image/analyze")
async def knowledge_image_analyze_api(
    file: UploadFile = File(..., description="待识别的聊天截图或可疑图片"),
    session_id: Optional[str] = Form(default=None, description="当前聊天会话 ID，用于前端关联"),
):
    filename = file.filename or "upload-image"
    content_type = (file.content_type or "").lower()
    filename_lower = filename.lower()
    has_allowed_type = content_type in ALLOWED_IMAGE_TYPES
    has_allowed_extension = filename_lower.endswith(ALLOWED_IMAGE_EXTENSIONS)
    if not has_allowed_type and not has_allowed_extension:
        raise HTTPException(status_code=400, detail="仅支持 PNG、JPG/JPEG、WEBP 图片")

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="图片文件为空")
    if len(image_bytes) > MAX_IMAGE_UPLOAD_BYTES:
        max_mb = MAX_IMAGE_UPLOAD_BYTES / 1024 / 1024
        raise HTTPException(status_code=413, detail=f"图片过大，请上传 {max_mb:.0f}MB 以内的图片")

    result = await analyze_image_fraud_risk(
        image_bytes,
        filename=filename,
        content_type=content_type if has_allowed_type else "",
    )
    result["filename"] = filename
    result["content_type"] = content_type or ""
    result["size_bytes"] = len(image_bytes)
    result["session_id"] = session_id or ""
    return result
