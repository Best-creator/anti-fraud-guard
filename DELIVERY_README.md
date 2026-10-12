# 反诈项目交付包使用说明

这个交付包包含项目源码、依赖锁定清单、数据库快照恢复脚本和启动脚本。

## 交付内容

- `app/`：项目代码
- `data/`：知识库、举报研判库等数据文件
- `scripts/`：Docker、数据库恢复、启动脚本
- `database_snapshot/`：MongoDB 与 Milvus 当前数据快照
- `requirements.txt`：当前环境完整依赖版本
- `.env.example`：环境变量模板，不含真实密钥
- `docker-compose.yml`：MongoDB 与 Milvus 本地服务

模型不随交付包一起压缩。BGE-M3 约 4.27GB，请按 `MODEL_DOWNLOADS.md` 或 `ENVIRONMENT_REQUIREMENTS.md` 中的地址另行下载。

## 第一次运行

1. 安装 Docker Desktop，并启动 Docker。

2. 启动 MongoDB 和 Milvus：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/docker-up.ps1
```

3. 创建 Python 环境并安装依赖：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-delivery.ps1
```

4. 打开 `.env`，填入自己的 `OPENAI_API_KEY`。

5. 下载 BGE-M3 模型到 `.env` 里的 `BGE_M3_PATH`。

如果暂时不下载模型，可以先把 `.env` 里的 `ANTI_FRAUD_EMBEDDING_BACKEND` 改为 `hash`。

6. 恢复数据库快照：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/restore-delivery-data.ps1
```

7. 启动页面服务：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start-delivery-services.ps1
```

访问：

- 导入页面：http://127.0.0.1:8000/import.html
- 聊天页面：http://127.0.0.1:8001/chat.html
- 管理后台：http://127.0.0.1:8001/admin/review.html

测试后台账号：

```text
账号：123456
密码：123456
```

## 注意

- `.env.example` 不包含真实 API Key；必须自行填写。
- `database_snapshot/` 是当前库的快照，恢复时默认会覆盖同名 MongoDB/Milvus 集合。
- 当前必需本地模型是 `BAAI/bge-m3`，但模型文件不包含在交付包里。
- `deepseek-chat` 走 API，不需要下载本地大模型。
- 如果暂时没有 BGE-M3，可在 `.env` 设置 `ANTI_FRAUD_EMBEDDING_BACKEND=hash`，但检索效果会弱一些。
