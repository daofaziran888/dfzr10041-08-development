"""业务路由汇总：所有模块共用一套资源路由，由领域服务完成分派。"""
from __future__ import annotations

from app.routers import dedup, resource

# dedup 调查路由含 /api/dedup/* 固定路径，必须先于通用 /api/{module} 注册，
# 否则 hits/groups 等入口会被动态路径抢先匹配。
ROUTERS = [dedup, resource]
