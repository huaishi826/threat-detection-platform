#!/bin/bash
echo "================================="
echo " ThreatSight 启动脚本"
echo "================================="
echo ""
echo "[1/3] 激活虚拟环境..."
source venv/bin/activate
echo "[2/3] 检查依赖..."
pip install -r requirements.txt > /dev/null 2>&1
echo "[3/3] 启动后端服务..."
echo ""
echo "演示模式已开启，访问以下地址："
echo "  仪表盘: http://localhost:5173"
echo "  API文档: http://localhost:5000/apidocs"
echo "  健康检查: http://localhost:5000/api/health"
echo ""
DEMO_MODE=true python app.py &
BACKEND_PID=$!
sleep 3
echo "启动前端开发服务器..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..
sleep 5
if [[ "$OSTYPE" == "darwin"* ]]; then
    open http://localhost:5173
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open http://localhost:5173
fi
echo ""
echo "启动完成！按 Ctrl+C 停止所有服务"
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
