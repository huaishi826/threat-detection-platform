@echo off
echo ====================================
echo ThreatSight 启动脚本
echo ====================================
echo.
echo [1/3] 激活虚拟环境...
call .\venv\Scripts\activate.bat
echo [2/3] 检查依赖...
pip install -r requirements.txt >nul 2>&1
echo [3/3] 启动后端服务...
echo.
echo 演示模式已开启，访问以下地址：
echo   仪表盘: http://localhost:5173
echo   API文档: http://localhost:5000/apidocs
echo   健康检查: http://localhost:5000/api/health
echo.
set DEMO_MODE=true
start python app.py
timeout /t 3 >nul
echo 启动前端开发服务器...
cd frontend
start npm run dev
cd ..
timeout /t 5 >nul
start http://localhost:5173
echo.
echo 启动完成！关闭窗口可退出...
pause >nul