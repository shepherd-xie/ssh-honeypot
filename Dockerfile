# 使用 Python 官方基础镜像
FROM python:3.10-slim

# 设置工作目录
WORKDIR /app

# 复制当前目录到容器中
COPY . .

# 安装所需的 Python 库
RUN pip install --no-cache-dir paramiko cryptography pytz pyyaml

# 暴露默认 SSH 端口
EXPOSE 2222

# 设置入口点，运行蜜罐脚本
CMD ["python", "ssh_honeypot.py"]
