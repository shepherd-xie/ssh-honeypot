import concurrent.futures
import os
import socket
import threading
from datetime import datetime

import paramiko
import pytz
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import monitor
import log

CONFIG_FILE = "config.yaml"


def load_config():
    """加载 YAML 格式配置文件"""
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"配置文件 {CONFIG_FILE} 不存在！")
    with open(CONFIG_FILE, "r") as f:
        return yaml.safe_load(f)


_config = load_config()
logger = log.setup_logging(_config)


def generate_ed25519_key(file_path):
    """生成 Ed25519 密钥并保存到文件"""
    """https://github.com/paramiko/paramiko/issues/1136#issuecomment-1160771520"""
    private_key = Ed25519PrivateKey.generate()
    with open(file_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"生成新的 Ed25519 密钥，并保存到 {file_path}")


def initialize_host_keys(keys_config):
    """加载或生成所有类型的主机密钥"""
    host_keys = {}

    for key_type, key_file in keys_config.items():
        if not os.path.exists(key_file):
            if key_type == "rsa":
                host_key = paramiko.RSAKey.generate(2048)
            elif key_type == "ecdsa":
                host_key = paramiko.ECDSAKey.generate(bits=256)
            elif key_type == "ed25519":
                generate_ed25519_key(key_file)
                continue
            else:
                raise ValueError(f"不支持的密钥类型：{key_type}")

            host_key.write_private_key_file(key_file)
            print(f"生成新的 {key_type.upper()} 密钥，并保存到 {key_file}")
        else:
            print(f"加载现有 {key_type.upper()} 密钥：{key_file}")
            if key_type == "rsa":
                host_key = paramiko.RSAKey(filename=key_file)
            elif key_type == "ecdsa":
                host_key = paramiko.ECDSAKey(filename=key_file)
            elif key_type == "ed25519":
                host_key = paramiko.Ed25519Key(filename=key_file)

        if key_type != "ed25519":  # Ed25519 手动生成，无需加载到 paramiko
            host_keys[key_type] = host_key

    return host_keys


def log_attempt(config, addr, username, method, password, key_type, key_data):
    """记录登录尝试信息"""
    timestamp = get_current_time_in_timezone(config["honeypot"].get("timezone", "UTC"))
    log_metric = monitor.LogMetric(
        timestamp=timestamp,
        ip=addr[0],
        port=addr[1],
        username=username,
        method=method,
        password=password,
        key_type=key_type,
        key_data=key_data,
    )
    # 写入日志文件
    with open(config["honeypot"]["log_file"], "a") as f:
        f.write(log_metric.to_log_line() + "\n")
    # 调试模式下输出到控制台
    if config["honeypot"].get("debug", False):
        logger.info(f"{log_metric.to_log_line()}")

    # 更新 Prometheus 指标
    monitor.login_attempts_total.labels(method=method, result=log_metric.ip).inc()


def get_current_time_in_timezone(timezone='UTC'):
    """获取当前时间并根据时区调整"""
    tz = pytz.timezone(timezone)
    return datetime.now(tz)


class SSHServer(paramiko.ServerInterface):
    """自定义 SSH 服务器"""

    def __init__(self, config, addr):
        self.config = config
        self.addr = addr  # 连接的客户端地址
        self.event = threading.Event()
        self.attempts = 0  # 登录尝试次数

    def check_auth_password(self, username, password):
        self.attempts += 1
        if self.exceeds_max_attempts():
            return paramiko.AUTH_FAILED
        # 记录使用密码登录的尝试
        log_attempt(self.config, self.addr, username, "password", password, "", "")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.attempts += 1
        if self.exceeds_max_attempts():
            return paramiko.AUTH_FAILED
        # 记录使用公钥登录的尝试
        key_type = key.get_name()  # 获取公钥类型
        key_data = key.get_base64()  # 获取公钥数据
        log_attempt(
            self.config,
            self.addr,
            username,
            "publickey",
            "",
            key_type,
            key_data,
        )
        return paramiko.AUTH_FAILED

    def exceeds_max_attempts(self):
        """检查是否超过最大尝试次数"""
        max_attempts = self.config["honeypot"].get("max_attempts", 0)
        if max_attempts > 0 and self.attempts >= max_attempts:
            logger.waring(f"超过最大登录尝试次数，断开连接：{self.addr}")
            return True
        return False

    def get_allowed_auths(self, username):
        # 允许的认证方式
        return "password,publickey"


def handle_client(client, addr, config, host_keys):
    """处理单个客户端连接"""
    logger.info(f"收到连接：{addr}")
    try:
        transport = paramiko.Transport(client)
        for key_type, key in host_keys.items():
            transport.add_server_key(key)
        ssh_server = SSHServer(config, addr)
        transport.start_server(server=ssh_server)

        # 等待客户端打开一个通道
        channel = transport.accept(20)
        if channel is not None:
            logger.info(f"客户端已打开通道：{addr}")
            channel.close()
    except Exception as e:
        logger.error(f"处理连接时出错：{e}")
    finally:
        client.close()


def start_honeypot(config):
    """启动 SSH 蜜罐"""
    host_keys = initialize_host_keys(config["keys"])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((config["honeypot"]["host"], config["honeypot"]["port"]))
    server.listen(100)
    logger.info(f"SSH 蜜罐运行中，监听 {config['honeypot']['host']}:{config['honeypot']['port']}")

    # 启动 Prometheus 推送线程
    prometheus_thread = threading.Thread(
        target=monitor.push_metrics_to_prometheus, args=(config, logger), daemon=True
    )
    prometheus_thread.start()

    with concurrent.futures.ThreadPoolExecutor(max_workers=config["honeypot"].get("max_threads", 20)) as executor:
        while True:
            client, addr = server.accept()
            # 提交任务到线程池
            executor.submit(handle_client, client, addr, config, host_keys)


if __name__ == "__main__":
    try:
        logger.info("SSH 蜜罐启动中...")
        start_honeypot(_config)
    except KeyboardInterrupt:
        logger.info("蜜罐已停止")
    except Exception as e:
        logger.exception(f"发生错误：{e}")
