import os
import socket
import threading
from datetime import datetime

import paramiko
import pytz
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CONFIG_FILE = "config.yaml"


def load_config():
    """加载 YAML 格式配置文件"""
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"配置文件 {CONFIG_FILE} 不存在！")
    with open(CONFIG_FILE, "r") as f:
        return yaml.safe_load(f)


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


def log_attempt(config, addr, username, method, details):
    """记录登录尝试信息"""
    timestamp = get_current_time_in_timezone(config["honeypot"].get("timezone", "UTC"))
    log_entry = config["honeypot"]["log_format"].format(
        timestamp=timestamp,
        ip=addr[0],
        port=addr[1],
        username=username,
        method=method,
        details=details,
    )
    # 写入日志文件
    with open(config["honeypot"]["log_file"], "a") as f:
        f.write(log_entry + "\n")
    # 调试模式下输出到控制台
    if config["honeypot"].get("debug", False):
        print(f"DEBUG: {log_entry}")


def get_current_time_in_timezone(timezone='UTC'):
    """获取当前时间并根据时区调整"""
    tz = pytz.timezone(timezone)
    now = datetime.now(tz)
    return now.strftime('%Y-%m-%d %H:%M:%S')


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
        log_attempt(self.config, self.addr, username, "password", password)
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
            f"publickey ({key_type})",
            key_data,
        )
        return paramiko.AUTH_FAILED

    def exceeds_max_attempts(self):
        """检查是否超过最大尝试次数"""
        max_attempts = self.config["honeypot"].get("max_attempts", 0)
        if max_attempts > 0 and self.attempts >= max_attempts:
            print(f"超过最大登录尝试次数，断开连接：{self.addr}")
            return True
        return False

    def get_allowed_auths(self, username):
        # 允许的认证方式
        return "password,publickey"


def start_honeypot(config):
    """启动 SSH 蜜罐"""
    host_keys = initialize_host_keys(config["keys"])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((config["honeypot"]["host"], config["honeypot"]["port"]))
    server.listen(100)
    print(f"SSH 蜜罐运行中，监听 {config['honeypot']['host']}:{config['honeypot']['port']}")

    while True:
        client, addr = server.accept()
        print(f"收到连接：{addr}")
        try:
            transport = paramiko.Transport(client)
            for key_type, key in host_keys.items():
                transport.add_server_key(key)
            ssh_server = SSHServer(config, addr)
            transport.start_server(server=ssh_server)

            # 等待客户端打开一个通道
            channel = transport.accept(20)
            if channel is not None:
                print(f"客户端已打开通道：{addr}")
                channel.close()
        except Exception as e:
            print(f"处理连接时出错：{e}")
        finally:
            client.close()


if __name__ == "__main__":
    try:
        config = load_config()
        start_honeypot(config)
    except KeyboardInterrupt:
        print("蜜罐已停止")
    except Exception as e:
        print(f"错误：{e}")
