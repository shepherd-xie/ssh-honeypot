from datetime import datetime

import requests
from requests.auth import HTTPBasicAuth

import logging
from logging_loki import LokiHandler


def setup_logging_with_loki(config):
    """设置 Loki 日志记录器"""
    log_level = config["honeypot"].get("log_level", "INFO").upper()
    loki_url = config["monitoring"].get("loki_endpoint")
    loki_labels = config["monitoring"].get("loki_labels", {"job": "ssh_honeypot"})

    if not loki_url:
        raise ValueError("Loki 推送地址未配置！")

    # 配置 LokiHandler
    loki_handler = LokiHandler(
        url=loki_url,
        tags=loki_labels,
        auth=(
            config["monitoring"].get("loki_auth", {}).get("username"),
            config["monitoring"].get("loki_auth", {}).get("password"),
        ),
        version="1",
    )

    # 设置格式化器
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    loki_handler.setFormatter(formatter)

    # 创建日志记录器
    logger = logging.getLogger("SSH_Honeypot")
    logger.setLevel(log_level)

    # 控制台日志
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 添加 LokiHandler
    logger.addHandler(loki_handler)

    return logger


class LogMetric:
    """日志指标数据对象"""

    def __init__(self, timestamp: datetime, ip, port, username, method, password, key_type, key_data):
        self.timestamp = timestamp
        self.ip = ip
        self.port = port
        self.username = username
        self.method = method
        self.password = password
        self.key_type = key_type
        self.key_data = key_data

    def to_prometheus(self):
        """转为 Prometheus 格式的指标"""
        labels = f'ip="{self.ip}",method="{self.method}",username="{self.username}"'
        return f'ssh_login_attempts{{{labels}}} 1\n'

    def to_log_line(self):
        """格式化为日志行"""
        return (f"{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - "
                f"{self.ip}[:{self.port}] Username: {self.username}, "
                f"Method: {self.method}, Password: {self.password}, KeyType: {self.key_type}, KeyData: {self.key_data}")

    def to_json(self):
        return


def push_to_prometheus(config, log_metric, logger):
    """推送指标到 Prometheus Pushgateway"""
    if not config["monitoring"].get("enable", False):
        logger.debug("监控未启用，跳过 Prometheus 推送")
        return

    prometheus_url = config["monitoring"].get("prometheus_pushgateway")
    if not prometheus_url:
        logger.warning("Prometheus Pushgateway 地址未配置，跳过推送")
        return

    metric_data = f"# HELP ssh_login_attempts Total login attempts\n"
    metric_data += f"# TYPE ssh_login_attempts counter\n"
    metric_data += log_metric.to_prometheus()

    try:
        response = requests.post(prometheus_url, data=metric_data)
        response.raise_for_status()
        logger.info("推送到 Prometheus 成功")
    except requests.RequestException as e:
        logger.error(f"推送到 Prometheus 失败: {e}")

