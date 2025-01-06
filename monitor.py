import time
from datetime import datetime

import requests
from prometheus_client import push_to_gateway, CollectorRegistry, Counter, Gauge
from requests.auth import HTTPBasicAuth

# 定义全局 Prometheus 指标
registry = CollectorRegistry()
login_attempts_total = Counter(
    'ssh_login_attempts_total',
    'Total number of SSH login attempts',
    ['method', 'result'],
    registry=registry
)
active_connections = Gauge(
    'ssh_active_connections',
    'Current number of active SSH connections',
    registry=registry
)


def push_metrics_to_prometheus(config, logger):
    """定期推送指标到 Prometheus Pushgateway"""
    push_interval = config["monitoring"].get("prometheus_push_interval", 30)
    pushgateway_url = config["monitoring"].get("prometheus_pushgateway")
    job_name = config["monitoring"].get("prometheus_job", "ssh_honeypot")
    auth_config = config["monitoring"].get("prometheus_auth", {})

    if not pushgateway_url:
        logger.warning("Prometheus Pushgateway 地址未配置，跳过推送")
        return

    # 定义 HTTP Basic Auth
    auth = None
    if "username" in auth_config and "password" in auth_config:
        auth = HTTPBasicAuth(auth_config["username"], auth_config["password"])

    while True:
        try:
            # 自定义 handler 支持 Basic Auth
            handler = None
            if auth:
                handler = requests.post

            # 推送指标
            push_to_gateway(pushgateway_url, job=job_name, registry=registry, handler=handler)
            logger.info("成功推送指标到 Prometheus Pushgateway")
        except Exception as e:
            logger.error(f"推送指标到 Prometheus Pushgateway 时出错: {e}")
        finally:
            time.sleep(push_interval)


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
