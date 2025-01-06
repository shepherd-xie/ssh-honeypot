import logging

from logging_loki import LokiHandler

# 设置格式化器
formatter = logging.Formatter(
    fmt="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def setup_loki_handler(config):
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

    loki_handler.setFormatter(formatter)
    return loki_handler


def setup_logging(config):
    """设置 Loki 日志记录器"""
    log_level = config["honeypot"].get("log_level", "INFO").upper()

    # 创建日志记录器
    logger = logging.getLogger("SSH_Honeypot")
    logger.setLevel(log_level)

    # 控制台日志
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 添加 LokiHandler
    logger.addHandler(setup_loki_handler(config))

    return logger
