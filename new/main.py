import asyncio
import logging
import yaml
from datetime import datetime
from maxminddb import open_database
from sqlalchemy import create_engine, Column, String, Integer, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from prometheus_client import Counter, Histogram, Gauge, start_http_server
from functools import lru_cache

# Configurations
CONFIG_FILE = "config.yaml"

# Database setup
Base = declarative_base()


class ConnectionLog(Base):
    __tablename__ = 'connection_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip = Column(String(45))
    port = Column(Integer)
    auth_type = Column(String(50))
    username = Column(String(100))
    password = Column(String(100))
    public_key = Column(JSON)
    geo_info = Column(JSON)


# Prometheus metrics
connection_counter = Counter('honeypot_connections_total', 'Total SSH connection attempts')
geo_counter = Counter('honeypot_geo_attempts', 'SSH attempts by geographical region', ['country'])
auth_attempt_counter = Counter('honeypot_auth_attempts', 'SSH authentication attempts', ['username', 'password'])
attempt_duration = Histogram('honeypot_connection_duration_seconds', 'Time taken for connection attempts')
active_connections = Gauge('honeypot_active_connections', 'Current active SSH connections')

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SSH-Honeypot")

# MaxMind database
GEO_DB_PATH = "GeoLite2-City.mmdb"


@lru_cache(maxsize=1000)
def get_geo_info(ip):
    try:
        with open_database(GEO_DB_PATH) as reader:
            geo_data = reader.get(ip)
            if geo_data:
                return {
                    "country": geo_data.get('country', {}).get('names', {}).get('en', 'Unknown'),
                    "city": geo_data.get('city', {}).get('names', {}).get('en', 'Unknown'),
                    "latitude": geo_data.get('location', {}).get('latitude'),
                    "longitude": geo_data.get('location', {}).get('longitude')
                }
    except Exception as e:
        logger.error(f"Error fetching geo info: {e}")
    return {"country": "Unknown"}


async def handle_client(reader, writer):
    start_time = datetime.utcnow()
    peername = writer.get_extra_info('peername')
    ip, port = peername

    active_connections.inc()
    logger.info(f"Connection from {ip}:{port}")
    connection_counter.inc()

    # Fake SSH server dialog
    try:
        writer.write(b"SSH-2.0-OpenSSH_8.0\n")
        await writer.drain()
        client_data = await reader.readline()
        logger.info(f"Client banner: {client_data.strip().decode('utf-8')}")

        # Simulate authentication prompt
        writer.write(b"Password: ")
        await writer.drain()
        auth_data = await reader.readline()
        username, password = "unknown", auth_data.strip().decode('utf-8')

        geo_info = get_geo_info(ip)
        geo_counter.labels(country=geo_info['country']).inc()
        auth_attempt_counter.labels(username=username, password=password).inc()

        # Log to database
        session = Session()
        connection_log = ConnectionLog(
            ip=ip,
            port=port,
            auth_type="password",
            username=username,
            password=password,
            geo_info=geo_info
        )
        session.add(connection_log)
        session.commit()
        session.close()
    except Exception as e:
        logger.error(f"Error handling client {ip}:{port}: {e}")
    finally:
        duration = (datetime.utcnow() - start_time).total_seconds()
        attempt_duration.observe(duration)
        active_connections.dec()
        writer.close()
        await writer.wait_closed()


async def main():
    # Load configuration
    with open(CONFIG_FILE, 'r') as file:
        config = yaml.safe_load(file)

    # Database engine
    engine = create_engine(config['database']['url'])
    Base.metadata.create_all(engine)
    global Session
    Session = sessionmaker(bind=engine)

    # Start Prometheus metrics server
    start_http_server(config['prometheus']['port'])

    # Start SSH honeypot
    server = await asyncio.start_server(handle_client, config['server']['host'], config['server']['port'])
    logger.info(f"SSH honeypot running on {config['server']['host']}:{config['server']['port']}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
