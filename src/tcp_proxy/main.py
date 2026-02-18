import asyncio
import logging
import struct

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def extract_postgres_username(data: bytes) -> str | None:
    """Parses the Postgres StartupMessage to find the 'user' key.

    Args:
        data: The raw bytes of the Postgres StartupMessage.

    Returns:
        The extracted username string if found, otherwise None.
    """
    try:
        # The first 4 bytes are length, next 4 are protocol version.
        # StartupMessage starts at offset 8.
        offset = 8
        while offset < len(data):
            # Key
            null_idx = data.find(b"\x00", offset)
            if null_idx == -1:
                break
            key = data[offset:null_idx].decode("utf-8")
            offset = null_idx + 1

            # Value
            null_idx = data.find(b"\x00", offset)
            if null_idx == -1:
                break
            value = data[offset:null_idx].decode("utf-8")
            offset = null_idx + 1

            if key == "user":
                return value
    except Exception:
        pass
    return None


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Simple bidirectional pipe that forwards data from reader to writer.

    Args:
        reader: The source asyncio StreamReader.
        writer: The destination asyncio StreamWriter.
    """
    try:
        while not reader.at_eof():
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def handle_postgres_client(
    client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
) -> None:
    """Handles an incoming Postgres client connection.

    Performs the following steps:
    1. Reads the initial packet.
    2. Handles SSL requests by denying them (forcing plaintext).
    3. Extracts the username from the StartupMessage.
    4. Connects to the internal sandbox using the username as the hostname.
    5. Bridges the connection between client and sandbox.

    Args:
        client_reader: The reader for the client connection.
        client_writer: The writer for the client connection.
    """
    try:
        peername = client_writer.get_extra_info("peername")
        logger.info(f"New connection from {peername}")

        # 1. Read the first packet
        initial_data = await client_reader.read(1024)

        # 2. Handle SSL Request (8 bytes: length=8, code=80877103)
        if (
            len(initial_data) >= 8
            and struct.unpack("!I", initial_data[4:8])[0] == 80877103
        ):
            logger.info(f"[{peername}] SSL Request received, denying.")
            # We tell the client "N" (No SSL supported by proxy)
            # so they send the StartupMessage in plain text.
            client_writer.write(b"N")
            await client_writer.drain()
            # Now read the real StartupMessage
            initial_data = await client_reader.read(1024)

        # 3. Extract Sandbox ID (Username)
        sandbox_id = extract_postgres_username(initial_data)
        logger.info(f"[{peername}] Extracted username (sandbox_id): {sandbox_id}")
        if not sandbox_id:
            logger.warning(f"[{peername}] No sandbox_id found, closing connection.")
            client_writer.close()
            return

        # 4. Connect to Internal Sandbox
        target_host = sandbox_id
        try:
            logger.info(f"[{peername}] Connecting to target {target_host}:5433...")
            remote_reader, remote_writer = await asyncio.open_connection(
                target_host, 5432
            )
            logger.info(f"[{peername}] Connected to target {target_host}:5433")
        except Exception as e:
            logger.error(f"[{peername}] Failed to connect to {target_host}: {e}")
            client_writer.close()
            return

        # 5. Forward the StartupMessage to the actual database
        remote_writer.write(initial_data)
        await remote_writer.drain()

        # 6. Bridge the connection
        await asyncio.gather(
            pipe(client_reader, remote_writer), pipe(remote_reader, client_writer)
        )
    except Exception as e:
        logger.error(f"Proxy Error: {e}")
    finally:
        logger.info(f"Connection closed")
        client_writer.close()


def parse_resp_array(data: bytes) -> list[bytes] | None:
    """Parses a single RESP array from raw bytes.

    Handles the *N\\r\\n$len\\r\\nvalue\\r\\n... format used by Redis clients.

    Returns:
        A list of byte-string elements, or None if parsing fails.
    """
    try:
        if not data or data[0:1] != b"*":
            return None
        crlf = data.find(b"\r\n")
        if crlf == -1:
            return None
        count = int(data[1:crlf])
        offset = crlf + 2
        elements: list[bytes] = []
        for _ in range(count):
            if offset >= len(data) or data[offset : offset + 1] != b"$":
                return None
            crlf = data.find(b"\r\n", offset)
            if crlf == -1:
                return None
            length = int(data[offset + 1 : crlf])
            offset = crlf + 2
            elements.append(data[offset : offset + length])
            offset += length + 2  # skip value + \r\n
        return elements
    except Exception:
        return None


def extract_redis_username(data: bytes) -> str | None:
    """Extracts the username from a Redis AUTH command.

    Expects RESP: *3\\r\\n$4\\r\\nAUTH\\r\\n$<len>\\r\\n<username>\\r\\n$<len>\\r\\n<password>\\r\\n

    Returns:
        The username string if a valid AUTH <user> <pass> command is found, otherwise None.
    """
    parts = parse_resp_array(data)
    if not parts:
        return None
    if len(parts) >= 3 and parts[0].upper() == b"AUTH":
        return parts[1].decode("utf-8")
    return None


async def handle_redis_client(
    client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
) -> None:
    """Handles an incoming Redis client connection.

    1. Reads the initial data (expected to be an AUTH command).
    2. Extracts the username (sandbox_id) from the AUTH command.
    3. Connects to the internal sandbox Redis on port 6379.
    4. Forwards the AUTH command and bridges the connection.
    """
    try:
        peername = client_writer.get_extra_info("peername")
        logger.info(f"[Redis] New connection from {peername}")

        initial_data = await client_reader.read(4096)
        if not initial_data:
            logger.warning(f"[Redis][{peername}] No data received, closing.")
            client_writer.close()
            return

        sandbox_id = extract_redis_username(initial_data)
        logger.info(
            f"[Redis][{peername}] Extracted username (sandbox_id): {sandbox_id}"
        )
        if not sandbox_id:
            logger.warning(
                f"[Redis][{peername}] No sandbox_id found, closing connection."
            )
            client_writer.write(b"-ERR no username provided in AUTH\r\n")
            await client_writer.drain()
            client_writer.close()
            return

        target_host = sandbox_id
        try:
            logger.info(
                f"[Redis][{peername}] Connecting to target {target_host}:6379..."
            )
            remote_reader, remote_writer = await asyncio.open_connection(
                target_host, 6379
            )
            logger.info(f"[Redis][{peername}] Connected to target {target_host}:6379")
        except Exception as e:
            logger.error(f"[Redis][{peername}] Failed to connect to {target_host}: {e}")
            client_writer.write(b"-ERR could not connect to backend\r\n")
            await client_writer.drain()
            client_writer.close()
            return

        remote_writer.write(initial_data)
        await remote_writer.drain()

        await asyncio.gather(
            pipe(client_reader, remote_writer), pipe(remote_reader, client_writer)
        )
    except Exception as e:
        logger.error(f"[Redis] Proxy Error: {e}")
    finally:
        logger.info(f"[Redis] Connection closed")
        client_writer.close()


async def main() -> None:
    """Starts the Postgres and Redis proxy servers."""
    postgres_server = await asyncio.start_server(
        handle_postgres_client, "0.0.0.0", 5432
    )
    redis_server = await asyncio.start_server(handle_redis_client, "0.0.0.0", 6379)

    logger.info("Postgres Proxy listening on 5432...")
    logger.info("Redis Proxy listening on 6379...")

    async with postgres_server, redis_server:
        await asyncio.gather(
            postgres_server.serve_forever(),
            redis_server.serve_forever(),
        )


if __name__ == "__main__":
    asyncio.run(main())
