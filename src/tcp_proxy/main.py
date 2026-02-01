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


async def main() -> None:
    """Starts the Postgres proxy server."""
    postgres_server = await asyncio.start_server(
        handle_postgres_client, "0.0.0.0", 5432
    )

    logger.info("Postgres Proxy listening on 5432...")

    async with postgres_server:
        await postgres_server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
