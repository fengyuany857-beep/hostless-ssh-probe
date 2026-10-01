from __future__ import annotations

import socket
import time


class CommandTimeout(TimeoutError):
    pass


class CommandOutputTooLarge(RuntimeError):
    pass


def _is_open_timeout(exc: BaseException) -> bool:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return True
    message = str(exc).lower()
    return "timeout opening channel" in message or "timed out" in message


def run_command_channel(client, command: str, command_timeout_s: float, open_timeout_s: float, max_output_bytes: int):
    try:
        _, stdout, stderr = client.exec_command(command, timeout=open_timeout_s)
    except Exception as exc:
        if _is_open_timeout(exc):
            raise CommandTimeout("opening command channel timed out") from exc
        raise

    channel = stdout.channel
    deadline = time.monotonic() + command_timeout_s
    out = bytearray()
    err = bytearray()

    while True:
        progressed = False

        while channel.recv_ready():
            out.extend(channel.recv(65536))
            progressed = True
            if len(out) > max_output_bytes:
                channel.close()
                raise CommandOutputTooLarge("stdout exceeded limit")

        while channel.recv_stderr_ready():
            err.extend(channel.recv_stderr(65536))
            progressed = True
            if len(err) > max_output_bytes:
                channel.close()
                raise CommandOutputTooLarge("stderr exceeded limit")

        if channel.exit_status_ready():
            while channel.recv_ready():
                out.extend(channel.recv(65536))
                if len(out) > max_output_bytes:
                    channel.close()
                    raise CommandOutputTooLarge("stdout exceeded limit")
            while channel.recv_stderr_ready():
                err.extend(channel.recv_stderr(65536))
                if len(err) > max_output_bytes:
                    channel.close()
                    raise CommandOutputTooLarge("stderr exceeded limit")
            return channel.recv_exit_status(), bytes(out), bytes(err)

        if time.monotonic() >= deadline:
            channel.close()
            raise CommandTimeout("command execution timed out")

        if not progressed:
            time.sleep(0.01)
