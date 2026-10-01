import unittest

from channel_exec import CommandOutputTooLarge, CommandTimeout, run_command_channel


class FakeChannel:
    def __init__(self, out=b"", err=b"", ready_after=0):
        self.out = bytearray(out)
        self.err = bytearray(err)
        self.ready_after = ready_after
        self.polls = 0
        self.closed = False

    def recv_ready(self):
        return bool(self.out)

    def recv(self, n):
        chunk = bytes(self.out[:n])
        del self.out[:n]
        return chunk

    def recv_stderr_ready(self):
        return bool(self.err)

    def recv_stderr(self, n):
        chunk = bytes(self.err[:n])
        del self.err[:n]
        return chunk

    def exit_status_ready(self):
        self.polls += 1
        return not self.out and not self.err and self.polls > self.ready_after

    def recv_exit_status(self):
        return 7

    def close(self):
        self.closed = True


class FakeStream:
    def __init__(self, channel):
        self.channel = channel


class FakeClient:
    def __init__(self, channel=None, exc=None):
        self.channel = channel
        self.exc = exc

    def exec_command(self, command, timeout=None):
        if self.exc:
            raise self.exc
        stream = FakeStream(self.channel)
        return None, stream, stream


class ChannelExecTests(unittest.TestCase):
    def test_collects_stdout_and_stderr(self):
        ch = FakeChannel(b"hello", b"warn")
        code, out, err = run_command_channel(FakeClient(ch), "x", 1, 1, 100)
        self.assertEqual((code, out, err), (7, b"hello", b"warn"))

    def test_open_timeout_is_normalized(self):
        with self.assertRaises(CommandTimeout):
            run_command_channel(FakeClient(exc=RuntimeError("Timeout opening channel.")), "x", 1, 1, 100)

    def test_command_deadline_closes_channel(self):
        ch = FakeChannel(ready_after=10000)
        with self.assertRaises(CommandTimeout):
            run_command_channel(FakeClient(ch), "x", 0.01, 1, 100)
        self.assertTrue(ch.closed)

    def test_output_limit_closes_channel(self):
        ch = FakeChannel(b"x" * 101)
        with self.assertRaises(CommandOutputTooLarge):
            run_command_channel(FakeClient(ch), "x", 1, 1, 100)
        self.assertTrue(ch.closed)


if __name__ == "__main__":
    unittest.main()
