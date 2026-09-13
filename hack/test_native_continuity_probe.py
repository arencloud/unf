import unittest
from unittest.mock import MagicMock, patch

from native_continuity_probe import observe, validate_targets


class ContinuityProbeTest(unittest.TestCase):
    target = {"label": "local/Pod/ipv4", "address": "192.0.2.1", "port": 8080}

    def response(self, chunks):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = chunks
        with patch("native_continuity_probe.socket.create_connection", return_value=connection) as create:
            record = observe(self.target)
        create.assert_called_once_with(("192.0.2.1", 8080), timeout=0.5)
        return record

    def test_http_success_and_fragmented_status(self):
        self.assertTrue(self.response([b"HTTP/1.0 200 OK\r\n"])['ok'])
        self.assertTrue(self.response([b"HTTP/1.1 ", b"200 OK\r\n"])['ok'])

    def test_wrong_status_empty_and_truncated_are_failures(self):
        for chunks in ([b"HTTP/1.0 503 Busy\r\n"], [b""], [b"HTTP/1.0 200", b""], [b"not-http\r\n"]):
            self.assertFalse(self.response(chunks)['ok'])

    def test_network_failure_is_a_sample_and_never_retried(self):
        with patch("native_continuity_probe.socket.create_connection", side_effect=TimeoutError) as create:
            record = observe(self.target)
        self.assertEqual(create.call_count, 1)
        self.assertFalse(record['ok'])
        self.assertEqual(record['outcome'], "TimeoutError")

    def test_internal_error_is_not_a_transport_observation(self):
        with patch("native_continuity_probe.socket.create_connection", side_effect=ValueError):
            with self.assertRaises(ValueError):
                observe(self.target)

    def test_fixture_target_validation(self):
        targets = [dict(self.target, label=str(i)) for i in range(8)]
        self.assertEqual(validate_targets(targets), targets)
        for invalid in ([], targets[:7], [self.target] * 8,
                        [dict(target, port=True) for target in targets],
                        [dict(target, address="invalid") for target in targets]):
            with self.assertRaises(ValueError):
                validate_targets(invalid)


if __name__ == "__main__":
    unittest.main()
