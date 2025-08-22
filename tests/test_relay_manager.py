"""Forked from https://github.com/jeffthibault/python-nostr.git."""

import ssl
import unittest
from unittest.mock import patch

from tornado import gen
from tornado.httpclient import HTTPRequest

from pynostr.event import Event
from pynostr.filters import FiltersList
from pynostr.key import PrivateKey
from pynostr.relay_manager import RelayException, RelayManager
from pynostr.subscription import Subscription


class TestPrivateKey(unittest.TestCase):
    def test_only_relay_valid_events(self):
        """publish_event raise a RelayException if an Event fails verification."""
        pk = PrivateKey()
        event = Event(
            pubkey=pk.public_key.hex(),
            content="Hello, world!",
        )

        relay_manager = RelayManager()

        # Deliberately forget to sign the Event
        with self.assertRaisesRegex(RelayException, "must be signed"):
            relay_manager.publish_event(event)

        # Attempt to relay with a nonsense signature
        event.sig = (b"\00" * 64).hex()
        with self.assertRaisesRegex(RelayException, "failed to verify"):
            relay_manager.publish_event(event)

        # Properly signed Event can be relayed
        event.sign(pk.hex())
        relay_manager.publish_event(event)

    def test_separate_subscriptions(self):
        """make sure that subscription dictionary default is not the same object across
        all relays so that subscriptions can vary."""
        # initiate relay manager with two relays
        relay_manager = RelayManager(error_threshold=1)
        relay_manager.add_relay(url="ws://fake-relay1")
        relay_manager.add_relay(url="ws://fake-relay2")

        # make test subscription and add to one relay
        test_subscription = Subscription("test", FiltersList())
        relay_manager.relays["ws://fake-relay1"].subscriptions.update(
            {test_subscription.id: test_subscription}
        )
        # make sure test subscription isn't in second relay subscriptions
        self.assertTrue(
            test_subscription.id
            not in relay_manager.relays["ws://fake-relay2"].subscriptions.keys()
        )
        relay_manager.close_all_relay_connections()


class TestRelayManagerSSLContext(unittest.TestCase):
    def test_add_relay_ssl_context(self):
        ctx = ssl.create_default_context()
        relay_manager = RelayManager()
        relay_manager.add_relay(url="ws://fake-relay", ssl_context=ctx)
        self.assertIs(relay_manager.relays["ws://fake-relay"].ssl_options, ctx)
        relay_manager.close_all_relay_connections()

    def test_websocket_connect_receives_ssl_context(self):
        ctx = ssl.create_default_context()
        relay_manager = RelayManager()
        relay_manager.add_relay(url="ws://fake-relay", ssl_context=ctx)
        relay = relay_manager.relays["ws://fake-relay"]

        captured = {}

        @gen.coroutine
        def fake_websocket_connect(request, *args, **kwargs):
            captured["request"] = request

            class DummyWS:
                protocol = object()

                def write_message(self, message):
                    pass

                @gen.coroutine
                def read_message(self):
                    return None

                @gen.coroutine
                def close(self):
                    pass

            raise gen.Return(DummyWS())

        with patch("pynostr.relay.websocket_connect", fake_websocket_connect):
            relay.io_loop.run_sync(relay.connect)

        self.assertIsInstance(captured["request"], HTTPRequest)
        self.assertIs(captured["request"].ssl_options, ctx)
