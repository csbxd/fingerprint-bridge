import copy
import unittest
import hpack
from lab import PREFACE, frame
from paired_http import compare


class PairedHttpTests(unittest.TestCase):
    def wire(self, authority, reverse=False, huffman=True):
        encoder = hpack.Encoder()
        wire = PREFACE + frame(4, 0, 0, b'')
        for stream in (1, 3):
            headers = [(b':method', b'GET'), (b':scheme', b'https'), (b':path', b'/'),
                       (b':authority', authority), (b'x-one', b'1'), (b'x-two', b'2')]
            if reverse:
                headers[-2:] = reversed(headers[-2:])
            wire += frame(1, 5, stream, encoder.encode(headers, huffman=huffman))
        return wire

    def document(self, right=None):
        return {'protocol': 'h2', 'inbound': {'bytes': list(self.wire(b'b.test:4444')), 'truncated': False},
                'outbound': {'bytes': list(right or self.wire(b'a.test:44333')), 'truncated': False}}

    def test_mapped_lengths_and_hpack_dynamic_reuse(self):
        self.assertTrue(compare(self.document(), 'b.test:4444', 'a.test:44333')['pass'])

    def test_changed_header_order_is_not_exempt(self):
        self.assertFalse(compare(self.document(self.wire(b'a.test:44333', reverse=True)), 'b.test:4444', 'a.test:44333')['pass'])

    def test_changed_huffman_representation_is_not_exempt(self):
        self.assertFalse(compare(self.document(self.wire(b'a.test:44333', huffman=False)), 'b.test:4444', 'a.test:44333')['pass'])

    def test_truncated_capture_is_not_a_pass(self):
        doc = self.document(); doc['inbound']['truncated'] = True
        with self.assertRaisesRegex(AssertionError, 'truncated'):
            compare(doc, 'b.test:4444', 'a.test:44333')

    def test_unmapped_value_change_fails(self):
        changed = self.wire(b'other.test:44333')
        self.assertFalse(compare(self.document(changed), 'b.test:4444', 'a.test:44333')['pass'])


if __name__ == '__main__':
    unittest.main()
