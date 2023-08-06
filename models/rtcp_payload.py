# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class RtcpPayload(KaitaiStruct):
    """RTCP is the Real-Time Control Protocol.
    
    .. seealso::
       Source - https://www.rfc-editor.org/rfc/rfc3550
    """

    class PacketType(Enum):
        fir = 192
        nack = 193
        ij = 195
        sr = 200
        rr = 201
        sdes = 202
        bye = 203
        app = 204
        rtpfb = 205
        psfb = 206
        xr = 207
        avb = 208
        rsi = 209

    class SdesItemType(Enum):
        end = 0
        cname = 1
        name = 2
        email = 3
        phone = 4
        loc = 5
        tool = 6
        note = 7
        priv = 8

    class PsfbSubtype(Enum):
        pli = 1
        sli = 2
        rpsi = 3
        fir = 4
        tstr = 5
        tstn = 6
        vbcm = 7
        afb = 15

    class RtpfbSubtype(Enum):
        nack = 1
        tmmbr = 3
        tmmbn = 4
        rrr = 5
        transport_feedback = 15
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.rtcp_packets = []
        i = 0
        while not self._io.is_eof():
            self.rtcp_packets.append(RtcpPayload.RtcpPacket(self._io, self, self._root))
            i += 1


    class PsfbAfbRembPacket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.num_ssrc_list = self._io.read_u1()
            self.br_exp = self._io.read_bits_int_be(6)
            self.br_mantissa = self._io.read_bits_int_be(18)
            self._io.align_to_byte()
            self.ssrc_list = []
            for i in range(self.num_ssrc_list):
                self.ssrc_list.append(self._io.read_u4be())


        @property
        def max_total_bitrate(self):
            if hasattr(self, '_m_max_total_bitrate'):
                return self._m_max_total_bitrate

            self._m_max_total_bitrate = (self.br_mantissa * (1 << self.br_exp))
            return getattr(self, '_m_max_total_bitrate', None)


    class SrPacket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.sneder_ssrc = self._io.read_u4be()
            self.ntp_msw = self._io.read_u4be()
            self.ntp_lsw = self._io.read_u4be()
            self.rtp_timestamp = self._io.read_u4be()
            self.sender_packet_count = self._io.read_u4be()
            self.sender_octet_count = self._io.read_u4be()
            self.report_blocks = []
            for i in range(self._parent.subtype):
                self.report_blocks.append(RtcpPayload.ReportBlock(self._io, self, self._root))


        @property
        def ntp(self):
            if hasattr(self, '_m_ntp'):
                return self._m_ntp

            self._m_ntp = ((self.ntp_msw << 32) & self.ntp_lsw)
            return getattr(self, '_m_ntp', None)


    class RrPacket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.sneder_ssrc = self._io.read_u4be()
            self.report_blocks = []
            for i in range(self._parent.subtype):
                self.report_blocks.append(RtcpPayload.ReportBlock(self._io, self, self._root))



    class RtcpPacket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.version = self._io.read_bits_int_be(2)
            self.padding = self._io.read_bits_int_be(1) != 0
            self.subtype = self._io.read_bits_int_be(5)
            self._io.align_to_byte()
            self.type = KaitaiStream.resolve_enum(RtcpPayload.PacketType, self._io.read_u1())
            self.length = self._io.read_u2be()
            _on = self.type
            if _on == RtcpPayload.PacketType.rr:
                self._raw_data = self._io.read_bytes((4 * self.length))
                _io__raw_data = KaitaiStream(BytesIO(self._raw_data))
                self.data = RtcpPayload.RrPacket(_io__raw_data, self, self._root)
            elif _on == RtcpPayload.PacketType.sr:
                self._raw_data = self._io.read_bytes((4 * self.length))
                _io__raw_data = KaitaiStream(BytesIO(self._raw_data))
                self.data = RtcpPayload.SrPacket(_io__raw_data, self, self._root)
            elif _on == RtcpPayload.PacketType.bye:
                self._raw_data = self._io.read_bytes((4 * self.length))
                _io__raw_data = KaitaiStream(BytesIO(self._raw_data))
                self.data = RtcpPayload.ByePacket(_io__raw_data, self, self._root)
            elif _on == RtcpPayload.PacketType.rtpfb:
                self._raw_data = self._io.read_bytes((4 * self.length))
                _io__raw_data = KaitaiStream(BytesIO(self._raw_data))
                self.data = RtcpPayload.RtpfbPacket(_io__raw_data, self, self._root)
            elif _on == RtcpPayload.PacketType.sdes:
                self._raw_data = self._io.read_bytes((4 * self.length))
                _io__raw_data = KaitaiStream(BytesIO(self._raw_data))
                self.data = RtcpPayload.SdesPacket(_io__raw_data, self, self._root)
            elif _on == RtcpPayload.PacketType.psfb:
                self._raw_data = self._io.read_bytes((4 * self.length))
                _io__raw_data = KaitaiStream(BytesIO(self._raw_data))
                self.data = RtcpPayload.PsfbPacket(_io__raw_data, self, self._root)
            else:
                self.data = self._io.read_bytes((4 * self.length))


    class ReportBlock(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ssrc_identifier = self._io.read_u4be()
            self.fraction_lost = self._io.read_u1()
            self.cumulative_number_of_packets_lost = self._io.read_bytes(3)
            self.extended_highest_sequence_number_received = self._io.read_u4be()
            self.interarrival_jitter = self._io.read_u4be()
            self.last_sr = self._io.read_u4be()
            self.delay_since_last_sr = self._io.read_u4be()


    class RtpfbTransportFeedbackPacket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.base_sequence_number = self._io.read_u2be()
            self.packet_status_count = self._io.read_u2be()
            self.b4 = self._io.read_u4be()
            self.remaining = self._io.read_bytes_full()

        @property
        def reference_time(self):
            if hasattr(self, '_m_reference_time'):
                return self._m_reference_time

            self._m_reference_time = (self.b4 >> 8)
            return getattr(self, '_m_reference_time', None)

        @property
        def fb_pkt_count(self):
            if hasattr(self, '_m_fb_pkt_count'):
                return self._m_fb_pkt_count

            self._m_fb_pkt_count = (self.b4 & 255)
            return getattr(self, '_m_fb_pkt_count', None)

        @property
        def packet_status(self):
            if hasattr(self, '_m_packet_status'):
                return self._m_packet_status

            self._m_packet_status = self._io.read_bytes(0)
            return getattr(self, '_m_packet_status', None)

        @property
        def recv_delta(self):
            if hasattr(self, '_m_recv_delta'):
                return self._m_recv_delta

            self._m_recv_delta = self._io.read_bytes(0)
            return getattr(self, '_m_recv_delta', None)


    class SdesItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.type = KaitaiStream.resolve_enum(RtcpPayload.SdesItemType, self._io.read_u1())
            if self.type != RtcpPayload.SdesItemType.end:
                self.len_value = self._io.read_u1()

            if self.type != RtcpPayload.SdesItemType.end:
                self.value = self._io.read_bytes(self.len_value)



    class PsfbPacket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ssrc = self._io.read_u4be()
            self.ssrc_media_source = self._io.read_u4be()
            _on = self.fmt
            if _on == RtcpPayload.PsfbSubtype.afb:
                self._raw_fci_block = self._io.read_bytes_full()
                _io__raw_fci_block = KaitaiStream(BytesIO(self._raw_fci_block))
                self.fci_block = RtcpPayload.PsfbAfbPacket(_io__raw_fci_block, self, self._root)
            else:
                self.fci_block = self._io.read_bytes_full()

        @property
        def fmt(self):
            if hasattr(self, '_m_fmt'):
                return self._m_fmt

            self._m_fmt = KaitaiStream.resolve_enum(RtcpPayload.PsfbSubtype, self._parent.subtype)
            return getattr(self, '_m_fmt', None)


    class ByePacket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ssrc = self._io.read_u4be()
            if self._parent.length > 1:
                self.len_text = self._io.read_u1()

            if self._parent.length > 1:
                self.text = (self._io.read_bytes(self.len_text)).decode(u"ascii")



    class SdesPacket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.chunks = []
            for i in range(self.num_chunks):
                self.chunks.append(RtcpPayload.SdesChunk(self._io, self, self._root))


        @property
        def num_chunks(self):
            if hasattr(self, '_m_num_chunks'):
                return self._m_num_chunks

            self._m_num_chunks = self._parent.subtype
            return getattr(self, '_m_num_chunks', None)


    class RtpfbPacket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ssrc = self._io.read_u4be()
            self.ssrc_media_source = self._io.read_u4be()
            _on = self.fmt
            if _on == RtcpPayload.RtpfbSubtype.transport_feedback:
                self._raw_fci_block = self._io.read_bytes_full()
                _io__raw_fci_block = KaitaiStream(BytesIO(self._raw_fci_block))
                self.fci_block = RtcpPayload.RtpfbTransportFeedbackPacket(_io__raw_fci_block, self, self._root)
            else:
                self.fci_block = self._io.read_bytes_full()

        @property
        def fmt(self):
            if hasattr(self, '_m_fmt'):
                return self._m_fmt

            self._m_fmt = KaitaiStream.resolve_enum(RtcpPayload.RtpfbSubtype, self._parent.subtype)
            return getattr(self, '_m_fmt', None)


    class PsfbAfbPacket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.uid = self._io.read_u4be()
            _on = self.uid
            if _on == 1380273474:
                self._raw_contents = self._io.read_bytes_full()
                _io__raw_contents = KaitaiStream(BytesIO(self._raw_contents))
                self.contents = RtcpPayload.PsfbAfbRembPacket(_io__raw_contents, self, self._root)
            else:
                self.contents = self._io.read_bytes_full()


    class SdesChunk(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ssrc = self._io.read_u4be()
            self.items = []
            i = 0
            while not self._io.is_eof():
                self.items.append(RtcpPayload.SdesItem(self._io, self, self._root))
                i += 1




