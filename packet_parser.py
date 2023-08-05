from scapy.all import rdpcap, hexdump
from scapy.packet import Packet
from kaitaistruct import KaitaiStream, BytesIO
from models.rtcp_payload import RtcpPayload


def parse_rtcp_payload(packet: Packet) -> RtcpPayload:
    if not packet.haslayer('UDP'):
        return []

    # remove ethernet trailer
    if packet.haslayer('Padding'):
        del packet['Padding']

    payload = RtcpPayload(KaitaiStream(BytesIO(bytes(packet['UDP'].payload))))
    return payload


def parse_pcap_file(filepath: str):
    rtcp_payloads: list[RtcpPayload] = []
    err_cnt = 0
    # Iterate through the packets and parse RTCP headers
    for idx, packet in enumerate(rdpcap(filepath)):
        try:
            datas = parse_rtcp_payload(packet)
            rtcp_payloads.append(datas)
        except Exception as e:
            err_cnt += 1
            print("=====================================")
            print('current packet id: ', idx + 1)
            print("Cannot parse rtcp payload, maybe it's not a RTCP packets")
            print('udp payload: ')
            hexdump(packet['UDP'].payload)
            print("Exception: ", e)

    print('Total packets: ', len(rtcp_payloads) + err_cnt)
    print('RTCP payloads: ', len(rtcp_payloads))
    print('Error packets: ', err_cnt)
    rtcp_packets: list[RtcpPayload.RtcpPacket] = [
        pack for payload in rtcp_payloads for pack in payload.rtcp_packets]
    print('Total RTCP Packets: ', len(rtcp_packets))
    print('Goodbye packet count: ', len(
        [p for p in rtcp_packets if p.payload_type == RtcpPayload.PayloadType.bye]))
    sr_packets = [p for p in rtcp_packets if p.payload_type ==
                  RtcpPayload.PayloadType.sr]
    rr_packets = [p for p in rtcp_packets if p.payload_type ==
                  RtcpPayload.PayloadType.rr]
    print('Sender report packet count: ', len(sr_packets))
    print('Receiver report packet count: ', len(rr_packets))


if __name__ == '__main__':
    # parse_pcap_file('4.pcap')

    for idx, packet in enumerate(rdpcap('4.pcap')):
        payload = parse_rtcp_payload(packet)

        for packet in payload.rtcp_packets:
            assert isinstance(packet, RtcpPayload.RtcpPacket)
            if packet.payload_type == RtcpPayload.PayloadType.rr:
                rr_packet: RtcpPayload.RrPacket = packet.body
                for report in rr_packet.report_blocks:
                    assert isinstance(report, RtcpPayload.ReportBlock)
                    print(
                        "SSRC_ID: ", report.ssrc_source_identifier, "\n",
                        "Packets Lost: ", report.fraction_lost, "\n",
                        "Jitter: ", report.interarrival_jitter, "\n",
                        "Last SR: ", report.last_sr, "\n",
                        "Delay Since Last SR: ", report.delay_since_last_sr, "\n",
                        "====================================="
                    )
