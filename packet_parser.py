from scapy.all import rdpcap,hexdump
from scapy.packet import Packet
from kaitaistruct import KaitaiStream, BytesIO
from models.rtcp_payload import RtcpPayload

def parse_rtcp_payload(packet:Packet) -> RtcpPayload:
        if not packet.haslayer('UDP'):
            return []
        
        # remove ethernet trailer
        if packet.haslayer('Padding'):
            del packet['Padding']

        payload = RtcpPayload(KaitaiStream(BytesIO(bytes(packet['UDP'].payload))))
        return payload
    

if __name__ == '__main__':
    # Replace 'your_pcap_file.pcap' with the actual path to your PCAP file
    # pcap_file = 'RTCP_From_MG.pcap'
    pcap_file = '4.pcap'

    rtcp_payloads: list[RtcpPayload] = []
    err_cnt = 0
    # Iterate through the packets and parse RTCP headers
    for idx, packet in enumerate(rdpcap(pcap_file)):
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
    rtcp_packets: list[RtcpPayload.RtcpPacket] = [pack for payload in rtcp_payloads for pack in payload.rtcp_packets]
    print('Total RTCP Packets: ', len(rtcp_packets))
    print('Goodbye packet count: ', len([p for p in rtcp_packets if p.payload_type == RtcpPayload.PayloadType.bye]))