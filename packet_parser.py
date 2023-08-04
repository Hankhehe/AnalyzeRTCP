from scapy.all import rdpcap
from scapy.packet import Packet
from kaitaistruct import KaitaiStream, BytesIO
from models.rtcp_payload import RtcpPayload

def parse_rtcp_packet(packet:Packet) -> list[RtcpPayload.RtcpPacket] | None:
    try:
        if not packet.haslayer('UDP'):
            return []
        datas = RtcpPayload(KaitaiStream(BytesIO(bytes(packet['UDP']['Raw']))))
        return datas.rtcp_packets
    except Exception as e:
        print("Cannot parse rtcp payload, maybe it's not a RTCP packets")
        print("Exception: ", e)
        return None


if __name__ == '__main__':
    # Replace 'your_pcap_file.pcap' with the actual path to your PCAP file
    pcap_file = 'RTCP_From_MG.pcap'

    rtcps = []
    # Iterate through the packets and parse RTCP headers
    for idx, packet in enumerate(rdpcap(pcap_file)):
        datas = parse_rtcp_packet(packet)
        if not datas:
            print('current packet id: ', idx)
            print("=====================================")
            continue
        
        rtcps.extend(datas)
             
    
