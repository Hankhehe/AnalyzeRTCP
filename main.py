from scapy.all import rdpcap,sniff
import json,matplotlib.pyplot as plt

class AnalyseRTCP:
    def __init__(self) -> None:
        self.IDmatch = {}
        self.Data = {}
        self.PacketNumber = 1

    def getPacket(self,pcapfilepath:str) -> dict:
        PcapData = rdpcap(pcapfilepath)
        for i in PcapData:
            IPaddr = i['IP'].src
            PacketRaw =bytes(i['Raw'])
            ReportCount = PacketRaw[0]
            Type = PacketRaw[1]

            if Type == 200:
                self.GetData_From_Goodbye(PacketRaw,IPaddr)

            elif Type == 201 and ReportCount == 129 :
                self.GetRSrcID_From_RR(PacketRaw)
            self.PacketNumber +=1

        with open('DeviceID.txt','w') as f:
            json.dump(self.IDmatch,f,indent=4)
        
        with open('SessionData.txt','w') as f:
            json.dump(self.Data,f,indent=4)
        return self.Data
    
    def GetRSrcID_From_RR(self,Packet) -> None:
        SrcID = int(Packet[8:12].replace(b'/',b'').hex(),16)
        PacketsLost = int(Packet[13:16].replace(b'/',b'').hex(),16)
        Jitter = int(Packet[20:24].replace(b'/',b'').hex(),16)
        if not self.IDmatch[SrcID] in self.Data : self.Data[self.IDmatch[SrcID]] = []
        self.Data[self.IDmatch[SrcID]].append({'ID':SrcID,'Jitter':Jitter,'PacketLost':PacketsLost})

    def GetData_From_Goodbye(self,Packet,IPAddr) -> None:
        SrcID =int(Packet[4:8].replace(b'/',b'').hex(),16)
        self.IDmatch[SrcID] = IPAddr

    def SniiffRTCP(self) -> None:
        pass
        # sniff(iface='乙太網路'filter = 'udp and port 5055',)


if __name__ == '__main__':
    task = AnalyseRTCP()
    # PcapData = rdpcap('4.pcap')
    # sniff(iface='乙太網路'filter = 'udp and port 5055')
    
    results = task.getPacket('4.pcap')
    
    x_7,y_7,x_8,y_8 = [],[],[],[]
    fig, (ax7, ax8) = plt.subplots(2, 1, sharex=True)

    if '192.168.69.7' in results:
        number = 1
        for i in results['192.168.69.7']:
            x_7.append(number)
            y_7.append(i['Jitter'])
            number += 1
        ax7.plot(x_7, y_7, label='192.168.69.7')
        ax7.set_ylim(0)
        ax7.set_ylabel('Jitter')
        ax7.legend()

    if '192.168.69.8' in results:
        number = 1
        for i in results['192.168.69.8']:
            x_8.append(number)
            y_8.append(i['Jitter'])
            number += 1
        ax8.plot(x_8, y_8, label='192.168.69.8')
        ax8.set_ylim(0)
        ax8.set_ylabel('Jitter')
        ax8.legend()

    plt.show()