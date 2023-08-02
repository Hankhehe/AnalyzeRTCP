from scapy.all import rdpcap
import json,matplotlib.pyplot as plt


class AnalyseRTCP:
    def __init__(self) -> None:
        pass
    def getPacket(self,pcapfilepath:str) -> dict:
        IDmatch,Data = {},{}
        PcapData = rdpcap(pcapfilepath)
        
        for i in PcapData:
            IPaddr = i['IP'].src
            PacketRaw =bytes(i['Raw'])
            Type = PacketRaw[1]

            if Type == 200:
                SrcID =int(PacketRaw[4:8].replace(b'/',b'').hex(),16)
                IDmatch[SrcID] = IPaddr

            elif Type == 201:
                SrcID = int(PacketRaw[8:12].replace(b'/',b'').hex(),16)
                PacketsLost = int(PacketRaw[13:16].replace(b'/',b'').hex(),16)
                Jitter = int(PacketRaw[20:24].replace(b'/',b'').hex(),16)

                if not IDmatch[SrcID] in Data : Data[IDmatch[SrcID]] = []
                
                Data[IDmatch[SrcID]].append({'ID':SrcID,'Jitter':Jitter,'PacketLost':PacketsLost})
        with open('DeviceID.txt','w') as f:
            json.dump(IDmatch,f,indent=4)
        
        with open('SessionData.txt','w') as f:
            json.dump(Data,f,indent=4)
        return Data


if __name__ == '__main__':
    task = AnalyseRTCP()
    results = task.getPacket('RTCP_From_MG.pcap')
    x_7,y_7,x_8,y_8,number = [],[],[],[],1

    for i in results['192.168.69.7']:
        x_7.append(number)
        y_7.append(i['Jitter'])
        number += 1

    number = 1
    for i in results['192.168.69.8']:
        x_8.append(number)
        y_8.append(i['Jitter'])
        number += 1


    fig, (ax7, ax8) = plt.subplots(2, 1, sharex=True)
    ax7.plot(x_7, y_7, label='192.168.69.7')
    ax7.set_ylim(0)
    ax7.set_ylabel('Jitter')

    ax8.plot(x_8, y_8, label='192.168.69.8')
    ax8.set_ylim(0)
    ax8.set_ylabel('Jitter')

    ax7.legend()
    ax8.legend()

    plt.show()