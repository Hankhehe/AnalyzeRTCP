from scapy.all import rdpcap,sniff
import json,matplotlib.pyplot as plt
from datetime import datetime

class AnalyseRTCP:
    def __init__(self) -> None:
        self.IDmatch = {}
        self.Data = {}
        self.PacketNumber = 1
    
    def Get_Data_From_RR(self,Packet) -> None:
        '''傳進 RR 封包並解析出 SrcID、Lost、DelayTime'''
        SrcID = int(Packet[8:12].replace(b'/',b'').hex(),16)
        PacketsLost = int(Packet[13:16].replace(b'/',b'').hex(),16)
        Jitter = int(Packet[20:24].replace(b'/',b'').hex(),16)
        DelayTime = int(Packet[28:32].replace(b'/',b'').hex(),16)
        if not self.IDmatch[SrcID] in self.Data : self.Data[self.IDmatch[SrcID]] = []
        self.Data[self.IDmatch[SrcID]].append({'ID':SrcID,'Jitter':Jitter,'PacketLost':PacketsLost
                                               ,'DelayTime':DelayTime ,'CreateTime':datetime.now().strftime('%Y-%m-%d %H:%M')})
        
    def Get_SrcID_From_SR(self,Packet,IPAddr) -> None:
        '''傳進 SR 封包，將 Src ID 存進 Data'''
        SrcID =int(Packet[4:8].replace(b'/',b'').hex(),16)
        self.IDmatch[SrcID] = IPAddr

    def CheckPacket(self,Packet) -> None:
        '''解析 RTCP 封包，並將分類成 RR or SR'''
        IPaddr = Packet['IP'].src
        PacketRaw =bytes(Packet['Raw'])
        ReportCount = PacketRaw[0]
        Type = PacketRaw[1]
        if Type == 200: 
            self.Get_SrcID_From_SR(PacketRaw,IPaddr)

        elif Type == 201 and ReportCount == 129 :
            self.Get_Data_From_RR(PacketRaw)
        self.PacketNumber +=1

        with open('DeviceID.txt','w') as f:
            json.dump(self.IDmatch,f,indent=4)
        
        with open('SessionData.txt','w') as f:
            json.dump(self.Data,f,indent=4)

    def Get_Packet(self,pcapfilepath:str) -> None:
        '''透過 pcap 封包檔解析 RTCP'''
        PcapData = rdpcap(pcapfilepath)
        for i in PcapData:
            self.CheckPacket(Packet=i)

    def SniiffRTCP(self) -> None:
        '''透過聽封包進行 RTCP 分析'''
        sniff(filter = 'udp and port 5005',store = 0,prn=self.CheckPacket,iface='乙太網路 4')


if __name__ == '__main__':
    task = AnalyseRTCP()
    # task.SniiffRTCP() #透過聽封包產生資料
    # results = task.Get_Packet('RTCP_From_MG.pcap') #透過 RTCP 封包檔產生資料


    if False: #圖表開關
        with open('SessionData.txt','r') as f:
            results = json.load(f)

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