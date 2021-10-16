import java.util.ArrayList;
import java.util.Hashtable;

public class ARPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    // Key: IP 주소
    public static Hashtable<String, _ARP_Cache_Entry> ARP_Cache_table = new Hashtable<>();// 우변 꺾쇠안에 타입 명시와 타입 명시하지 않는 차이가??
    public static Hashtable<String, _Proxy_Entry> Proxy_Entry_table = new Hashtable<>();

    _ARP_HEADER m_sHeader;

    private class _ARP_HEADER {
        byte[] macType;					// Hardware Type
        byte[] ipType;					// Protocol Type
        byte macAddrLen;				// Length of hardware Address
        byte ipAddrLen;					// Length of protocol Address
        byte[] opcode;					// Opcode (ARP Request)
        _ETHERNET_ADDR srcMac;			// Sender's hardware Address
        _IP_ADDR srcIp;					// Sender's protocol Address
        _ETHERNET_ADDR dstMac;			// Target's hardware Address
        _IP_ADDR dstIp;					// Target's protocol Address

        public _ARP_HEADER() {          // 28 Bytes
            this.macType = new byte[2];			    // 2 Bytes / 0 ~ 1
            this.ipType = new byte[2];			    // 2 Bytes / 2 ~ 3
            this.macAddrLen = (byte) 0x00;			// 1 Byte  / 4
            this.ipAddrLen = (byte) 0x00;			// 1 Byte  / 5
            this.opcode = new byte[2];		        // 2 Bytes / 6 ~ 7
            this.srcMac = new _ETHERNET_ADDR();		// 6 Bytes / 8 ~ 13
            this.srcIp = new _IP_ADDR();			// 4 Bytes / 14 ~ 17
            this.dstMac = new _ETHERNET_ADDR();		// 6 Bytes / 18 ~ 23
            this.dstIp = new _IP_ADDR();			// 4 Bytes / 24 ~ 27
        }
    }

    public static class _ARP_Cache_Entry {
        byte[] addr;
        boolean status;
        int lifetime;

        //ARP Cache Entry
        public _ARP_Cache_Entry(byte[] addr, boolean status, int lifetime){
            this.addr = addr;
            this.status = status;
            this.lifetime = lifetime;
        }
    }

    //Proxy ARP Entry
    public static class _Proxy_Entry{
        String hostName;
        byte[] addr;    // mac addr

        public _Proxy_Entry(byte[] addr, String hostName){
            this.hostName = hostName;
            this.addr = addr;
        }
    }

    private void ResetHeader(){
            m_sHeader = new _ARP_HEADER();
    }

    public ARPLayer(String pName){
        pLayerName = pName;
        ResetHeader();
    }

    private class _IP_ADDR {
        private byte[] addr = new byte[4];

        public _IP_ADDR() {
            this.addr[0] = (byte) 0x00;
            this.addr[1] = (byte) 0x00;
            this.addr[2] = (byte) 0x00;
            this.addr[3] = (byte) 0x00;
        }
    }

    private class _ETHERNET_ADDR {
        private byte[] addr = new byte[6];
     
        public _ETHERNET_ADDR() {
            this.addr[0] = (byte) 0x00;
            this.addr[1] = (byte) 0x00;
            this.addr[2] = (byte) 0x00;
            this.addr[3] = (byte) 0x00;
            this.addr[4] = (byte) 0x00;
            this.addr[5] = (byte) 0x00;
        }
    }

    public byte[] ObjToByte(_ARP_HEADER Header) {
        byte[] buf = new byte[28];	
        
        buf[0] = Header.macType[0];
        buf[1] = Header.macType[1];
        buf[2] = Header.ipType[0];
        buf[3] = Header.ipType[1];
        buf[4] = Header.macAddrLen;
        buf[5] = Header.ipAddrLen;
        buf[6] = Header.opcode[0];
        buf[7] = Header.opcode[1];
        for (int i =0; i<6; i++) {
        	buf[8+i] = Header.srcMac.addr[i];
        }
        for (int i =0; i<4; i++) {
        	buf[14+i] = Header.srcIp.addr[i];
        }
        for (int i =0; i<6; i++) {
        	buf[18+i] = Header.dstMac.addr[i];
        }
        for (int i =0; i<4; i++) {
        	buf[24+i] = Header.dstIp.addr[i];
        }
        return buf;
    }
    // ARP Request 
    public boolean Send(byte[] input, int length, String dstIP) {
        // TODO: Send 구현
        // 엔트리 테이블에서 이미 있는 IP인지 확인
        // 없으면 엔트리 테이블에 추가

        if(!ARP_Cache_table.containsKey(dstIP)) {   // 테이블에 없는 경우(ARP전송)
            // 엔트리 테이블에 추가
            addARPEntry(dstIP);
            // EthernetLayer dstAddr를 Broadcast로 설정
            byte[] dstAddr = new byte[6];
            for(int i = 0; i < 6; i++) {	// FF-FF-FF-FF-FF-FF ( Broadcast )
                dstAddr[i] = (byte) 0xFF;
            }
            ((EthernetLayer) this.GetUnderLayer()).SetEnetDstAddress(dstAddr);
            
            m_sHeader.macType = intToByte2(1);	// Hardwaretype : Ethernet
            m_sHeader.ipType = intToByte2(8);	// IP field 	: 0x0800
            m_sHeader.macAddrLen = (byte) 0x06;	// Mac Address 	: 6 bytes
            m_sHeader.ipAddrLen = (byte) 0x04;	// Ip Address 	: 4 bytes
            m_sHeader.opcode = intToByte2(1);	// ARP request 	: 0x01
            byte[] bytes = ObjToByte(m_sHeader);
            
            this.GetUnderLayer().Send(bytes, bytes.length);
            
        } /* else if(ARP_Cache_table.containsKey(dstIP)) {
            // 테이블에 있는데 MAC 주소를 모르는 경우
            // 엔트리 테이블에 추가
            addARPEntry(dstIP);
            // EthernetLayer dstAddr를 Broadcast로 설정
            byte[] dstAddr = new byte[6];
            for(int i = 0; i < 6; i++) {
                dstAddr[i] = (byte) 0xFF;
            }
            ((EthernetLayer) this.GetUnderLayer()).SetEnetDstAddress(dstAddr);
            // TODO: Header 붙인 뒤 Send ( 엔트리테이블에 없을때와 똑같이 동작 )           
        } */
        
        else {
        	// 테이블에 있고 MAC 주소도 아는 경우 아무것도 하지 않음
        	return true;
        }

        return true;
    }
    // ARP Reply : receive에서 src주소와 dst주소를 뒤집은 Frame에 OPCODE 수정하여 반환함
    public boolean Send(byte[] reply_pack) {
    	byte[] temp = intToByte2(2);	// ARP Reply	: 0x02
    	reply_pack[6] = temp[0];	
    	reply_pack[7] = temp[1];	
    	this.GetUnderLayer().Send(reply_pack, reply_pack.length);
    	
    	return true;
    }


    // arp cache entry를 해시테이블에 추가하는 함수
    public static void addARPEntry(String ip_key) {
        _ARP_Cache_Entry newItem = new _ARP_Cache_Entry(null, false, 3);
        ARP_Cache_table.put(ip_key, newItem);

        // GUI update
        ARPDlg.UpdateARPCacheEntryWindow(ARP_Cache_table);
    }

    // arp cache entry를 해시테이블에서 삭제하는 함수
    public static void deleteARPEntry(String ip_key) {
        ARP_Cache_table.remove(ip_key);

        // GUI update
        ARPDlg.UpdateARPCacheEntryWindow(ARP_Cache_table);
    }

    public static void deleteAllARPEntry() {
        ARP_Cache_table.clear();

        // GUI update
        ARPDlg.UpdateARPCacheEntryWindow(ARP_Cache_table);
    }

    // 새 proxy host를 해시테이블에 추가하는 함수
    public static void addProxyEntry(String hostName, String ip, byte[] addr) {
        _Proxy_Entry newItem = new _Proxy_Entry(addr, hostName);
        Proxy_Entry_table.put(ip, newItem);

        // GUI update
        ARPDlg.UpdateProxyEntryWindow(Proxy_Entry_table);
    }

    // proxy host를 해시테이블에서 삭제하는 함수
    public static void deleteProxyEntry(String ip_key) {
        Proxy_Entry_table.remove(ip_key);

        // GUI update
        ARPDlg.UpdateProxyEntryWindow(Proxy_Entry_table);
    }

    // ARPLayer가 받은 패킷의 ARP Header에서 dstIP를 확인하고
    // proxy table에 있는지 확인하는 함수
    public boolean IsProxyHost(byte[] input) {
        // 패킷으로부터 dstIP 추출
        String dstIP;
        String s1 = String.valueOf(input[24] & 0xFF);
        String s2 = String.valueOf(input[25] & 0xFF);
        String s3 = String.valueOf(input[26] & 0xFF);
        String s4 = String.valueOf(input[27] & 0xFF);
        dstIP = s1 + "." + s2 + "." + s3 + "." + s4;

        dstIP = dstIP.trim();
        return Proxy_Entry_table.containsKey(dstIP);
     }

    public byte[] RemoveARPHeader(byte[] input, int length) {
        byte[] cpyInput = new byte[length - 28];
        System.arraycopy(input, 28, cpyInput, 0, length - 28);
        input = cpyInput;
        return input;
    }

    // Src HardWare 및 Protocol Address와 Dst HardWare 및 Protocol Address Swap함수 
    // index 교체 => 8 ~ 17 <-> 18 ~ 27
    public byte[] swap(byte[] input){
        int start = 8; 
        for(int i = start; i < start + 10; i++){
            byte temp = input[i];
            input[i] = input[i+10];
            input[i+10] = temp;
        }
        return input;
    }

    /*-------------------내 IP 확실히 하고 작성.-----------------*/ 
    public boolean checkAddressWithMyIp(byte[] dstIp){
        // 인자로 들어온 dstIP와 현재 Host의 Ip가 다르면 False 반환 
        // 같은경우 True 반환.
        for(int i = 0; i < 4; i++) {
            if(m_sHeader.srcIp.addr[i] != dstIp[i]) {
                return false;
            }
        }
        return true;
    }

    public synchronized boolean Receive(byte[] input) {
        byte[] srcMac = new byte[6];
        byte[] srcIp = new byte[4];
		byte[] dstMac = new byte[6];
		byte[] dstIp = new byte[4];
        System.arraycopy(input, 8, srcMac, 0, 6);
		System.arraycopy(input, 14, srcIp, 0, 4);
		System.arraycopy(input, 18, dstMac, 0, 6);
		System.arraycopy(input, 24, dstIp, 0, 4);
        String ipKey = ipByteToString(srcIp);

        //opcode == 1인경우 basic ARP or proxy ARP
        if(input[7] == 0x01){
            if(checkAddressWithMyIp(dstIp) || Proxy_Entry_table.containsKey(dstIp)){ // 자신의 주소와 같거나 혹은 Proxytable에 있는지 검사.
                _ARP_Cache_Entry entry = new _ARP_Cache_Entry(srcMac, true, 30);
                ARP_Cache_table.put(ipKey, entry); // hashtable 원소 => <String, entry>
                byte[] swappedInput = swap(input);
                Send(swappedInput);
            }
            // 위 if문 내 자신의 Mac Address 추가해야함.
            // 자신의 Mac & Ip는 어디 저장되어 있는지??

            else{//자신과 상관없는 경우 => G-ARP 및 BroadCast
                if(ARP_Cache_table.containsKey(ipKey)){
                    _ARP_Cache_Entry entry = ARP_Cache_table.get(ipKey);
                    System.arraycopy(srcMac, 0, entry.addr, 0 , 6);
                    ARP_Cache_table.replace(ipKey, entry);
                }
                else if(){
                    
                }   
            }
        }
        // ARP Reply 인 경우.
        else if (input[7] == 0x02) {
            if(checkAddressWithMyIp(dstIp)){
                _ARP_Cache_Entry entry = ARP_Cache_table.get(ipKey);
                entry.addr = srcMac;
                entry.status = true;
                ARP_Cache_table.replace(ipKey, entry);
            }
        }
        return true;
    }

    
    private byte[] intToByte2(int value) {
        byte[] temp = new byte[2];
        temp[0] |= (byte) ((value & 0xFF00) >> 8);
        temp[1] |= (byte) (value & 0xFF);

        return temp;
    }

    private int byte2ToInt(byte value1, byte value2) {
        return (int)((value1 << 8) | (value2));
    }

    public void SetSrcMacAddress(byte[] srcAddress) {
        m_sHeader.srcMac.addr = srcAddress;
    }

    public void SetSrcIPAddress(byte[] srcAddress) {
        m_sHeader.srcIp.addr = srcAddress;
    }

    public void SetDstIPAddress(byte[] dstAddress) {
        m_sHeader.dstIp.addr = dstAddress;
    }


    @Override
    public String GetLayerName() {
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer() {
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
    }

    public String ipByteToString(byte[] something){
        String temp = "";
        for (byte b : something){
            temp += Integer.toString(b & 0xFF) + "."; //0xff = 11111111(2) byte 정수변환
        }
        return temp.substring(0, temp.length() - 1);
    }
}
