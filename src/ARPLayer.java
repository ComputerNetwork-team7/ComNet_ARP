import java.util.ArrayList;
import java.util.Hashtable;

public class ARPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    // Key: IP 주소
    public static Hashtable<String, _ARP_Cache_Entry> ARP_Cache_table = new Hashtable<>();
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

    public byte[] ObjToByte(_ARP_HEADER Header, byte[] input, int length) {//data�� ��� �ٿ��ֱ�
        byte[] buf = new byte[length + 14];
//        for(int i = 0; i < 6; i++) {
//            buf[i] = Header.enet_dstaddr.addr[i];
//            buf[i+6] = Header.enet_srcaddr.addr[i];
//        }
//        buf[12] = Header.enet_type[0];
//        buf[13] = Header.enet_type[1];
//        for (int i = 0; i < length; i++)
//            buf[14 + i] = input[i];

        return buf;
    }

    public boolean Send(byte[] input, int length, String dstIP) {
        // TODO: Send 구현
        // arp테이블에서 이미 있는 ip인지 확인
        // 없으면 arp 테이블에 추가

        // Send시에는 그냥 함수 파라미터 String dstIP만 넘겨서 해당 IP가 해시테이블에 있는지 확인하면 됩니다
        if(!ARP_Cache_table.containsKey(dstIP)) {   // 테이블에 없는 경우(ARP전송)
            // 엔트리 테이블에 추가
            addARPEntry(dstIP);
            // EthernetLayer dstAddr를 Broadcast로 설정
            byte[] dstAddr = new byte[6];
            for(int i = 0; i < 6; i++) {
                dstAddr[i] = (byte) 0xFF;
            }
            ((EthernetLayer) this.GetUnderLayer()).SetEnetDstAddress(dstAddr);
            // TODO: Header 붙인 뒤 Send


        } else if(ARP_Cache_table.containsKey(dstIP)) {
            // 테이블에 있는데 MAC 주소를 모르는 경우
            // 엔트리 테이블에 추가
            addARPEntry(dstIP);
            // EthernetLayer dstAddr를 Broadcast로 설정
            byte[] dstAddr = new byte[6];
            for(int i = 0; i < 6; i++) {
                dstAddr[i] = (byte) 0xFF;
            }
            ((EthernetLayer) this.GetUnderLayer()).SetEnetDstAddress(dstAddr);
            // TODO: Header 붙인 뒤 Send(테이블에 없는 경우와 같은 방법으로)

            // 테이블에 있고 MAC 주소도 아는 경우 아무것도 하지 않음
        }

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
        String s1 = String.valueOf(input[24]);
        String s2 = String.valueOf(input[25]);
        String s3 = String.valueOf(input[26]);
        String s4 = String.valueOf(input[27]);
        dstIP = s1 + "." + s2 + "." + s3 + "." + s4;

        dstIP = dstIP.trim();
        return Proxy_Entry_table.containsKey(dstIP);
     }

    public byte[] RemoveARPHeader(byte[] input, int length) {
//        byte[] cpyInput = new byte[length - 14];
//        System.arraycopy(input, 14, cpyInput, 0, length - 14);
//        input = cpyInput;
        return input;
    }

    public synchronized boolean Receive(byte[] input) {

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
}
