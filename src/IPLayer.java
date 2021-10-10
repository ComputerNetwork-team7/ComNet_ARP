import java.util.ArrayList;

public class IPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    _IP_HEADER m_sHeader;

    private class _IP_HEADER {
        byte ip_verlen;     // ip version->IPv4 : 4 (1 byte)
        byte ip_tos;        // type of service
        byte[] ip_len;      // total packet length
        byte[] ip_id;       // datagram id
        byte[] ip_fragoff;  // fragment offset
        byte ip_ttl;        // time to live in gateway hops
        byte ip_proto;      // IP protocol
        byte[] ip_cksum;    // header checksum
        _IP_ADDR ip_src;    // source IP address
        _IP_ADDR ip_dst;    // destination IP address

        public _IP_HEADER() {				// 20 Bytes
            this.ip_verlen = (byte) 0x00;       // 1 Byte / 0
            this.ip_tos = (byte) 0x00;          // 1 Byte / 1
            this.ip_len = new byte[2];          // 2 Byte / 2 ~ 3
            this.ip_id = new byte[2];           // 2 Byte / 4 ~ 5
            this.ip_fragoff = new byte[2];      // 2 Byte / 6 ~ 7
            this.ip_ttl = (byte) 0x00;          // 1 Byte / 8
            this.ip_proto = (byte) 0x00;        // 1 Byte / 9
            this.ip_cksum = new byte[2];        // 2 Byte / 10 ~ 11
            this.ip_src = new _IP_ADDR();       // 4 Byte / 12 ~ 15
            this.ip_dst = new _IP_ADDR();       // 4 Byte / 16 ~ 19
        }
    }

    private void ResetHeader(){
        m_sHeader = new _IP_HEADER();
    }

    public IPLayer(String pName){
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

    public byte[] ObjToByte(_IP_HEADER Header, byte[] input, int length) {//data�� ��� �ٿ��ֱ�
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

    public boolean Send(byte[] input, int length) {

        return true;
    }

    public byte[] RemoveARPHeader(byte[] input, int length) {
        byte[] cpyInput = new byte[length - 14];
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
