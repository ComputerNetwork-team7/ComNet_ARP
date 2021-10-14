import java.util.ArrayList;


public class ApplicationLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    public int packet_size = 10;
    _ARP_HEADER m_sHeader;
        
    private class _ARP_HEADER {
        byte[] app_totlen;
        byte app_type;
        byte app_unused;
        byte[] app_data;
        
        public _ARP_HEADER() {
            this.app_totlen = new byte[2];
            this.app_type = 0x00;
            this.app_unused = 0x00;
            this.app_data = null;
        }
    }

    public ApplicationLayer(String pName) {
        // super(pName);
        pLayerName = pName;
        ResetHeader();
    }

    private void ResetHeader() {
        m_sHeader = new _ARP_HEADER();
    }

    private byte[] objToByte(_ARP_HEADER Header, byte[] input, int length) {
        byte[] buf = new     byte[length + 4];
        
        buf[0] = Header.app_totlen[0];
        buf[1] = Header.app_totlen[1];
        buf[2] = Header.app_type;
        buf[3] = Header.app_unused;

        if (length >= 0) System.arraycopy(input, 0, buf, 4, length);

        return buf;
    }

    public byte[] RemoveappHeader(byte[] input, int length) {
        byte[] cpyInput = new byte[length - 4];
        System.arraycopy(input, 4, cpyInput, 0, length - 4);
        input = cpyInput;
        return input;
    }
    
  /**/
    private void fragSend(byte[] input, int length) { // 단편화
    	byte[] bytes = new byte[packet_size];
    	int i = 0;
    	m_sHeader.app_totlen = intToByte2(length);
    	m_sHeader.app_type = (byte) (0x01); // 단편화 시작 패킷
    	
    	System.arraycopy(input,  0 , bytes, 0, packet_size);
    	bytes = objToByte(m_sHeader, bytes, packet_size);
    	this.GetUnderLayer().Send(bytes, bytes.length);
    	
    	int maxLen = length / packet_size;
    	
    	m_sHeader.app_type = (byte) (0x02); // 단편화 중간 패킷
    	m_sHeader.app_totlen = intToByte2(packet_size);
    	for (i=1; i<maxLen; i++) {
    		if(i+1<maxLen && length%packet_size == 0) {
    			m_sHeader.app_type = (byte) (0x03); // 단편화 마지막 패킷
    		}
    		System.arraycopy(input, packet_size*i, bytes, 0, packet_size);
    		bytes = objToByte(m_sHeader, bytes, packet_size);
    		this.GetUnderLayer().Send(bytes, bytes.length);
    	}
    	if ( length % packet_size != 0) {
    		m_sHeader.app_type = (byte) (0x03);  // 단편화 마지막 패킷
    		m_sHeader.app_totlen = intToByte2(length%packet_size);
    		bytes = new byte[length / packet_size];
    		System.arraycopy(input,  length-(length%packet_size), bytes, 0, length%packet_size);
    		bytes = objToByte(m_sHeader, bytes, bytes.length);
    		this.GetUnderLayer().Send(bytes, bytes.length);
    	}
    }
    
    public boolean Send(byte[] input, int length) {
    	byte[] bytes;
    	m_sHeader.app_totlen = intToByte2(length);
    	m_sHeader.app_type = (byte) (0x00);
    
    	if (length > packet_size) {
    		fragSend(input, length);
    	} else {
    		bytes = objToByte(m_sHeader, input, input.length);
    		this.GetUnderLayer().Send(bytes, bytes.length);
    	}
        return true;
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
