
import java.util.ArrayList;

public class EthernetLayer implements BaseLayer {

	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	_ETHERNET_Frame m_sHeader;
	
	public EthernetLayer(String pName) {
		// super(pName);
		pLayerName = pName;
		ResetHeader();
	}
	
	public void ResetHeader() {
		m_sHeader = new _ETHERNET_Frame();
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
    
    private class _ETHERNET_Frame {
        _ETHERNET_ADDR enet_dstaddr;	// destination mac addr
        _ETHERNET_ADDR enet_srcaddr;	// source mac addr
        byte[] enet_type;				// ethernet protocol type
        byte[] enet_data;				// data

        public _ETHERNET_Frame() {
            this.enet_dstaddr = new _ETHERNET_ADDR();	// 6 Bytes / 0 ~ 5
            this.enet_srcaddr = new _ETHERNET_ADDR();	// 6 Bytes / 6 ~ 11
            this.enet_type = new byte[2];				// 2 Bytes / 12 ~ 13
            this.enet_data = null;						// variable length data
        }
    }
    
    public byte[] ObjToByte(_ETHERNET_Frame Header, byte[] input, int length) {//data�� ��� �ٿ��ֱ�
		byte[] buf = new byte[length + 14];
		for(int i = 0; i < 6; i++) {
			buf[i] = Header.enet_dstaddr.addr[i];
			buf[i+6] = Header.enet_srcaddr.addr[i];
		}			
		buf[12] = Header.enet_type[0];
		buf[13] = Header.enet_type[1];
		for (int i = 0; i < length; i++)
			buf[14 + i] = input[i];

		return buf;
	}

    // 상위 레이어에서 내려온 데이터에 Ethernet Header를 붙여서 전송
	public boolean Send(byte[] input, int length) {
		if (isBroadcast(m_sHeader.enet_dstaddr.addr)) { // broadcast라면 ARP 요청인 것 - 0x0806 (ARP)
			m_sHeader.enet_type[0] = (byte) 0x08;
			m_sHeader.enet_type[1] = (byte) 0x06;
		}
		else {	// broadcast가 아니라면 일반 메시지 전송인 것이므로 0x0800 (IP)
			m_sHeader.enet_type[0] = (byte) 0x08;
			m_sHeader.enet_type[1] = (byte) 0x00;
		}

		// data에 헤더를 붙여서 Send
		byte[] bytes = ObjToByte(m_sHeader, input, length);
		this.GetUnderLayer().Send(bytes, length + 14);
		return true;
	}
	

	// Ethernet Header 제거 함수
	public byte[] RemoveEthernetHeader(byte[] input, int length) {
		byte[] cpyInput = new byte[length - 14];
		System.arraycopy(input, 14, cpyInput, 0, length - 14);
		input = cpyInput;
		return input;
	}

	// ARP Reply Send 함수
	public boolean ARPReplySend(byte[] input, int length) {
		// ARP Packet의 dst Mac을 enet_dst 설정
		for(int i = 0; i < 6; i++) {
			m_sHeader.enet_dstaddr.addr[i] = input[18+i];
		}
		// arp 프로토콜으로 설정
		m_sHeader.enet_type[0] = (byte) 0x08;
		m_sHeader.enet_type[1] = (byte) 0x06;

		// data에 헤더를 붙여서 Send
		byte[] bytes = ObjToByte(m_sHeader, input, length);
		this.GetUnderLayer().Send(bytes, length + 14);
		return true;

	}
	
	// 수신 함수
	public synchronized boolean Receive(byte[] input) {
		byte[] data;
		byte[] temp_src = m_sHeader.enet_srcaddr.addr;

		// Ethernet 프레임 헤더 중에 16비트(2 byte) 프로토콜 타입 필드를 보고 판단하여 상위 계층으로 전달 (enet_type)
		if(input[12] == (byte) 0x08 && input[13] == (byte) 0x06) {	// 0X0806 - ARP (첫 번째 상위레이어)
			if (chkAddr(input) || (isBroadcast(input)) || !isMyPacket(input)) {
				data = RemoveEthernetHeader(input, input.length);
				this.GetUpperLayer(0).Receive(data);	// To ARPLayer
				return true;
			}
		}

		else if(input[12] == (byte) 0x08 && input[13] == (byte) 0x00) {	// 0x0800 - IP (두 번째 상위레이어)
			if (chkAddr(input) || (isBroadcast(input)) || !isMyPacket(input)) {
				data = RemoveEthernetHeader(input, input.length);
				this.GetUpperLayer(1).Receive(data);	// To IPLayer
				return true;
			}
		}

		return false;
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

	// 목적지 Ethernet 주소가 브로드캐스트(ff-ff-ff-ff-ff-ff)인 경우 true
	private boolean isBroadcast(byte[] bytes) {
		for(int i = 0; i< 6; i++) {
			if (bytes[i] != (byte) 0xff)
				return false;
		}
		return true;
	}

	// 자신이 만든 frame인 경우 true (Src Ethernet 주소가 자신의 주소인 경우)
	private boolean isMyPacket(byte[] input){
		for(int i = 0; i < 6; i++)
			if(m_sHeader.enet_srcaddr.addr[i] != input[6 + i])
				return false;
		return true;
	}

	// 목적지 Ethernet 주소가 자신의 Ethernet 주소인 경우 true
	private boolean chkAddr(byte[] input) {
		byte[] temp = m_sHeader.enet_srcaddr.addr;
		for(int i = 0; i< 6; i++)
			if(m_sHeader.enet_srcaddr.addr[i] != input[i])
				return false;
		return true;
	}
	
	public void SetEnetSrcAddress(byte[] srcAddress) {
		m_sHeader.enet_srcaddr.addr = srcAddress;
	}

	public void SetEnetDstAddress(byte[] dstAddress) {
		m_sHeader.enet_dstaddr.addr = dstAddress;
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
