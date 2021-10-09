import java.util.ArrayList;

public class ARPLayer implements BaseLayer {

	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	_ARP_Frame ARPframe;
	
	public ARPLayer(String pName) {
		// TODO Auto-generated constructor stub
		pLayerName = pName;
	}
	
	public void ResetFrame() {
		ARPframe = new _ARP_Frame();
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
	
	private class _IP_ADDR {
		private byte[] addr = new byte[4];
		
		public _IP_ADDR() {
			this.addr[0] = (byte) 0x00;
            this.addr[1] = (byte) 0x00;
            this.addr[2] = (byte) 0x00;
            this.addr[3] = (byte) 0x00;
		}
	}
	
	private class _ARP_Frame {
		byte[] hard_type;
		byte[] prot_type;
		byte hard_size;
		byte prot_size;
		byte[] op;
		_ETHERNET_ADDR src_enet_addr;
		_IP_ADDR src_ip_addr;
		_ETHERNET_ADDR dst_enet_addr;
		_IP_ADDR dst_ip_addr;
		
		public _ARP_Frame() {
			this.hard_type = new byte[2];
			this.prot_type = new byte[2];
			this.hard_size = 0x00;
			this.prot_size = 0x00;
			this.op = new byte[2];
			this.src_enet_addr = new _ETHERNET_ADDR();
			this.src_ip_addr = new _IP_ADDR();
			this.dst_enet_addr = new _ETHERNET_ADDR();
			this.dst_ip_addr = new _IP_ADDR();
		}
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
	
	public boolean Send() {
		
		
		return true;
	}
	
	public boolean Recieve() {
		
		
		return true;
	}

}
