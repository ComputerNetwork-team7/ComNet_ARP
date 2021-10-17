import org.jnetpcap.PcapIf;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Map;

public class ARPDlg extends JFrame implements BaseLayer {

	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	BaseLayer UnderLayer;

	private static LayerManager m_LayerMgr = new LayerManager();
	
	Container contentPane;
	
	// ARP Cache
	JTextArea ARPCacheTableArea;
	JList list_arp_cache;		// arp cache list
	static DefaultListModel model_arp;	// 실제 arp cache 데이터
	JScrollPane scroll_arp;		// 스크롤 속성(arp)
	JButton Item_Delete_Button;	// Item Delete 버튼
	JButton All_Delete_Button;	// All Delete 버튼
	private JTextField targetIPWrite;

	// Proxy ARP
	JList list_proxy_arp;			// proxy arp entry list
	static DefaultListModel model_proxy;	// 실제 proxy arp entry 데이터
	JScrollPane scroll_proxy;		// 스크롤 속성(proxy)
	JButton Add_Button_Proxy;		// Add 버튼
	JButton Delete_Button_Proxy;	// Delete 버튼
	JDialog addDialog;			// add proxy 다이얼로그

	// Gratuitous ARP
	JTextField gratWrite;		// gratuitous MAC 텍스트필드
	JButton gratSendButton;		// grat ARP 패킷 전송 버튼

	// Source Address Setting
	JButton Setting_Button;		// Source MAC, IP 세팅 버튼
	JButton ARP_send_Button;	// ARP 패킷 전송 버튼
	static JComboBox<String> NICComboBox;	// 랜카드 선택 ComboBox
	JTextArea srcMacAddress;
	JTextArea srcIPAddress;
	JLabel lblsrcIP;
	JLabel lblsrcMAC;

	int adapterNumber = 0;

	public static void main(String[] args) {

		// 모든 레이어 추가 및 연결
		// 하위 계층의 순서를 정함
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new EthernetLayer("Ethernet"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP"));
		m_LayerMgr.AddLayer(new IPLayer("IP"));
		m_LayerMgr.AddLayer(new ApplicationLayer("Application"));
		m_LayerMgr.AddLayer(new ARPDlg("GUI"));
		
		m_LayerMgr.ConnectLayers(" NI ( *Ethernet ( *ARP ( *IP ) *IP ( *Application ( *GUI ) ) ) )");
	}

	public ARPDlg(String pName) {
		pLayerName = pName;

		// Frame
		setTitle("ARP Test");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(250, 250, 770, 580);
		contentPane = new JPanel();
		((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		// ARP Cache Table GUI - START
		// ARP Cache Table panel
		JPanel arpPanel = new JPanel();
		arpPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "ARP Cache",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		arpPanel.setBounds(10, 5, 360, 310);
		contentPane.add(arpPanel);
		arpPanel.setLayout(null);

		// Cache Table Items panel
		JPanel arpCacheTablePanel = new JPanel();
		arpCacheTablePanel.setBounds(10, 15, 340, 210);
		arpPanel.add(arpCacheTablePanel);
		arpCacheTablePanel.setLayout(null);

		// Cache Table Items List
		model_arp = new DefaultListModel();
		list_arp_cache = new JList(model_arp);
		list_arp_cache.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);	// 하나만 선택가능하도록
		scroll_arp = new JScrollPane(list_arp_cache);	// make scrollable
		scroll_arp.setBorder(BorderFactory.createEmptyBorder(0,5,5,5));
		scroll_arp.setBounds(0, 0, 340, 210);
		arpCacheTablePanel.add(scroll_arp);

		// ARP Cache Item Manage Buttons panel
		JPanel arpCacheManageButtonPanel = new JPanel();
		arpCacheManageButtonPanel.setBounds(10, 230, 340, 30);
		arpPanel.add(arpCacheManageButtonPanel);
		arpCacheManageButtonPanel.setLayout(null);

		// Item Delete Button - arp cache
		Item_Delete_Button = new JButton("Item Delete");
		Item_Delete_Button.setBounds(70, 2, 100, 25);
		Item_Delete_Button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if(e.getSource() == Item_Delete_Button) {
					int selected_index = list_arp_cache.getSelectedIndex();
					if(selected_index < 0) {	// 선택된 항목이 없는 경우 예외처리
						if(model_arp.size() == 0) return;	// 아무것도 없는경우
						selected_index = 0;
					}
					String item = model_arp.getElementAt(selected_index).toString();
					ARPLayer.deleteARPEntry(item.substring(0,19).trim());	// IP주소만 잘라서 key로 전달
				}
			}
		});

		arpCacheManageButtonPanel.add(Item_Delete_Button);

		// All Delete Button - arp cache
		All_Delete_Button = new JButton("All Delete");
		All_Delete_Button.setBounds(180, 2, 100, 25);
		All_Delete_Button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if(e.getSource() == All_Delete_Button) {
					// TODO: 전체 항목 삭제 - DONE
					ARPLayer.deleteAllARPEntry();
				}
			}
		});
		arpCacheManageButtonPanel.add(All_Delete_Button);


		// target IP address input panel
		JPanel targetIPaddrInputPanel = new JPanel();
		targetIPaddrInputPanel.setBounds(10, 270, 340, 30);
		arpPanel.add(targetIPaddrInputPanel);
		targetIPaddrInputPanel.setLayout(null);

		// target IP address input label
		JLabel targetIPLabel = new JLabel("IP 주소");
		targetIPLabel.setBounds(0, 0, 50, 20);
		targetIPaddrInputPanel.add(targetIPLabel);

		// target IP address input textfield
		targetIPWrite = new JTextField();
		targetIPWrite.setBounds(50, 2, 200, 20);// 249
		targetIPaddrInputPanel.add(targetIPWrite);
		targetIPWrite.setColumns(10);

		// ARP Test Send Button
		ARP_send_Button = new JButton("Send");
		ARP_send_Button.setBounds(255, 2, 80, 20);
		ARP_send_Button.addActionListener(new sendButtonListener());
		targetIPaddrInputPanel.add(ARP_send_Button);

		// ARP Cache GUI - END

		// Source Address Setting GUI - START
		// Source Address Setting panel
		JPanel srcAddrSettingPanel = new JPanel();// file panel
		srcAddrSettingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Src Address Setting",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		srcAddrSettingPanel.setBounds(10, 330, 360, 190);
		contentPane.add(srcAddrSettingPanel);
		srcAddrSettingPanel.setLayout(null);

		JLabel NICLabel = new JLabel("NIC List");
		NICLabel.setBounds(10, 20, 170, 20);
		srcAddrSettingPanel.add(NICLabel);

		// NIC Combo Box
		NICComboBox = new JComboBox();
		NICComboBox.setBounds(10, 50, 170, 20);
		srcAddrSettingPanel.add(NICComboBox);

		lblsrcMAC = new JLabel("Source Mac Address");
		lblsrcMAC.setBounds(10, 80, 170, 20); //�쐞移� 吏��젙
		srcAddrSettingPanel.add(lblsrcMAC); //panel 異붽�

		srcMacAddress = new JTextArea();
		srcMacAddress.setBounds(10, 105, 170, 20);
		srcMacAddress.setBorder(BorderFactory.createLineBorder(Color.black));
		srcAddrSettingPanel.add(srcMacAddress);// src address

		lblsrcIP = new JLabel("Source IP Address");
		lblsrcIP.setBounds(10, 135, 190, 20);
		srcAddrSettingPanel.add(lblsrcIP);

		srcIPAddress = new JTextArea();
		srcIPAddress.setBounds(10, 160, 170, 20);
		srcIPAddress.setBorder(BorderFactory.createLineBorder(Color.black));
		srcAddrSettingPanel.add(srcIPAddress);// dst address

		Setting_Button = new JButton("Setting");// setting
		Setting_Button.setBounds(200, 105, 130, 20);
		Setting_Button.addActionListener(new setAddressListener());
		srcAddrSettingPanel.add(Setting_Button);// setting

		// NILayer로부터 랜카드 정보 가져오기
		NILayer tempNiLayer = (NILayer) m_LayerMgr.GetLayer("NI");

		for (int i = 0; i < tempNiLayer.getAdapterList().size(); i++) {
			PcapIf pcapIf = tempNiLayer.GetAdapterObject(i); //
			NICComboBox.addItem(pcapIf.getName());
		}

		NICComboBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				// adapterNumber = NICComboBox.getSelectedIndex();
				JComboBox jcombo = (JComboBox) e.getSource();
				adapterNumber = jcombo.getSelectedIndex();
				System.out.println("Index: " + adapterNumber);
				try {
					srcMacAddress.setText("");
					srcMacAddress.append(get_MacAddress(((NILayer) m_LayerMgr.GetLayer("NI"))
							.GetAdapterObject(adapterNumber).getHardwareAddress()));

				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
		});

		try {
			srcMacAddress.append(get_MacAddress(
					((NILayer) m_LayerMgr.GetLayer("NI")).GetAdapterObject(adapterNumber).getHardwareAddress()));
		} catch (IOException e1) {
			e1.printStackTrace();
		};

		// Source Address Setting GUI - END

		// Proxy ARP Entry GUI - START
		// Proxy ARP Entry panel
		JPanel proxyARPPanel = new JPanel();
		proxyARPPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Proxy ARP Entry",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		proxyARPPanel.setBounds(380, 5, 360, 280);
		contentPane.add(proxyARPPanel);
		proxyARPPanel.setLayout(null);

		// Proxy Entry Table panel
		JPanel proxyARPTablePanel = new JPanel();
		proxyARPTablePanel.setBounds(10, 15, 340, 210);
		proxyARPPanel.add(proxyARPTablePanel);
		proxyARPTablePanel.setLayout(null);

		// Proxy Entry Table Items List
		model_proxy = new DefaultListModel();
		list_proxy_arp = new JList(model_proxy);
		list_proxy_arp.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);	// 하나만 선택가능하도록
		scroll_proxy = new JScrollPane(list_proxy_arp);	// make scrollable
		scroll_proxy.setBorder(BorderFactory.createEmptyBorder(0,5,5,5));
		scroll_proxy.setBounds(0, 0, 340, 210);
		proxyARPTablePanel.add(scroll_proxy);

		// Proxy Entry Item Manage Buttons panel
		JPanel proxyManageButtonPanel = new JPanel();
		proxyManageButtonPanel.setBounds(10, 230, 340, 30);
		proxyARPPanel.add(proxyManageButtonPanel);
		proxyManageButtonPanel.setLayout(null);

		// Add Button - proxy
		Add_Button_Proxy = new JButton("Add");
		Add_Button_Proxy.setBounds(70, 2, 100, 25);
		addDialog = new AddProxyDialog(this, "Proxy ARP Entry 추가");	// 추가 dialog
		Add_Button_Proxy.addActionListener(new ActionListener () {
			// Proxy ARP Entry 추가 다이얼로그 띄우기
			@Override
			public void actionPerformed(ActionEvent e) {
				if (e.getSource() == Add_Button_Proxy) {
					addDialog.setVisible(true);
				}
			}
		});
		proxyManageButtonPanel.add(Add_Button_Proxy);

		// Delete Button - proxy
		Delete_Button_Proxy = new JButton("Delete");
		Delete_Button_Proxy.setBounds(180, 2, 100, 25);
		Delete_Button_Proxy.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO: Delete 버튼 클릭 이벤트 처리 - DONE
				if(e.getSource() == Delete_Button_Proxy) {
					// ARPLayer의 DeleteProxyEntry() 함수를 불러서 지움
					int selected_index = list_proxy_arp.getSelectedIndex();
					if(selected_index < 0) {	// 선택된 항목이 없는 경우 예외처리
						if(model_proxy.size() == 0) return;	// 아무것도 없는경우
						selected_index = 0;
					}
					String item = model_proxy.getElementAt(selected_index).toString();
					ARPLayer.deleteProxyEntry(item.substring(20,39).trim());	// IP주소만 잘라서 key로 전달
				}
			}
		});
		proxyManageButtonPanel.add(Delete_Button_Proxy);

		// Proxy ARP Entry GUI - END

		// Gratuitous ARP GUI - START
		JPanel gratARPPanel = new JPanel();
		gratARPPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Gratuitous ARP",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		gratARPPanel.setBounds(380, 290, 360, 60);
		contentPane.add(gratARPPanel);
		gratARPPanel.setLayout(null);

		JPanel gratInputPanel = new JPanel();
		gratInputPanel.setBounds(10, 20, 340, 30);
		gratARPPanel.add(gratInputPanel);
		gratInputPanel.setLayout(null);

		JLabel hwAddrLabel = new JLabel("H/W 주소");
		hwAddrLabel.setBounds(0, 0, 60, 20);
		gratInputPanel.add(hwAddrLabel);

		gratWrite = new JTextField();
		gratWrite.setBounds(65, 2, 170, 20);// 249
		gratInputPanel.add(gratWrite);
		gratWrite.setColumns(10);

		gratSendButton = new JButton("Send");
		gratSendButton.setBounds(245, 2, 80, 20);
		gratSendButton.addActionListener(new sendButtonListener());
		gratInputPanel.add(gratSendButton);

		// Gratuitous ARP GUI - END

		// DON'T DELETE THIS
		setVisible(true);
	}

	class AddProxyDialog extends JDialog {
		JLabel DeviceLabel = new JLabel("Device");
		JLabel HostIPLabel = new JLabel("IP 주소");
		JLabel HostEthernetLabel = new JLabel("Ethernet 주소");
		JTextField d_tf = new JTextField();	// device tf
		JTextField ip_tf = new JTextField();	// ip tf
		JTextField e_tf = new JTextField();	// ethernet tf
		JButton OKButton;

		public AddProxyDialog(JFrame frame, String title) {
			super(frame, title);
			this.setLocationRelativeTo(frame);
			JPanel jp = new JPanel();

			JPanel subpanel = new JPanel();
			subpanel.add(DeviceLabel);
			subpanel.add(d_tf);
			subpanel.add(HostIPLabel);
			subpanel.add(ip_tf);
			subpanel.add(HostEthernetLabel);
			subpanel.add(e_tf);
			subpanel.setLayout(new GridLayout(3,2));

			BorderLayout bl = new BorderLayout();
			jp.setLayout(bl);
			jp.add(subpanel, BorderLayout.NORTH);
			OKButton = new JButton("OK");
			jp.add(OKButton, BorderLayout.SOUTH);


			add(jp);
			setSize(400, 150);
			setDefaultCloseOperation(DISPOSE_ON_CLOSE);

			OKButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					// TODO: 입력받은 정보를 Proxy Entry 리스트에 추가 후 창을 닫음
					String hostName = d_tf.getText();
					String hostIP = ip_tf.getText();
					String hostEthernet = e_tf.getText();

					// hostEthernet의 :를 빼고 byte배열로 변환
					String[] byte_mac = hostEthernet.split(":|-");
					byte[] hostMac = new byte[6];
					for (int i = 0; i < 6; i++) {
						hostMac[i] = (byte) Integer.parseInt(byte_mac[i], 16);
					}
					// ARPLayer의 Proxy Entry 테이블에 추가하도록 함
					ARPLayer.addProxyEntry(hostName, hostIP, hostMac);

					d_tf.setText("");
					ip_tf.setText("");
					e_tf.setText("");
					setVisible(false);	// 창 닫기
				}
			});
		}
	}


	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {

			if (e.getSource() == Setting_Button) { // Setting 버튼 클릭 이벤트 처리
				// TODO: Setting 버튼 클릭 이벤트 처리
				byte[] srcMAC = new byte[6];
				byte[] srcIP = new byte[4];

				String mac = srcMacAddress.getText();
				String ip = srcIPAddress.getText();

				String[] byte_mac = mac.split("-|:");
				for (int i = 0; i < 6; i++) {
					srcMAC[i] = (byte) Integer.parseInt(byte_mac[i], 16);
				}

				String[] byte_ip = ip.split("\\.");
				for (int i = 0; i < 4; i++) {
					srcIP[i] = (byte) Integer.parseInt(byte_ip[i], 10);
				}

				// 하위 레이어에 srcIP, srcMac 헤더 세팅
				((IPLayer) m_LayerMgr.GetLayer("IP")).SetSrcIPAddress(srcIP);
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetSrcMacAddress(srcMAC);
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetSrcIPAddress(srcIP);
				((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetSrcAddress(srcMAC);

				((NILayer) m_LayerMgr.GetLayer("NI")).SetAdapterNumber(adapterNumber);

				System.out.println("Source ip, mac Set");
			}
		}
	}

	class sendButtonListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if (e.getSource() == ARP_send_Button) { // ARP Send 버튼 클릭 이벤트 처리
				// ARP Send 버튼 클릭 이벤트 처리 1 - ARP Cache Table Update
				// ARPLayer에서 GUI Window update 함수 호출하는 것으로 대체

				// TODO: ARP Send 버튼 클릭 이벤트 처리 2 - 패킷 전송(Send) 구현
				String dstIP = targetIPWrite.getText();

				byte[] dstIP_bytearr = new byte[4];
				String[] byte_ip = dstIP.split("\\.");
				for (int i = 0; i < 4; i++) {
					dstIP_bytearr[i] = (byte) Integer.parseInt(byte_ip[i], 10);
				}
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetDstIPAddress(dstIP_bytearr);

				// AppLayer로 전송
				String input = "";	// data
				byte[] bytes = input.getBytes();
				((ApplicationLayer) m_LayerMgr.GetLayer("Application")).Send(bytes, bytes.length, dstIP);
			}

			if (e.getSource() == gratSendButton) { // gratuitous ARP Send 버튼 클릭 이벤트 처리
				// TODO: gratuitous ARP Send 버튼 클릭 이벤트 처리 - 패킷 전송(Send) 구현
				byte[] srcMAC = new byte[6];
				String mac = gratWrite.getText();
				
				String[] byte_mac = mac.split("-|:");
				for (int i = 0; i < 6; i++) {
					srcMAC[i] = (byte) Integer.parseInt(byte_mac[i], 16);
				}
				
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetSrcMacAddress(srcMAC);
				((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetSrcAddress(srcMAC);
				
				((ApplicationLayer) m_LayerMgr.GetLayer("Application")).GARP_Send();
			}
		}

	}

	public String get_MacAddress(byte[] byte_MacAddress) { //MAC Byte二쇱냼瑜� String�쑝濡� 蹂��솚
		String MacAddress = "";
		for (int i = 0; i < 6; i++) { 
			//2�옄由� 16吏꾩닔瑜� ��臾몄옄濡�, 洹몃━怨� 1�옄由� 16吏꾩닔�뒗 �븵�뿉 0�쓣 遺숈엫.
			MacAddress += String.format("%02X%s", byte_MacAddress[i], (i < MacAddress.length() - 1) ? "" : "");
			
			if (i != 5) {
				//2�옄由� 16吏꾩닔 �옄由� �떒�쐞 �뮘�뿉 "-"遺숈뿬二쇨린
				MacAddress += "-";
			}
		} 
		System.out.println("mac_address:" + MacAddress);
		return MacAddress;
	}

	public boolean Receive(byte[] input) { //硫붿떆吏� Receive
		// TODO: Receive 구현
		return true;
	}

	// GUI의 ARPCacheEntryWindow를 업데이트하는 함수
	public static void UpdateARPCacheEntryWindow(Hashtable<String, ARPLayer._ARP_Cache_Entry> table) {
		model_arp.removeAllElements();
		if(table.size() > 0) {
			for(Map.Entry<String, ARPLayer._ARP_Cache_Entry> e : table.entrySet()) {
				String targetIP = e.getKey();	// 타겟 IP 주소
				if(targetIP == null || targetIP.length() == 0)	return;

				String macAddr_string = "";
				byte[] macAddr_bytearray = e.getValue().addr;	// mac 주소
				if(macAddr_bytearray == null || macAddr_bytearray.length == 0) {
					// mac 주소 모르는 경우
					macAddr_string = "????????????";
				} else {
					// mac 주소 아는 경우=
					// : 붙이기
					macAddr_string += String.format("%02X", (0xFF & macAddr_bytearray[0])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[1])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[2])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[3])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[4])) + ":"
							+ String.format("%02X", (0xFF & macAddr_bytearray[5]));
				}

				String status = e.getValue().status? "complete" : "incomplete";		// status 정보

				// Window에 표시될 최종 정보
				String itemText = String.format("%-20s %-20s %-20s", targetIP, macAddr_string, status);

				model_arp.addElement(itemText);
			}
		}
	}

	// GUI의 ProxyEntryWindow를 업데이트하는 함수
	public static void UpdateProxyEntryWindow(Hashtable<String, ARPLayer._Proxy_Entry> table) {
		model_proxy.removeAllElements();
		if(table.size() > 0) {
			for(Map.Entry<String, ARPLayer._Proxy_Entry> e : table.entrySet()) {
				String ipAddr = e.getKey();	// IP 주소
				if(ipAddr == null || ipAddr.length() == 0)	return;

				String hostName = e.getValue().hostName;

				String macAddr_string = "";
				byte[] macAddr_bytearray = e.getValue().addr;	// mac 주소
				// : 붙이기
				macAddr_string += String.format("%02X", (0xFF & macAddr_bytearray[0])) + ":"
						+ String.format("%02X", (0xFF & macAddr_bytearray[1])) + ":"
						+ String.format("%02X", (0xFF & macAddr_bytearray[2])) + ":"
						+ String.format("%02X", (0xFF & macAddr_bytearray[3])) + ":"
						+ String.format("%02X", (0xFF & macAddr_bytearray[4])) + ":"
						+ String.format("%02X", (0xFF & macAddr_bytearray[5]));

				// Window에 표시될 최종 정보
				String itemText = String.format("%-20s %-20s %-20s", hostName, ipAddr, macAddr_string);

				model_proxy.addElement(itemText);
			}
		}
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
		// nUpperLayerCount++;
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
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);

	}

}
