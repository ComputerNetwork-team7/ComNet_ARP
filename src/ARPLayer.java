public class ARPLayer implements BaseLayer{
        private class _ARP_HEADER {
            byte[] macType;								// Hardware Type
            byte[] ipType;								// Protocol Type
            byte macAddrLen;							// Length of hardware Address
            byte ipAddrLen;								// Length of protocol Address
            byte[] opcode;								// Opcode (ARP Request)
            _ETHERNET_ADDR srcMac;						// Sender's hardware Address
            _IP_ADDR srcIp;								// Sender's protocol Address
            _ETHERNET_ADDR dstMac;						// Target's hardware Address
            _IP_ADDR dstIp;								// Target's protocol Address
            
            public _ARP_HEADER() {						// 28 Bytes
                this.macType = new byte[2];				// 2 Bytes / 0 ~ 1
                this.ipType = new byte[2];				// 2 Bytes / 2 ~ 3
                this.macAddrLen = (byte) 0x00;			// 1 Byte  / 4
                this.ipAddrLen = (byte) 0x00;			// 1 Byte  / 5
                this.opcode = new byte[2];				// 2 Bytes / 6 ~ 7 
                this.srcMac = new ETHERNET_ADDR();		// 6 Bytes / 8 ~ 13 
                this.srcIp = new IP_ADDR();			// 4 Bytes / 14 ~ 17
                this.dstMac = new ETHERNET_ADDR();		// 6 Bytes / 18 ~ 23
                this.dstIp = new IP_ADDR();			// 4 Bytes / 24 ~ 27
            }
        }

        public static class _ARP_Cache_Entry{    
            byte[] addr;
            String status;
            String arp_interface;
            //ARP Cache Entry
            public _ARPCache_Entry(byte[] addr, String status, String arp_interface){
                this.addr = addr;
                this.status = status;
                this.arp_interface = arp_interface;
            }
        }
        //Proxy ARP Entry
        public static class _Proxy_Entry{
            String hostName;
            byte[] addr;

            public _Proxy_Entry(byte[] addr, String hostName){
                this.hostName = hostName;
                this.addr = addr;
            }
        }

        private void ResetHeader(){
                m_sHeader = new ARP_HEADER();
        }

        public ARPLayer(String Name){
            pLayerName = pName;
            ResetHeader();    
        }
        
        // 각 Port의 mac Address와 Ip Address 저장하는 함수
        public void initAddress() {
            String port0_mac = NILayer.getMacAddress(0);
            String port1_mac = NILayer.getMacAddress(1);
            myMacAddress[0] = Translator.macToByte(port0_mac);
            myMacAddress[1] = Translator.macToByte(port1_mac);
            
            String port0_ip = NILayer.getIpAddress(0);
            String port1_ip = NILayer.getIpAddress(1);
            myIpAddress[0] = Translator.ipToByte(port0_ip);
            myIpAddress[1] = Translator.ipToByte(port1_ip);
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
    }