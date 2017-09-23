package pktanalyzer;
import java.io.IOException;
import java.net.InetAddress;

public class Parser {
	
	/** the input device */
	private java.io.InputStream reader;
	
	/** the current text position in the buffer */
	private int currentPos;

	/**
	 * endRead marks the last character in the buffer, that has been read from
	 * input
	 */
	private int endRead;
	
	/** initial size of the lookahead buffer */
	private static final int BUFFERSIZE = 16384;
	
	private byte buffer[] = new byte[BUFFERSIZE];
	
	/**
	 * Creates a new scanner
	 *
	 * @param in the java.io.Reader to read input from.
	 */
	public Parser(java.io.InputStream in) {
		this.reader = in;
	}
	
	
	public void parse(){		
		try{
			parseEtherHeader();
		} catch(Exception e){
			e.printStackTrace();
		}
	}
	
	public byte nextByte() throws IOException {
				
		if (currentPos <= endRead && endRead != 0) {
			return buffer[currentPos++];
		} else {
			currentPos = 0;
			endRead = 0;		
			boolean eof = refill();
			
			if (eof) {
				return 0;
			} else {
				return buffer[currentPos++];
			}	
		}		
	}
	
	public boolean refill() throws IOException {

		/* fill the buffer with new input */
		int requested = buffer.length - endRead;
		
		if (requested <= 0) {
			/* no space to refill*/
			return false;
		}
		
		int numRead = reader.read(buffer, endRead, requested);
		if (numRead == 0) {
			throw new java.io.IOException("Reader returned 0 characters.");
		}

		if (numRead > 0) {
			endRead += numRead;
			/* potentially more input available */
			return false;
		}

		/* numRead < 0 ==> end of stream */
		return true;

	}
	
	public void parseIpHeader() throws IOException {
		String version_ihl = byteToHex(nextByte());
		String version = version_ihl.substring(0, 1);
		int ihl_bytes = Integer.parseInt(version_ihl.substring(1)) * 4;

		byte btypeOfService = nextByte();
		String typeOfService = "0x" + byteToHex(btypeOfService);
		int precedence = (btypeOfService & 0xE0) >> 5;
		int delay = (btypeOfService & 0x10) >> 4;
		int throughput = (btypeOfService & 0x08) >> 3;
		int reliability = (btypeOfService & 0x04) >> 2;
		
		int totalLength = parseInt(2); 
		int indentification = parseInt(2); 
		
		byte bFlags = nextByte();
		String flags = "0x" + byteToHex((byte) ((bFlags & 0xE0)>> 5));
		int controlFlag1 = (bFlags & 0x40) >> 6;
		int controlFlag2 = (bFlags & 0x20) >> 5;
		
		int fragmentOffset = bFlags & 0x1F;
		fragmentOffset <<= 8;
		fragmentOffset |= (nextByte() & 0xFF); 
		
		int ttl = nextByte() & 0xFF;
		int protocol = nextByte() & 0xFF;
		
		String checksum = "0x" + byteToHex(nextByte()) +  byteToHex(nextByte());
		String srcAddress = parseIPAddr();
		String destAddress = parseIPAddr();
		
		InetAddress srcaddr = InetAddress.getByName(srcAddress);
		String srchost = srcaddr.getHostName();
		
		InetAddress destaddr = InetAddress.getByName(destAddress);
		String desthost = destaddr.getHostName();
		
		StringBuilder sb = new StringBuilder();
		
		sb.append("IP:   ----- IP Header ----- " + "\n");
		sb.append("IP: " + "\n");
		sb.append("IP:   Header length = " + ihl_bytes + " bytes" + "\n");
		sb.append("IP:   Version = " + version + "\n");
		sb.append("IP:   Type of service = " + typeOfService + "\n");
		sb.append("IP:         xxx. .... = " + precedence + " (precedence)" + "\n");
		sb.append("IP:         ..." + delay + " .... = normal delay" + "\n");
		sb.append("IP:         .... " + throughput + "... = normal throughput" + "\n");
		sb.append("IP:         .... ." + reliability + ".. = normal reliability" + "\n");
		sb.append("IP:   Total length = " + totalLength + " bytes" + "\n");
		sb.append("IP:   Identification = " + indentification + "\n");
		sb.append("IP:   Flags = " + flags + "\n");
		sb.append("IP:         ." + controlFlag1 + ".. .... = do not fragment" + "\n");
		sb.append("IP:         .." + controlFlag2 + ". .... = last fragment" + "\n");
		sb.append("IP:   Fragment offset = "+ fragmentOffset +" bytes" + "\n");
		sb.append("IP:   Time to live = " + ttl + " seconds/hops" + "\n");
		sb.append("IP:   Protocol = " + protocol + protoStr(protocol) + "\n");
		sb.append("IP:   Header checksum = " + checksum + "\n");
		sb.append("IP:   Source address = " + srcAddress + ", " + srchost + "\n");
		sb.append("IP:   Destination address = " + destAddress + ", " + desthost + "\n");
		sb.append("IP:   No options " + "\n");
		sb.append("IP: " + "\n");
		
		System.out.print(sb.toString());
			
		switch(protocol) {
			case 1: parseICMP(); break; 
			case 17: parseUDP(); break;
			case 6: parseTCP(); break;
			default:  break;
		}
	}
	
	public String protoStr(int protocol) {
		switch(protocol) {
			case 1: return "(ICMP)"; 
			case 17: return "(UDP)";
			case 6: return "(TCP)";
			default: return "";				
		}
	}
	
	
	public void parseEtherHeader() throws IOException{
		String dest = parseMacAddr();
		String src = parseMacAddr();
		String type = "0x"+ byteToHex(nextByte()) + byteToHex(nextByte());
		
		System.out.println("ETHER:  ----- Ether Header -----");
		System.out.println("ETHER:");
		System.out.println("ETHER:  Destination = "+dest+", ");
		System.out.println("ETHER:  Source      = "+src+",");
		System.out.println("ETHER:  Ethertype = " + type);		
		System.out.println("ETHER:");
		
		if ("0x0800".equals(type)) {
			parseIpHeader();
		}				
	}
	
	public void parseTCP() throws IOException {
		int srcPort = parseInt(2);
		int destPort = parseInt(2);
		long seqNumber = parseLong(4);		
		long ackNumber = parseLong(4);
				
		byte offset_flags = nextByte(); 
		int dataOffset = (offset_flags & 0xF0) >> 4;
		dataOffset *= 4;
		
		byte bFlags = nextByte();
		String flags = "0x" + byteToHex(bFlags);
		int urg = (bFlags & 0x20) >> 5;
		int ack = (bFlags & 0x10) >> 4;
		int psh = (bFlags & 0x08) >> 3;
		int rst = (bFlags & 0x04) >> 2;
		int syn = (bFlags & 0x02) >> 1;
		int fin = bFlags & 0x01;
		
		int window = parseInt(2);
		String checksum = "0x" + byteToHex(nextByte()) + byteToHex(nextByte());
		
		int urgentPointer = parseInt(2);
		StringBuilder sb = new StringBuilder();
		
		sb.append("TCP:  ----- TCP Header ----- " + "\n");
		sb.append("TCP:  Source port = " + srcPort + "\n");
		sb.append("TCP:  Destination port = "+destPort + "\n");
		sb.append("TCP:  Sequence number = " + seqNumber + "\n");
		sb.append("TCP:  Acknowledgement number = " + ackNumber + "\n");
		sb.append("TCP:  Data offset = "+dataOffset+" bytes" + "\n");
		sb.append("TCP:  Flags = " + flags + "\n");
		sb.append("TCP:        .."+urg+". .... = urgent pointer" + "\n");
		sb.append("TCP:        ..."+ack+" .... = Acknowledgement" + "\n");
		sb.append("TCP:        .... "+psh+"... = Push" + "\n");
		sb.append("TCP:        .... ."+rst+".. = reset" + "\n");
		sb.append("TCP:        .... .."+syn+". = Syn" + "\n");
		sb.append("TCP:        .... ..."+fin+" = Fin" + "\n");
		sb.append("TCP:  Window = " + window + "\n");
		sb.append("TCP:  Checksum = " + checksum + "\n");
		sb.append("TCP:  Urgent pointer = " + urgentPointer + "\n");
		sb.append("TCP:  No options" + "\n");
		sb.append("TCP:" + "\n");
		sb.append("TCP:  Data: (first 64 bytes)" + "\n");
		sb.append("TCP: " + parseData() + "\n");
		sb.append("TCP: " + parseData() + "\n");
		sb.append("TCP: " + parseData() + "\n");
		sb.append("TCP: " + parseData() + "\n");
		System.out.println(sb.toString());
	}
	
	
	public void parseUDP() throws IOException{
		int srcPort = parseInt(2);		
		int destPort = parseInt(2);
		int length = parseInt(2);
		String checksum = byteToHex(nextByte()) + byteToHex(nextByte());
		
		System.out.println("UDP:  ----- UDP Header ----- ");
		System.out.println("UDP:");
		System.out.println("UDP:  Source port = " + srcPort);
		System.out.println("UDP:  Destination port = " + destPort);
		System.out.println("UDP:  Length = " + length);
		System.out.println("UDP:  Checksum = " + checksum);
		System.out.println("UDP:");
		System.out.println("UDP:  Data: (first 64 bytes)");
		System.out.println("UDP:  " + parseData());
		System.out.println("UDP:  " + parseData());
		System.out.println("UDP:  " + parseData());
		System.out.println("UDP:  " + parseData());
		
	}
	
	public void parseICMP() throws IOException {
		int type = parseInt(1); 
		int code = parseInt(1);
		String checksum = byteToHex(nextByte()) + byteToHex(nextByte());
		
		System.out.println("ICMP:  ----- ICMP Header -----");
		System.out.println("ICMP:");
		System.out.println("ICMP:  Type = " + type);
		System.out.println("ICMP:  Code = " + code);
		System.out.println("ICMP:  Checksum = " + checksum);
		System.out.println("ICMP:");
	}
	
	public String parseData() throws IOException {
		StringBuilder sb = new StringBuilder();
		StringBuilder sb2 = new StringBuilder();
			for (int i = 0; i < 8; i++) {
				byte b1 = nextByte();
				byte b2 = nextByte();
				sb.append(byteToHex(b1));
				sb.append(byteToHex(b2));
				sb.append(" ");
				
				sb2.append(byteToAscii(b1));
				sb2.append(byteToAscii(b2));
			}	
		return sb.toString() + "\t" + sb2.toString();
	}
	
	public String parseIPAddr() throws IOException {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 3; i++) {
			sb.append(nextByte() & 0xFF);
			sb.append(".");
		}
		sb.append(nextByte() & 0xFF);
		return sb.toString();
	}
	
	public String parseMacAddr() throws IOException {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 5; i++) {
			sb.append(byteToHex(nextByte()));
			sb.append(":");
		}
		sb.append(byteToHex(nextByte()));
		return sb.toString();
	}
	
	public String byteToHex(byte data) {
		return String.format("%02x", data & 0xFF);
	}
	
	public String byteToAscii(byte data) {
		int ascii = data & 0xFF;
		if (ascii >= 0 && ascii <= 127 && ascii != 10)
			return "" + (char)ascii;
		else 
			return ".";
	}
	
	public int parseInt(int bytes) throws IOException {
		int data = 0;
		for (int i = 0; i < bytes; i++) {
			data <<= 8;
			data |=  (nextByte() & 0xFF);			
		}
		return data;
	}	
	
	public long parseLong(int bytes) throws IOException {
		long data = 0;
		for (int i = 0; i < bytes; i++) {
			data <<= 8;
			data |=  (nextByte() & 0xFF);			
		}
		return data;
	}	
}
