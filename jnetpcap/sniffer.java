/*
 sniffer.java
 by
 fk
 
 run: java sniffer <interface>
 
 eg:  java sniffer eth0
 
 To be set:
 
 sniffer
  x - filter and protocol
  for eg.
  String protocol = "http";
  String FILTER = "tcp port 80 and dst ";
  
  
 */


import java.util.ArrayList;  
import java.util.Date;  
import java.util.List;  
import java.sql.Timestamp;

import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapIf;  
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.PcapHeader;
import java.net.Inet4Address;
import java.net.InetAddress;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapSockAddr;

import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.nio.JBuffer;  
import org.jnetpcap.nio.JMemory;  
import org.jnetpcap.packet.PcapPacketHandler;  

import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Http;

import org.jnetpcap.packet.format.FormatUtils;


//import java.io.File;
//import java.io.FileWriter;
//import java.io.IOException;

public class sniffer {  
  
  private static List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs 
  private static int i;
  private static StringBuilder errbuf = new StringBuilder(); // For any error msgs
  //private static String FILTER = "tcp port 80 and dst "; //to set filter
  public static String ipDev;
  public static PcapIf device;


  public static void main(String[] args) {  
    
    /*************************************************************************** 
      * First get a list of devices on this system 
      **************************************************************************/  
    int r = Pcap.findAllDevs(alldevs, errbuf);  
    if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
      System.err.printf("Can't read list of devices, error is %s", errbuf  
                          .toString());  
      return;  
    }  
    try {
      if(args.length > 0){
        sniffer test = new sniffer(args[0]);
      } else {
        System.out.println("Usage: java sniffer [device name]");
        System.out.println("Available network devices on your machine:");
        i = 0;  
        for (PcapIf device : alldevs) {  
          String description =  
            (device.getDescription() != null) ? device.getDescription()  
            : "No description available";  
          System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
        }  
      }
    } catch(Exception e) {
      e.printStackTrace();
    }  
    
  }  
	/* //if mac enabled
  private static String asString(final byte[] mac) {  
    final StringBuilder buf = new StringBuilder();  
    for (byte b : mac) {  
      if (buf.length() != 0) {  
        buf.append(':');  
      }  
      if (b >= 0 && b < 16) {  
        buf.append('0');  
      }  
      buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());  
    }  
    
    return buf.toString();  
  }  
  */
  
  private int octet(byte b) {
    return (b >= 0) ? b : b + 256;
  }
  
  
  
  public sniffer(String selection){ 
    int index = deviceIndex(selection);
    //System.out.println(index);
    
    device = alldevs.get(index);
    System.out.println("Using device: " + device.getName());
		/* //if mac enabled
    try{
      final byte[] mac = device.getHardwareAddress();
      //String mac = new String(device.getHardwareAddress());
      System.out.println("Mac: " + asString(mac));
    }
    catch(Exception e){
      
    }
    	*/
    List<PcapAddr> addresses = device.getAddresses();
    
    for(PcapAddr address : addresses){
      //System.out.println(InetAddress.getByAddress(address.getAddr()));
      if (address.getAddr().getFamily() == PcapSockAddr.AF_INET) {
        byte[] ipadd = address.getAddr().getData();
        //String lala = new String(address.getAddr().getData());
        ipDev = octet(ipadd[0]) + "." + octet(ipadd[1]) + "." + octet(ipadd[2])
          + "." + octet(ipadd[3]);
        System.out.println(ipDev);
        //FILTER += ipDev; //if filter set
      }    
    }
    
    
    /*************************************************************************** 
      * Second we open up the selected device 
      **************************************************************************/  
    
    int snaplen = 64 * 1024;           // Capture all packets, no trucation  
    int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
    int timeout = 10 * 1000;           // 10 seconds in millispcap: get Ip address of machine  
    Pcap pcap =  
      Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf); 
    
    if (pcap == null) {  
      System.err.printf("Error while opening device for capture: "  
                          + errbuf.toString());  
      return;  
    }  
    /*
    PcapBpfProgram filter = new PcapBpfProgram();
    //String expression = "port 80";
    int optimize = 0; // 1 means true, 0 means false
    int netmask = 0;
    System.out.println("Setting capture filter to: " + FILTER);
    int f = pcap.compile(filter, FILTER, optimize, netmask);
    if (f != Pcap.OK) {
      System.out.println("Filter error: " + pcap.getErr());
    }
    
    pcap.setFilter(filter); // if filterset
    */
    jpHandler jph = new jpHandler(ipDev);
    
    System.out.println("Capturing packets...");
    pcap.loop(-1, jph, "jNetTest");  
    
    pcap.close();  
    
    
  }
  
  public int deviceIndex(String selection){
    int index = 0;
    for (int j = 0; j < alldevs.size(); j++) {
      if(alldevs.get(j).getName().equals(selection)){
        index = j;
      }
    }
    return index;
  }
  

}

class jpHandler implements PcapPacketHandler<String>{

  int pktC = 0;
  private String ip;
  private int reqGetCount;
  private int completeGet;
  Http http = new Http();
  public jpHandler(String ip){
    this.ip = ip;
    reqGetCount = 0;
    completeGet = 0;
  }
  
  //public void nextPacket(PcapHeader header, JBuffer buffer, String user) {  
  public void nextPacket(PcapPacket packet, String user) {  
    checkPacket(packet);
    
	/*
    System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n", new Date(packet.getCaptureHeader().timestampInMillis()), // Length actually captured
            packet.getCaptureHeader().caplen(), // Original length
            packet.getCaptureHeader().wirelen(), // User supplied object
            user);
	*/
    
  } 
  public void checkPacket(PcapPacket packet){
    pktC++;
    System.out.println("Total packets: " + pktC);
    System.out.println(packet.toString());

    
  }
  
}
