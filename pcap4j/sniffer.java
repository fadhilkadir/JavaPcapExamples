/*
by fk (24/08/19)

to run: sudo java -cp jars/pcap4j-core.jar:jars/pcap4j-packetfactory-static.jar:jars/jna-5.4.0.jar:jars/slf4j-api-1.7.28.jar: sniffer

*/


import com.sun.jna.Platform;
import java.io.IOException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class sniffer {

	private static final String NIF_NAME_KEY = sniffer.class.getName() + ".nifName";
	private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);
	
	
	private static final String BUFFER_SIZE_KEY = sniffer.class.getName() + ".bufferSize";
	private static final int BUFFER_SIZE = Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]
	
	
	private static final String READ_TIMEOUT_KEY = sniffer.class.getName() + ".readTimeout";
	private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]
	
	private static final String SNAPLEN_KEY = sniffer.class.getName() + ".snaplen";
	private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]
	
	
	private static final String TIMESTAMP_PRECISION_NANO_KEY = sniffer.class.getName() + ".timestampPrecision.nano";
	private static final boolean TIMESTAMP_PRECISION_NANO = Boolean.getBoolean(TIMESTAMP_PRECISION_NANO_KEY);
	
	
	private static final String COUNT_KEY = sniffer.class.getName() + ".count";
	private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);
	
	
	//set filter
	/*
	private static String protocol = "http";
	private static String FILTER = "tcp port " + protocol + " and dst ";
	*/
	
	public static void main(String[] args) throws PcapNativeException, NotOpenException {
		String filter = args.length != 0 ? args[0] : "";

		PcapNetworkInterface nif;
		if (NIF_NAME != null) {
		    nif = Pcaps.getDevByName(NIF_NAME);
		    } else {
      			try {
			        nif = new NifSelector().selectNetworkInterface();
			      } catch (IOException e) {
				        e.printStackTrace();
				        return;
			      }

      			if (nif == null) {
        		return;
      			}
    		}
		String ipaddress = "";
		System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
    		for (PcapAddress addr : nif.getAddresses()) {
		      if (addr.getAddress() != null) {
		      		if(ipaddress.equals("")){
			      		ipaddress = "" + addr.getAddress();
			      		ipaddress = ipaddress.substring(1);
				        System.out.println("IP address:1 " + ipaddress);
				    }
				    else{
				    	System.out.println("IP address:2 " + addr.getAddress());
				    }
				     
		      }
    		}
   		System.out.println("");
   		
		final PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

		//to set filter
		//filter = FILTER + ipaddress;
		//System.out.println(filter);
	    handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

		System.out.println("Capturing packets...");
		
		PacketHandler listener = new PacketHandler();
		try {
				handle.loop(-1,listener);
		}	catch (InterruptedException e) {
				e.printStackTrace();
		}
		
		handle.close();
	}

}

class PacketHandler implements PacketListener {

	int pktC = 0;
	@Override
	public void gotPacket(Packet packet) {
        System.out.println(packet);
        pktC++;
        System.out.println("Total packets: " + pktC + "\n");
    }


}



