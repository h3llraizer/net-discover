//Native socket libraries - not strictly needed in this implementation with PcapPlusPlus
//#include <winsock2.h>  // Must be first
//#include <ws2tcpip.h>  // Optional, for modern networking functions

// PcapPlusPlus Library
#include "PcapLiveDeviceList.h"
#include "PcapLiveDevice.h" 
#include "RawPacket.h"
#include "Packet.h"

#include "NetworkUtils.h"
#include "EthLayer.h"
#include "MacAddress.h"

#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "DhcpLayer.h"
#include "DnsLayer.h"

#include "PayloadLayer.h"
#include "Layer.h"

#include "Logger.h"

// Standard Library
#include <iostream>
#include <stdexcept>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip> // for std::put_time
#include <thread>
#include <map>
#include <string>

std::string getCurrentTime()
{
	// std::cout << getCurrentTime() << std::endl;

	// 1. Get current system time
	auto now = std::chrono::system_clock::now();

	// 2. Convert to time_t
	std::time_t t = std::chrono::system_clock::to_time_t(now);

	// 3. Convert to local time
	std::tm localTime;
	localtime_s(&localTime, &t); // Windows-safe version

	// 4. Format into string
	std::ostringstream oss;
	oss << std::put_time(&localTime, "%d/%m/%Y:%H:%M:%S");

	return oss.str(); // return formatted string
}

class DHCP {
private:
	std::string localIp_;
	pcpp::PcapLiveDevice* device;

	pcpp::MacAddress localMac;

public:
	DHCP(std::string localIp) : localIp_(localIp)
	{
		device = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(localIp);
		if (!device || !device->open())
		{
			throw std::runtime_error("Failed to open device.\n");
		}

		std::cout << "Opened device " << device->getName() << "\n" << std::endl;

		localMac = device->getMacAddress();
	}

	void Discover()
	{
		pcpp::MacAddress dstMac = ("FF:FF:FF:FF:FF:FF");

		pcpp::EthLayer ethLayer(
			localMac,
			dstMac,
			PCPP_ETHERTYPE_IP
		);

		pcpp::IPv4Address srcIp("0.0.0.0");
		pcpp::IPv4Address dstIp("255.255.255.255");
		pcpp::IPv4Layer ipLayer(srcIp, dstIp);

		ipLayer.getIPv4Header()->protocol = pcpp::PACKETPP_IPPROTO_UDP;
		ipLayer.getIPv4Header()->timeToLive = 64;

		pcpp::UdpLayer udpLayer(68, 67); // DHCP client -> server ports


		pcpp::DhcpLayer dhcpLayer;
		dhcpLayer.getDhcpHeader()->opCode = pcpp::DHCP_DISCOVER;
		dhcpLayer.getDhcpHeader()->hardwareType = pcpp::LINKTYPE_ETHERNET;
		dhcpLayer.getDhcpHeader()->hardwareAddressLength = 6;
		dhcpLayer.getDhcpHeader()->hops = 0;
		dhcpLayer.getDhcpHeader()->transactionID = htonl(rand());
		dhcpLayer.getDhcpHeader()->flags = htons(0x8000); // broadcast flag

		localMac.copyTo(dhcpLayer.getDhcpHeader()->clientHardwareAddress, 6);

		uint8_t msgType = pcpp::DHCP_DISCOVER;

		dhcpLayer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_MESSAGE_TYPE, msgType));

		uint8_t params[] = { 1, 3, 6, 15 }; // subnet mask, router, DNS, domain name
		dhcpLayer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST, params));

		dhcpLayer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_OPTION_PANA_AGENT, nullptr, 0));

		dhcpLayer.setMessageType(pcpp::DHCP_DISCOVER);

		// attempt to calculate the size of the packet for the pcpp::Packet constructor

		pcpp::Packet packet(512);

		packet.addLayer(&ethLayer);
		packet.addLayer(&ipLayer);
		packet.addLayer(&udpLayer);
		packet.addLayer(&dhcpLayer);
		packet.computeCalculateFields();


		if (!device->sendPacket(packet, false))
		{
			std::cerr << "Failed to send DHCP Discover" << std::endl;
		}

		else
		{
			std::cout << "DHCP Discover sent successfully" << std::endl;
		}
	}

	void Release()
	{
		pcpp::IPv4Address clientIp("192.168.1.230");
		pcpp::MacAddress serverMac("38:06:E6:92:63:AC");
		pcpp::IPv4Address serverIp("192.168.1.254");
		pcpp::DhcpLayer dhcpLayer;
		dhcpLayer.setMessageType(pcpp::DHCP_RELEASE);
		//dhcpLayer.setClientHardwareAddress(clientMac);


		//pcpp::MacAddress spoofedMac = ("0A:FC:65:31:2C:96");

		localMac.copyTo(dhcpLayer.getDhcpHeader()->clientHardwareAddress, 6);

		dhcpLayer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER, serverIp));

		pcpp::EthLayer ethLayer(localMac, serverMac, PCPP_ETHERTYPE_IP);
		pcpp::IPv4Layer ipLayer(clientIp, serverIp);
		pcpp::UdpLayer udpLayer(68, 67);

		pcpp::Packet packet;
		packet.addLayer(&ethLayer);
		packet.addLayer(&ipLayer);
		packet.addLayer(&udpLayer);
		packet.addLayer(&dhcpLayer);

		if (!device->sendPacket(packet, false))
		{
			std::cerr << "Failed to send DHCP Release" << std::endl;
		}

		else
		{
			std::cout << "DHCP Release sent successfully" << std::endl;
		}

	}

	~DHCP()
	{
		device->close();
	}
};

//class Interface {
//private:
//	pcpp::PcapLiveDevice* device = { nullptr };
//public:
//	Interface(std::string ifaceIp)
//	{
//		device = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ifaceIp.c_str());
//		if (!device)
//		{
//			throw std::runtime_error("Could not intialise device " + ifaceIp + "\n");
//		}
//
//		if (!device->open())
//		{
//			throw std::runtime_error("Could not open device " + ifaceIp + "\n");
//		}
//
//		std::cout << "Opened device." << std::endl;
//	}
//
//	~Interface()
//	{
//		if (device->isOpened())
//		{
//			device->close();
//		}
//	}
//
//};

// Endpoints might not be the best name as routers aren't technically endpoints, same for switches, hubs etc.
class Endpoint {
private:
	pcpp::MacAddress mac;
	pcpp::IPv4Address ip;
	std::string firstSeen;
	std::string lastSeen;
public:
	Endpoint(pcpp::MacAddress macAddr, std::string firstSeenTime) : mac(macAddr), firstSeen(firstSeenTime)
	{
		if (mac == nullptr)
		{
			throw std::runtime_error("Failed to create Endpoint with MAC " + macAddr.toString());
			//std::cerr << "Failed to create Endpoint with MAC " << macAddr << "\n";
		}
	}

	Endpoint& operator=(Endpoint&& other) noexcept
	{
		if (this != &other)
		{
			// moving uninitalised variables is probably gonna cause a nullptr dereference
			mac = std::move(other.mac);
			ip = std::move(other.ip);
			firstSeen = std::move(other.firstSeen);
			lastSeen = std::move(other.lastSeen);
		}

		return *this;
	}

	//Endpoint(const Endpoint&) = default;
	//Endpoint(Endpoint&&) = default;
	//Endpoint& operator=(const Endpoint&) = default;
	//Endpoint& operator=(Endpoint&&) = default;

	pcpp::MacAddress* getMac()  // passing back pointers might be dangerous for accidental value changes
	{
		return &mac;
	}

	pcpp::IPv4Address* getIp()
	{
		return &ip;
	}

	bool updateIp(pcpp::IPv4Address ipAddr)
	{
		ip = ipAddr;
		if (ip == nullptr)
		{
			std::cerr << "Failed to update IP for " << mac.toString() << "\n";
			return false;
		}

		return true;

	}

	void updateLastSeen(std::string time)
	{
		lastSeen = time;
		// add error handling here
	}

	std::string getLastSeen()
	{
		return lastSeen;
	}

	std::string getFirstSeen()
	{
		return firstSeen;
	}

	~Endpoint()
	{
		std::cerr << "Failed to destroy object"; //  shouldn't realistically happen but useful to know if the automatic destruction fails - add more robust error handling in future
	}


};

class LAN {
private:
	pcpp::IPv4Address ifaceIp_;
	pcpp::PcapLiveDevice* device = { nullptr };
	std::atomic<bool> passive;
	std::vector<pcpp::MacAddress> macs;
	std::vector<pcpp::IPv4Address> ips;
	std::vector<std::unique_ptr<Endpoint>> endpoints;

	void addEndpoint(std::unique_ptr<Endpoint> endpoint)
	{
		endpoints.push_back(endpoint);
	}

	static void ProcessPkt(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* cookie)
	{
		LAN* self = reinterpret_cast<LAN*>(cookie);

		pcpp::Packet packet(rawPacket);

		pcpp::EthLayer* ethLayer(packet.getLayerOfType<pcpp::EthLayer>());

		if (ethLayer != nullptr)
		{
			// check if the MAC address has already been added to the macs vector - avoid printing mac already found. Might be useful to update "last seen" time (in that case use std::map)
			bool alreadyAdded = false;
			for (auto& endpoint : self->endpoints)
			{
				if (*endpoint->getMac() == ethLayer->getSourceMac())
				{
					endpoint->updateLastSeen(getCurrentTime());  // no need to deference because method being called on object
					return;
				}
			}

			std::cout << "New endpoint\n";

			//self->macs.push_back(ethLayer->getSourceMac());

			std::unique_ptr<Endpoint> newEndpoint = std::make_unique<Endpoint>(ethLayer->getSourceMac(), getCurrentTime()); // use smartptr to create the object - avoid memory leaks
			if (newEndpoint != nullptr) {
				self->endpoints.push_back(std::move(newEndpoint)); // *caution* even after move there's a risk the ptr will be accessible but invalid
			}
			else {
				// log somewhere else instead
				std::cout << "Failed to create endpoint object.\n";
			}

			//std::cout << "MAC: " << ethLayer->getSourceMac().toString() << " ";

		}

		for (auto& endpoint : self->endpoints)
		{
			std::cout << "Endpoint: " << endpoint->getMac() << endpoint->getFirstSeen() << " " << endpoint->getLastSeen() << "\n";
		}

		//pcpp::IPv4Layer* ip4Layer(packet.getLayerOfType<pcpp::IPv4Layer>());

		//if (ip4Layer != nullptr)
		//{
		//	bool alreadyAdded = false;
		//	for (auto endpoint : self->endpoints)
		//	{
		//		if (*endpoint.getIp() == ip4Layer->getSrcIPAddress())  // non-ptr to ptr IPv4Address type gives awkward matching
		//		{
		//			// IPs can change - add an IP drift notifier in future
		//			return;
		//		}
		//	}

		//	// get a reference to the Endpoint object created for this device using on its MAC


		//	self->endpoints.push_back(*ip4Layer->getSrcIPv4Address());
		//	std::cout << "IP: " << ip4Layer->getSrcIPAddress().toString() << " ";

		//}
		//else {
		//	std::cout << "(No IP in Pkt Hdr) ";
		//}

		//std::cout << getCurrentTime();

		//std::cout << "\n";

	}

 public:
	LAN(std::string localIp) : ifaceIp_(localIp)
	{
		device = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ifaceIp_);
		if (!device || !device->open())
		{
			throw std::runtime_error("Could not open local device.");
		}

		std::cout << "Opened device " << device->getName() << "\n";
	}



	void Passive()
	{
		if (!device->isOpened())
		{
			std::cerr << "Network interface not open\n";
			return;
		}

		if (!device->startCapture(&LAN::ProcessPkt, this))
		{
			throw std::runtime_error("Could not start capture.\n");
		}

	}

	void Stop()
	{
		if (!device->isOpened())
		{
			std::cerr << "Device not open?";
		}

		if (!device->captureActive())
		{
			std::cerr << "Device not capturing?";
		}

		device->close();

	}



	~LAN()
	{
		if (device)
		{
			if (device->isOpened())
			{
				device->close();
			}
			if (device->isOpened())
			{
				std::cerr << "Failed to close device.\n";
			}
		}
	}
};


/* https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6 */

class DNS {
private:
	pcpp::IPv4Address ifaceIp_;
	pcpp::PcapLiveDevice* device = { nullptr };
	/*std::thread captureRspThread;*/
	uint16_t dnsTransactionId = 0;

	const std::map<uint16_t, std::map<std::string, std::string>> dnsRcodes =
	{
		{0, {{"NoError", "No Error" }}},
		{1, {{"FormErr", "Format Error"}}},
		{2, {{"ServFail", "Server Failure"}}},
		{3, {{"NXDomain", "Non - Existent Domain"}}},
		{4, {{"NotImp", "Not Implemented"}}},
		{5, {{"Refused", "Query Refused"}}},
		{6, {{"YXDomain", "Name Exists when it should not"}}},
		{7, {{"YXRRSet",  "RR Set Exists when it should not"}}},
		{8, {{"NXRRSet", "RR Set that should exist does not"}}},
		{9, {{"NotAuth",  "Server Not Authoritative for zone / Not Authorized"}}},
		{10, {{"NotZone", "Name not contained in zone"}}},
		{11, {{"DSOTYPENI", "DSO - TYPE Not Implemented"}}},
		{12, {{"Unassigned", ""}}},
		{13, {{"Unassigned", ""}}},
		{14, {{"Unassigned", ""}}},
		{15, {{"Unassigned", ""}}},
		{16, {{"BADVERS",  "Bad OPT Version / TSIG Signature Failure"}}},
		/*16 {"BADSIG", "TSIG Signature Failure"},*/
		{17, {{"BADKEY", "Key not recognized"}}},
		{18, {{"BADTIME", "Signature out of time window"}}},
		{19, {{"BADMODE", "Bad TKEY Mode"}}},
		{20, {{"BADNAME", "Duplicate key name"}}},
		{21, {{"BADALG", "Algorithm not supported"}}},
		{22, {{"BADTRUNC", "Bad Truncation"}}},
		{23, {{"BADCOOKIE", "Bad / missing Server Cookie"}}},
		{24, {{"Unassigned", ""}}},  // 3840
		{3841, {{"Reserved", "for Private Use"}}}, //4095
		{4096, {{"Unassigned", ""}}}, // 65534
		{65535, {{"Reserved", "can be allocated by Standards Action"}}}
	};

	struct packetFilter {
		uint16_t dnsTransactionId;
	};

public:

	DNS(std::string localIp) : ifaceIp_(localIp)
	{
		device = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(localIp);
		if (!device || !device->open())
		{
			throw std::runtime_error("Failed to open device.\n");
		}

		std::cout << "Opened device " << device->getName() << "\n" << std::endl;

	}



	bool ProcessPkt(pcpp::RawPacket* rawPacket, std::vector<pcpp::IPv4Address>* addresses)
	{

		pcpp::Packet pkt(rawPacket);

		if (pcpp::DnsLayer* dnsLayer = pkt.getLayerOfType<pcpp::DnsLayer>())
		{
			// response code lookup might be better suited here for performance - save the parsing and return the code right away
			pcpp::IPv4Layer* ip4Layer = pkt.getLayerOfType<pcpp::IPv4Layer>();
			pcpp::IPv4Address* dst = const_cast<pcpp::IPv4Address*>(&ip4Layer->getDstIPAddress().getIPv4());
			
			if (dst->toString() == device->getIPv4Address().toString())
			{
				if (dnsLayer->getDnsHeader()->transactionID == dnsTransactionId)
				{
					// check DNS response here

					size_t nAnswers = dnsLayer->getAnswerCount();  // number of answers

					//std::cout << dnsLayer->getDnsHeader()->responseCode << "\n";// - probably a better choice

					//auto responseCode = dnsRcodes.find(dnsLayer->getDnsHeader()->responseCode);
	
					//std::cout << responseCode->first << "\n"; // just the key

					//for (auto iter = responseCode->second.begin(); iter != responseCode->second.end(); iter++)  // this iterator should not really be required because only map is only ever returned 
					//{
					//	std::cout << iter->first << " " << iter->second << "\n";
					//}

					//std::cout << "\n";

					std::cout << dnsRcodes.find(dnsLayer->getDnsHeader()->responseCode)->second.begin()->first << " " << dnsRcodes.find(dnsLayer->getDnsHeader()->responseCode)->second.begin()->second << "\n";


					for (auto answer = dnsLayer->getFirstAnswer(); answer != nullptr; answer = dnsLayer->getNextAnswer(answer))
					{
						pcpp::IPv4Address addr(answer->getData().get()->toString()); // take the answer (std::string) and create an IPv4Address from it
						addresses->push_back(addr);  // push the dns answer (as IPv4Address) onto the vector						
					}
					return true;  // answers found so return true

				}
			}
		}

		return false;
	}

	// static void ProcessPkt()

	void Query(const std::string& name)
	{
		double arpTimeout = 1000;

		pcpp::IPv4Address gatewayIp = device->getDefaultGateway();
		auto gatewayMac = pcpp::NetworkUtils::getInstance().getMacAddress(gatewayIp, device, arpTimeout);

		// build EthLayer
		pcpp::EthLayer ethLayer(device->getMacAddress(), gatewayMac, PCPP_ETHERTYPE_IP);
		
		// build IPLayer
		pcpp::IPv4Layer ipLayer(device->getIPv4Address(), device->getDefaultGateway());
		
		ipLayer.getIPv4Header()->protocol = pcpp::PACKETPP_IPPROTO_UDP;
		ipLayer.getIPv4Header()->timeToLive = 64;  // required for TCP

		uint16_t srcPort = rand() & 65536;  // make more random
		uint16_t dstPort = 53;    // check if DNS is serving from port 53 and likewise check if TCP/UDP only

		pcpp::UdpLayer udpLayer(srcPort, dstPort);

		pcpp::DnsLayer dnsLayer;

		std::cout << "DNS Layer created" << "\n";

		dnsLayer.addQuery(name, pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);

		std::cout << "Query for " << name << " added." << "\n";

		dnsLayer.getDnsHeader()->transactionID = rand() % 65535;  // make more random

		dnsLayer.getDnsHeader()->recursionDesired = 1;  // instruct the DNS server to perform a recursive lookup
		//dnsLayer.getDnsHeader()->recursionAvailable;  // this is set by DNS servers in responses

		int count = 0;
		for (pcpp::DnsQuery* query = dnsLayer.getFirstQuery(); query != nullptr; query = dnsLayer.getNextQuery(query))
		{
			count++;
			std::cout << "Query " << count << ":" << query->getName() << "\n";
		}

		pcpp::Packet packet;

		packet.addLayer(&ethLayer);
		packet.addLayer(&ipLayer);
		packet.addLayer(&udpLayer);
		packet.addLayer(&dnsLayer);

		auto checksum = udpLayer.calculateChecksum(true);

		//std::cout << "checksum calculated: " << checksum << "\n";

		packet.computeCalculateFields();


		if (!packet.isPacketOfType(pcpp::DNS))
		{
			std::cout << "Packet does not contain DNS layer.\n";
		}

		if (auto dnsHeader = dnsLayer.getDnsHeader())
		{
			std::cout << "Number of queries: " << dnsHeader->numberOfQuestions << "\n";
			std::cout << "Transaction ID: " << dnsHeader->transactionID << "\n";
			if (dnsHeader->transactionID != 0)  // check the transaction ID was set
			{ 
				dnsTransactionId = dnsHeader->transactionID; // this needs to be set in the classes scope so the PktProcess method knows what DNS response to look for
				std::cout << "Current DNS-TransactionID to " << dnsTransactionId << "\n";
			}
			else {
				std::cout << "TransactionID not set? Aborting the query.\n";
				return;
			}
			std::cout << "Recursion Desired: " << dnsLayer.getDnsHeader()->recursionDesired << "\n";
		}

		if (!device->isOpened())
		{
			std::cout << "Device is not open\n";
			return;
		}

		pcpp::RawPacketVector rawPkts;

		// startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie); // more suitable for this type of capture (avoid parsing RawPackets whilst capturing). use onPacketArrivesUserCookie to pass a filter/context struct
		if (!device->startCapture(rawPkts))
		{
			std::cout << "Could not start RawPacket capture.\n";
			return;
		}

		std::cout << "Capturing RawPackets to catch DNS answer\n";

		bool result = device->sendPacket(packet, true);
		if (!result)
		{
			std::cout << "failed to send DNS query\n";
			return;
		}
		else {

			std::cout << "DNS Query sent: " << result << "\n";
		}

		int maxCapture = 10;
		//int currentIter = 0;
		bool found = false;
		std::vector<pcpp::IPv4Address> answers;

		while (found == false && rawPkts.size() <= maxCapture)  // PcapPlusPlus documentation advises against parsing RawPackets buffer whilst capture is in progress. Potential workaround: send over TCP and use handshake as queue to stop capture
		{
			for (auto pkt : rawPkts)
			{
				if (ProcessPkt(pkt, &answers))
				{
					found = true;
				}
			}
		}

		if (!found)
		{
			std::cout << "Failed to capture the DNS answer.\n";
		}

		if (answers.empty())
		{
			std::cout << "Answers vector empty. (DNS did not provide a response with hostname / hostname invalid)\n";
		}

		else {
			int count = 0;
			for (auto& answer : answers)
			{
				count++;
				std::cout << "Answer " << count << ": " << answer.toString() << "\n";
			}
		}

		std::cout << "Number of raw packets parsed: " << rawPkts.size() << "\n";



		if (device->captureActive())
		{
			device->stopCapture();
			if (device->captureActive())
			{
				std::cout << "Failed to stop capture.\n";
			}
		}
		else {
			std::cout << "Device wasn't capturing?\n";
		}

		dnsTransactionId = 0;

		std::cout << "DNS Transaction ID reset to " << dnsTransactionId << "\n";

	}

	~DNS()
	{
		if (device->isOpened())
		{
			device->close();
		}
	}
};

int main()
{

	std::cout << getCurrentTime()  << "\n";

	/*Objects are currently being created based on protocol. Long term this could hinder overall design. Potentially better to do per behaviour e.g. sniff, inject etc*/

	std::string ip("192.168.1.190");
	//std::unique_ptr<DNS> dns = std::make_unique<DNS>(ip);  // use smartptr for automatic cleanup

	//const std::string name = "iPhone"; // LAN host

	//const std::string name = "google.com"; // WAN host

	//dns->Query(name);

	//std::cin.get();

	//std::unique_ptr<DHCP> dhcp = std::make_unique<DHCP>("192.168.1.230");

	//dhcp->Discover();

	std::unique_ptr<LAN> lan = std::make_unique<LAN>(ip);

	lan->Passive();

	std::cin.get();  // IO gets "stuck" waiting for input

	lan->Stop();

	return 0;

}

