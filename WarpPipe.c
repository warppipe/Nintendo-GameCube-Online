// -------------------------------------------------------------------------------
// WarpPipe project
//
//	WarpPipe is a proxy that will link cubes on lans to other cubes across
//	a WAN.
// -------------------------------------------------------------------------------
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>		// FIXME: These don't work in BSD....
#include <linux/if_ether.h>		// need to find the equiv. headers or just use libpcap
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>

// -------------------------------------------------------------------------------
// Defines
// -------------------------------------------------------------------------------
#define		PROXY_PROTO_VER		0x02		// Protocol Version 2 (this is arbitrary till the first release.. :)

#define		MAX_CUBES		4
#define		MAX_PROXY_LINKS		4
#define		BLACKLIST_SIZE		24

#define		DEAMON_PORT		4000		// For now port to listen on is a constant

// Control Link Packet Types
#define		PKT_CTRL_HELLO		0x01
#define		PKT_CTRL_FULL		0x02
#define		PKT_CTRL_IPVERIFY	0x03
#define		PKT_CTRL_IPNERF		0x04
#define		PKT_CTRL_CUBEALERT	0x05

// UDP link Packet Types
#define		PKT_UDP_UPNP		0x01
#define		PKT_UDP_GAME		0x02

// Ethernet Frame Offsets
#define		ETH_DST_MAC		0x00
#define		ETH_SRC_MAC		0x06
#define		ETH_PROTOCOL		0x0C

// -------------------------------------------------------------------------------
// Structures
// -------------------------------------------------------------------------------
typedef struct proxylink_s
{
	unsigned long Ip;		// IP of Proxy
	unsigned short Port;		// UDP listen port of proxy

	unsigned char Validated;	// Flag. If version has been validated correct

	unsigned char Pad;		// Makes this struct align nicely

	int Socket;			// Socket for this proxy link.

	struct proxylink_s *Prev;
	struct proxylink_s *Next;
} proxylink_typ;

typedef struct remotecube_s
{
	unsigned long CubeIp;		// inet_addr formatted IP of Cube
	unsigned long TimeStamp;	// Timestamp so entrys will expire and not corrupt table

	proxylink_typ *Proxy;		// ProxyLink entry of host proxying this cube

	struct remotecube_s *Prev;
	struct remotecube_s *Next;
} remotecube_typ;

typedef struct localcube_s		// FIXME: Make this a linked list some day
{
	unsigned long CubeIP;		// IP of local cube
	unsigned char MAC[6];		// MAC of local cube.
} localcube_typ;

typedef struct ipverify_s
{
	unsigned long IP;		// IP that is being verified
	unsigned char MAC[6];		// MAC address of cube trying for IP.
	unsigned long TimeStamp;	// Timestamp of request. Only Nerf's are recieved, so need to expire old valid ip entries.

	struct ipverify_s *Prev;
	struct ipverify_s *Next;
} ipverify_typ;

typedef struct blacklist_s
{
	unsigned long IP;		// Blacklisted IP
	unsigned long TimeStamp;	// Timestamp so entries will expire over time
} blacklist_typ;

typedef struct sockets_s
{
	int Arp;			// RAW socket for sniffing ARP's

	int Listen;			// Listen port for incoming TCP Proxy Connections

	int Udp;			// UDP socket for listening for game data from other proxies

	int Raw;			// Raw Socket for sniffing for game data.

	int Cmd;			// TCP socket for GUI command interface

	int MaxSocket;			// Greatest number for sockets for select.
	fd_set Fds;			// Set for select
} sockets_typ;

typedef struct sys_s
{
	unsigned char MacAddress[6];	// MacAddress of Interface
	unsigned short IfIndex;		// Index of interface
	unsigned long Ip;		// IP of interface

	unsigned short CtrlPort;	// Port to listen on for Proxy Links

	unsigned char Verbose;		// Flag to give more output.

	unsigned char Quit;		// Quit flag
} sys_typ;

// -------------------------------------------------------------------------------
// Prototypes
// -------------------------------------------------------------------------------
void Shutdown (void);

// Socket creation / deletion
int CreateSockets (void);
void CloseSockets (void);
void BuildFds (void);

// ARP processing
int ProcArp (void);
int SendArpReq (unsigned long *IP);
int SendArpReply (unsigned char *DstMAC, unsigned long *DstIP, unsigned char *SrcMAC, unsigned long *SrcIP);

int ProcRaw (void);		// process a raw frame

int ProcUdp (void);		// Process a game packet from a cube

// Proxy Link funcs
int  OpenProxyLink (char *Host);
int  AcceptProxyLink (void);
int  ProcProxyPkt (proxylink_typ *Proxy);
void CloseProxyLink (proxylink_typ *Proxy);

// RLE Compression
unsigned long RLECompress (unsigned char *Src, unsigned char *Dst, unsigned long Len);
unsigned long RLEExpand (unsigned char *Src, unsigned char *Dst, unsigned long Len);

// Utility Funcs
int isCubeMAC (unsigned char *MAC);
char *IPtoASC (unsigned long IP);

// Signal Funcs
void SigHandler (int Signal);

// -------------------------------------------------------------------------------
// Globals
// -------------------------------------------------------------------------------
proxylink_typ	*ProxyLinks;			// Linked list of connected proxies.
remotecube_typ 	*RemoteCubes;			// Linked list of known Cubes
localcube_typ	LocalCubes[MAX_CUBES];		// List of local LAN cubes
ipverify_typ 	*VerifyList;			// Linked list of pending IP Verify's
blacklist_typ	BlackList[BLACKLIST_SIZE];	// Blacklist of bad IP's
sockets_typ 	Sockets;			// Struct holding all needed sockets
sys_typ 	Sys;				// Various system information

// -------------------------------------------------------------------------------
// Main
// -------------------------------------------------------------------------------
int main (int argc, char **argv)
{
	proxylink_typ *Proxy;
	proxylink_typ *Next;
	remotecube_typ *Cube;
	int i;
	int ret;
	
	signal (SIGINT, SigHandler);
	signal (SIGQUIT, SigHandler);

	// Zero out all our globals
	ProxyLinks = NULL;
	RemoteCubes = NULL;
	memset (LocalCubes, 0, sizeof (localcube_typ) * MAX_CUBES);
	memset (BlackList, 0, sizeof (blacklist_typ) * 24);
	VerifyList = NULL;
	memset (&Sockets, 0, sizeof (sockets_typ)); 
	memset (&Sys, 0, sizeof (sys_typ));

	Sys.CtrlPort = htons (DEAMON_PORT);

	// Do first round of param checks
	for (i=1; i<argc; i++)		// We have params, so assume <host>:<port> and try to connect
	{
		if (!strcmp (argv[i], "-?"))
		{
			printf ("Usage: %s [options...] [<ip>:<port>...]\n", argv[0]);
			printf ("Options:\n");
			printf ("  -?          Help.\n");
			printf ("  -l <port>   Set the Listen port for Proxy Connections.\n");
			printf ("  -d          Deamon mode. Immediate return to console.\n");
			printf ("  -g          Gui mode, enables stdin/stdout communication.\n");
			printf ("  -v          Verbose.\n");
			printf ("  -V          Very Verbose.\n\n");

			return 0;
		}
		else if (!strcmp (argv[i], "-l"))
			Sys.CtrlPort = htons (atoi (argv[i++]));
		else if (!strcmp (argv[i], "-v"))
			Sys.Verbose = 1;
		else if (!strcmp (argv[i], "-V"))
			Sys.Verbose = 2;
	}

	// Create all of our sockets
	ret = CreateSockets ();
	if (ret) Sys.Quit = 1;	// CreateSockets will have logged the error

	// See if we need to establish a control link
	for (i=1; i<argc; i++)
	{
		if (strchr (argv[i], ':'))
			OpenProxyLink (argv[i]);
	}

	// Now sit and wait for packets
	while (!Sys.Quit)
	{
		BuildFds ();
		ret = select (Sockets.MaxSocket+1, &Sockets.Fds, NULL, NULL, NULL);
		if (ret)
		{
			if (FD_ISSET (Sockets.Arp, &Sockets.Fds))
				ProcArp ();
			if (FD_ISSET (Sockets.Listen, &Sockets.Fds))
				AcceptProxyLink ();
			if (FD_ISSET (Sockets.Udp, &Sockets.Fds))
				ProcUdp ();
			if (FD_ISSET (Sockets.Raw, &Sockets.Fds))
				ProcRaw ();

			Proxy = ProxyLinks;
			while (Proxy)
			{
				Next = Proxy->Next;
				if (FD_ISSET (Proxy->Socket, &Sockets.Fds))
					ProcProxyPkt (Proxy);

				Proxy = Next;
			}
		}
		else
			printf ("select returned 0? What the hell.\n");
	}

	// Cleanup
	CloseSockets ();

	while (ProxyLinks)
	{
		Proxy = ProxyLinks->Next;
		close (ProxyLinks->Socket);
		free (ProxyLinks);
		ProxyLinks = Proxy;
	}

	while (RemoteCubes)
	{
		Cube = RemoteCubes->Next;
		free (RemoteCubes);
		RemoteCubes = Cube;
	}

	return 0;
}

void Shutdown (void)
{
	// Flush Proxy list

	// flush remote cube list

	// clear anything else out.
}

// -------------------------------------------------------------------------------
// CreateSockets - Creates all needed sockets.
// -------------------------------------------------------------------------------
int CreateSockets (void)
{
	struct ifreq 		IfReq;
	struct packet_mreq 	MemReq;
	struct sockaddr_in 	SrcAddr;
	int Socket;

	int ret;

	// ********************
	// Create the ARP socket
	Socket = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (Socket == -1)
	{
		printf ("CreateSockets - Failed to Create ARP socket.\n");
		return  -1;
	}

	// Get Interface Index fo future use.
	memset (&IfReq, 0, sizeof (struct ifreq));
	sprintf (IfReq.ifr_name, "eth0");	// FIXME: Make me an option some day.
	ret = ioctl (Socket, SIOCGIFINDEX, (char *)&IfReq);
	if (ret)
	{
		printf ("CreateSockets - Failed to acquire Interface Index.\n");
		return -1;
	}
	Sys.IfIndex = IfReq.ifr_ifindex;

	// Get MAC adress for future use.
	memset (&IfReq, 0, sizeof (struct ifreq));
	sprintf (IfReq.ifr_name, "eth0");	// FIXME: Make me an option some day.
	ret = ioctl (Socket, SIOCGIFHWADDR, (char *)&IfReq);
	if (ret)
	{
		printf ("CreateSockets - Failed to get MAC address.\n");
		return -1;
	}
	memcpy (Sys.MacAddress, IfReq.ifr_hwaddr.sa_data, 6);
	if (Sys.Verbose) printf ("CreateSockets - MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", Sys.MacAddress[0], Sys.MacAddress[1], Sys.MacAddress[2], Sys.MacAddress[3], Sys.MacAddress[4], Sys.MacAddress[5]);

	// Get IP address for use.
	memset (&IfReq, 0, sizeof (struct ifreq));
	sprintf (IfReq.ifr_name, "eth0");	// FIXME: Make me an option some day.
	ret = ioctl (Socket, SIOCGIFADDR, (char *)&IfReq);
	if (ret)
	{
		printf ("CreateSockets - Failed to get IP address.\n");
		return -1;
	}
	memcpy (&Sys.Ip, IfReq.ifr_hwaddr.sa_data+2, 4);
	if (Sys.Verbose) printf ("CreateSockets - Ip address: %s\n", IPtoASC (Sys.Ip));

	// Now we need to make the socket recieve all ARP traffic
	memset (&MemReq, 0, sizeof (struct packet_mreq));
	MemReq.mr_ifindex = Sys.IfIndex;
	MemReq.mr_type = PACKET_MR_PROMISC;
	ret = setsockopt (Socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &MemReq, sizeof (struct packet_mreq));
	if (ret)
	{
		printf ("CreateSockets - Failed to set Arp socket into Promisc mode.\n");
		return -1;
	}

	// Socket is ready, add it to the main socket struct and we can move on.
	Sockets.Arp = Socket;
	if (Sys.Verbose) printf ("CreateSockets - ARP Socket Created: %d\n", Socket);

	// ********************
	// Create the Game Data UDP socket
	Socket = socket (AF_INET, SOCK_DGRAM, 0);
	if (Socket == -1)
	{
		printf ("CreateSockets - Failed to create UDP Socket.\n");
		return -1;
	}

	// bind socket to udp port
	memset (&SrcAddr, 0, sizeof (struct sockaddr_in));
	SrcAddr.sin_family = AF_INET;
	SrcAddr.sin_addr.s_addr = htonl (INADDR_ANY);
	SrcAddr.sin_port = Sys.CtrlPort;
	ret = bind (Socket, (struct sockaddr *)&SrcAddr, sizeof (struct sockaddr_in));
	if (ret)
	{
		printf ("CreateSockets - Failed to bind UDP socket.\n");
		return -1;
	}

	// Socket is ready
	Sockets.Udp = Socket;
	if (Sys.Verbose) printf ("CreateSockets - Udp socket created: %d\n", Socket);

	// ********************
	// Create the RAW socket for game data.
	Socket = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_IP));
	if (Socket == -1)
	{
		printf ("CreateSockets - Failed to create Raw Socket.\n");
		return -1;
	}

	// Now we need to make the socket recieve all IP traffic
	memset (&MemReq, 0, sizeof (struct packet_mreq));
	MemReq.mr_ifindex = IfReq.ifr_ifindex;
	MemReq.mr_type = PACKET_MR_PROMISC;
	ret = setsockopt (Socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &MemReq, sizeof (struct packet_mreq));
	if (ret)
	{
		printf ("CreateSockets - Failed to set Raw socket into Promisc mode.\n");
		return -1;
	}

	// Socket is ready, add it to the main socket struct and we can move on.
	Sockets.Raw = Socket;
	if (Sys.Verbose) printf ("CreateSockets - Raw Socket Created: %d\n", Socket);

	// ********************
	// Create the Proxy TCP listen socket
	Socket = socket (AF_INET, SOCK_STREAM, 0);
	if (Socket == -1)
	{
		printf ("CreateSockets - Failed to create Control Listen socket.\n");
		return -1;
	}

	// bind the socket to the deamon listen port
	memset (&SrcAddr, 0, sizeof (struct sockaddr_in));
	SrcAddr.sin_family = AF_INET;
	SrcAddr.sin_addr.s_addr = htonl (INADDR_ANY);
	SrcAddr.sin_port = Sys.CtrlPort;
	ret = bind (Socket, (struct sockaddr *)&SrcAddr, sizeof(struct sockaddr_in));
	if (ret)
	{
		printf ("CreateSockets - Failed to bind Control Listen socket.\n");
		return -1;
	}

	// Make the socket listen for connections
	ret = listen (Socket, MAX_PROXY_LINKS);
	if (ret)
	{
		printf ("CreateSockets - Failed to Listen on Control Listen Socket.\n");
		return -1;
	}

	// Socket is ready, add it to struct
	Sockets.Listen = Socket;
	if (Sys.Verbose) printf ("CreateSockets - Control Listen socket created: %d\n", Socket);

	// ********************
	// Create the GUI Command Listen Socket

	return 0;
}

void CloseSockets (void)
{
	if (Sockets.Arp)
	{
		close (Sockets.Arp);
		Sockets.Arp = 0;
	}

	if (Sockets.Udp)
	{
		close (Sockets.Udp);
		Sockets.Udp = 0;
	}

	if (Sockets.Raw)
	{
		close (Sockets.Raw);
		Sockets.Raw = 0;
	}

	if (Sockets.Listen)
	{
		close (Sockets.Listen);
		Sockets.Listen = 0;
	}

	if (Sockets.Cmd)
	{
		close (Sockets.Cmd);
		Sockets.Cmd = 0;
	}

	if (Sys.Verbose) printf ("Sockets Closed.\n");
}

void BuildFds (void)
{
	proxylink_typ *Proxy;

	FD_ZERO (&Sockets.Fds);
	Sockets.MaxSocket = 0;

	if (Sockets.Listen)
	{
		FD_SET (Sockets.Listen, &Sockets.Fds);
		if (Sockets.Listen > Sockets.MaxSocket)
			Sockets.MaxSocket = Sockets.Listen;
	}

	if (Sockets.Arp)
	{
		FD_SET (Sockets.Arp, &Sockets.Fds);
		if (Sockets.Arp > Sockets.MaxSocket)
			Sockets.MaxSocket = Sockets.Arp;
	}

	if (Sockets.Udp)
	{
		FD_SET (Sockets.Udp, &Sockets.Fds);
		if (Sockets.Udp > Sockets.MaxSocket)
			Sockets.MaxSocket = Sockets.Arp;
	}

	if (Sockets.Raw)
	{
		FD_SET (Sockets.Raw, &Sockets.Fds);
		if (Sockets.Raw > Sockets.MaxSocket)
			Sockets.MaxSocket = Sockets.Arp;
	}

	if (Sockets.Cmd)
	{
		FD_SET (Sockets.Cmd, &Sockets.Fds);
		if (Sockets.Cmd > Sockets.MaxSocket)
			Sockets.MaxSocket = Sockets.Arp;	
	}

	Proxy  = ProxyLinks;
	while (Proxy)
	{
		FD_SET (Proxy->Socket, &Sockets.Fds);
		if (Proxy->Socket > Sockets.MaxSocket)
			Sockets.MaxSocket = Proxy->Socket;

		Proxy = Proxy->Next;
	}
}

// -------------------------------------------------------------------------------
// ProcArpPacket - Processes an ARP packet and acts accordingly.
// -------------------------------------------------------------------------------
#define ARP_BUFFER_SIZE		60		

#define ARP_OFS_HTYPE		0x0E
#define ARP_OFS_PTYPE		0x10
#define	ARP_OFS_HLEN		0x12
#define	ARP_OFS_PLEN		0x13
#define	ARP_OFS_OPCODE		0x14
#define ARP_OFS_SENDER_MAC	0x16		// These values are supposed to be based off the HLNE and PLEN
#define	ARP_OFS_SENDER_IP	0x1C		// But I doubt they will change, so might as well use constants
#define	ARP_OFS_TARGET_MAC	0x20		// for speed.
#define ARP_OFS_TARGET_IP	0x26

#define ARP_OPCODE_REQ		0x0001
#define ARP_OPCODE_REPLY	0x0002

int ProcArp (void)
{
	unsigned char Buffer[ARP_BUFFER_SIZE];
	int ret;
	int i;
	unsigned short OpCode;
	ipverify_typ *Verify;
	remotecube_typ *Cube;
	proxylink_typ *Proxy;

	// Get the data from the socket
	ret = recvfrom (Sockets.Arp, Buffer, ARP_BUFFER_SIZE, 0, NULL, NULL);

	// Pull some valus from the Packet
	OpCode = ntohs (*(unsigned short *)(Buffer + ARP_OFS_OPCODE));
	
	if (OpCode == ARP_OPCODE_REQ)	
	{
		if (Sys.Verbose) printf ("ProcArp - Recieved ARP Request. len: %d\n", ret);

		// First do proper ARP, see if this IP is in the RemoteCubes list, and reply accordingly
		Cube = RemoteCubes;
		while (Cube)
		{
			if (!memcmp (&Cube->CubeIp, Buffer+ARP_OFS_TARGET_IP, 4))
			{
				// Send an ARP reply
				SendArpReply ((Buffer+ARP_OFS_SENDER_MAC), (unsigned long *)(Buffer+ARP_OFS_SENDER_IP), Sys.MacAddress, &Cube->CubeIp);

				if (Sys.Verbose) printf ("ProcArp - Sent ARP response for remote cube. IP: %s.\n", IPtoASC (Cube->CubeIp));
				return 0;
			}
			Cube = Cube->Next;
		}

		// Must not be in remote cubes list. If the ARP was from a cube we start doing funky ARP stuff
		if (isCubeMAC (Buffer+ARP_OFS_SENDER_MAC))
		{
			// If this is an IP, tell IP where the IP's match, we assume the IP has been determined valid.
			if (!memcmp (Buffer+ARP_OFS_SENDER_IP, Buffer+ARP_OFS_TARGET_IP, 4))
			{
				// Make sure we don't already know about this cube
				for (i=0; i<MAX_CUBES; i++)
				{
					if (!memcmp (&LocalCubes[i].CubeIP, Buffer+ARP_OFS_SENDER_IP, 4))
						return 0;
				}

				// Find the IPVerify entry for the pending IP, since it has now been taken.
				Verify = VerifyList;
				while (Verify)
				{
					if (!memcmp (&Verify->IP, Buffer+ARP_OFS_SENDER_IP, 4))
						break;

					Verify = Verify->Next;
				}
				if (Verify)
				{
					if (Verify->Next)
						Verify->Next->Prev = Verify->Prev;
					if (Verify->Prev)
						Verify->Prev->Next = Verify->Next;
					if (VerifyList == Verify)
						VerifyList = Verify->Next;

					free (Verify);
				}

				// Now alert all proxies to the new Cube
				Buffer[0] = PKT_CTRL_CUBEALERT;
				memcpy (Buffer+1, Buffer+ARP_OFS_SENDER_IP, 4);

				Proxy = ProxyLinks;
				while (Proxy)
				{
					ret = send (Proxy->Socket, Buffer, 5, 0);
					Proxy = Proxy->Next;
				}

				// Find a free LocalCube entry to add new cube
				for (i=0; i<MAX_CUBES; i++)
				{
					if (memcmp (&LocalCubes[i].CubeIP, Buffer+ARP_OFS_SENDER_IP, 4))
					{
						if (!LocalCubes[i].CubeIP)
						{
							memcpy (&LocalCubes[i].CubeIP, Buffer+ARP_OFS_SENDER_IP, 4);
							memcpy (LocalCubes[i].MAC, Buffer+ARP_OFS_SENDER_MAC, 6);
							break;
						}
					}
				}

				if (Sys.Verbose) printf ("ProcArp - Local cube added. IP: %s.\n", IPtoASC (LocalCubes[i].CubeIP));
				return 0;
			}

			// This arp is not an IP tell IP, so make sure it's not in the Pending Verify List
			Verify = VerifyList;
			while (Verify)
			{
				if (!memcmp (&Verify->IP, Buffer+ARP_OFS_TARGET_IP, 4))
					return 0;

				Verify = Verify->Next;
			}

			// It's not a IP take, and it's not pending, so chck Blacklist
			for (i=0; i < BLACKLIST_SIZE; i++)
			{
				// Need to expire entries based on timstamp here.

				if (!memcmp (&BlackList[i].IP, Buffer+ARP_OFS_TARGET_IP, 4))
				{
					// Send an ARP reply
					SendArpReply ((Buffer+ARP_OFS_SENDER_MAC), (unsigned long *)(Buffer+ARP_OFS_SENDER_IP), Sys.MacAddress, &BlackList[i].IP);

					if (Sys.Verbose) printf ("ProcArp - BlackListed IP %s was requested by Cube. Nerfed.\n", IPtoASC (BlackList[i].IP));
					return 0;
				}
			}

			// IP isn't blacklisted, so time to ask the other proxies if the IP is ok.
			Verify = (ipverify_typ *)malloc(sizeof(ipverify_typ));
			if (!Verify)
			{
				printf ("ProcArp - malloc of IPVerify failed.\n");
				return -1;
			}
			Verify->IP = *(unsigned long *)(Buffer+ARP_OFS_TARGET_IP);
			memcpy (Verify->MAC, Buffer+ARP_OFS_SENDER_MAC, 6);
			Verify->TimeStamp = 0;		// FIXME: Do TimeStamp.
			Verify->Prev = NULL;
			Verify->Next = VerifyList;
			if (VerifyList)
				VerifyList->Prev = Verify;
			VerifyList = Verify;

			Buffer[0] = PKT_CTRL_IPVERIFY;
			memcpy (Buffer+1, Buffer+ARP_OFS_TARGET_IP, 4);
			
			Proxy = ProxyLinks;
			while (Proxy)
			{
				ret = send (Proxy->Socket, Buffer, 5, 0);
				Proxy = Proxy->Next;
			}

			if (Sys.Verbose) printf ("ProcArp - IP Verify sent out for %s.\n", IPtoASC (*(unsigned long *)(Buffer+ARP_OFS_TARGET_IP)));
			return 0;
		}
		// Otherwise ignore it, we only deal with cubes
	}
	else if (OpCode == ARP_OPCODE_REPLY)
	{
		if (Sys.Verbose) printf ("ProcArp - Recieved ARP reply.\n");

		// Look for an IPVerify entry.
		Verify = VerifyList;
		while (Verify)
		{
			if (!memcmp (&Verify->IP, Buffer+ARP_OFS_SENDER_IP, 4))
				break;

			Verify = Verify->Next;
		}
		if (Verify)
		{
			// Send an IPNerf to all connected proxies
			Buffer[0] = PKT_CTRL_IPNERF;
			memcpy (Buffer+1, Buffer+ARP_OFS_SENDER_IP, 4);

			Proxy = ProxyLinks;
			while (Proxy)
			{
				ret = send (Proxy->Socket, Buffer, 5, 0);
				Proxy = Proxy->Next;
			}
			if (Sys.Verbose) printf ("ProcArp - IPNerf sent to all Proxies for %s\n", IPtoASC (Verify->IP));

			// Delete the Entry.
			if (Verify->Next)
				Verify->Next->Prev = Verify->Prev;
			if (Verify->Prev)
				Verify->Prev->Next = Verify->Next;
			else
				VerifyList = Verify;

			free (Verify);
		}

	}
	
	// Otherwise it is some other variation on the ARP protocol. Ignore it.
	return 0;
}

int SendArpReq (unsigned long *IP)
{
	unsigned char Buffer[ARP_BUFFER_SIZE];
	struct sockaddr_ll SockAddr;
	int ret;

	// Make an ARP request packet.
	memset (Buffer, 0, ARP_BUFFER_SIZE);
	memset (Buffer+ETH_DST_MAC, 0xFF, 6);
	memcpy (Buffer+ETH_SRC_MAC, Sys.MacAddress, 6);
	Buffer[12] = 0x08;
	Buffer[13] = 0x06;
	Buffer[15] = 0x01;
	Buffer[16] = 0x08;
	Buffer[18] = 0x06;
	Buffer[19] = 0x04;
	Buffer[21] = 0x01;
	memcpy (Buffer+ARP_OFS_SENDER_MAC, Sys.MacAddress, 6);
	memcpy (Buffer+ARP_OFS_SENDER_IP, &Sys.Ip, 4);
	memcpy (Buffer+ARP_OFS_TARGET_IP, IP, 4);

	memset (&SockAddr, 0, sizeof (struct sockaddr_ll));
	SockAddr.sll_ifindex = Sys.IfIndex;
	ret = sendto (Sockets.Arp, Buffer, ARP_BUFFER_SIZE, 0, (struct sockaddr *)&SockAddr, sizeof (struct sockaddr_ll));
	if (ret > 0)
	{
		if (Sys.Verbose) printf ("SendArpReq - Sent request for IP: %s\n", IPtoASC (*IP));
	}
	else
	{
		if (Sys.Verbose) printf ("SendArpReq - Error %d : %s\n", errno, strerror(errno));
	}
		
	return 0;
}

int SendArpReply (unsigned char *DstMAC, unsigned long *DstIP, unsigned char *SrcMAC, unsigned long *SrcIP)
{
	unsigned char Buffer[ARP_BUFFER_SIZE];
	struct sockaddr_ll SockAddr;
	int ret;

	// Make an ARP reply packet, destined for DstMAC, with these values.
	memset (Buffer, 0, ARP_BUFFER_SIZE);
	memcpy (Buffer+ETH_DST_MAC, DstMAC, 6);
	memcpy (Buffer+ETH_SRC_MAC, SrcMAC, 6);
	Buffer[12] = 0x08;
	Buffer[13] = 0x06;
	Buffer[15] = 0x01;
	Buffer[16] = 0x08;
	Buffer[18] = 0x06;
	Buffer[19] = 0x04;
	Buffer[21] = 0x02;
	memcpy (Buffer+ARP_OFS_SENDER_MAC, SrcMAC, 6);
	memcpy (Buffer+ARP_OFS_SENDER_IP, SrcIP, 4);
	memcpy (Buffer+ARP_OFS_TARGET_MAC, DstMAC, 6);
	memcpy (Buffer+ARP_OFS_TARGET_IP, DstIP, 4);

	memset (&SockAddr, 0, sizeof (struct sockaddr_ll));
	SockAddr.sll_ifindex = Sys.IfIndex;
	ret = sendto (Sockets.Arp, Buffer, ARP_BUFFER_SIZE, 0, (struct sockaddr *)&SockAddr, sizeof (struct sockaddr_ll));
	if (ret > 0)
	{
		if (Sys.Verbose) printf ("ArpReply - Sent reply for IP: %s\n", IPtoASC (*SrcIP));
	}
	else
	{
		if (Sys.Verbose) printf ("ArpReply - Error %d : %s\n", errno, strerror (errno));
	}
		
	return 0;
}

// -------------------------------------------------------------------------------
// ProcUdp - Deals with game and UPnP data sent via the UDP link.
// -------------------------------------------------------------------------------
#define	UDP_BUFFER_SIZE		1500

#define IP_OFS_TOTAL_SIZE	0x10
#define	IP_OFS_IDENT		0x12
#define	IP_OFS_FLAGS		0x14
#define	IP_OFS_FRAG_OFS		0x14
#define	IP_OFS_TTL		0x16
#define	IP_OFS_PROTOCOL		0x17
#define IP_OFS_CRC		0x18
#define IP_OFS_SRC_IP		0x1A
#define IP_OFS_DST_IP		0x1E

int ProcUdp (void)
{
	struct sockaddr_ll SockAddr;
	unsigned char Buffer[UDP_BUFFER_SIZE];
	unsigned char *Pkt;
	int len;
	int i;
	int ret;

	len = recvfrom (Sockets.Udp, Buffer, UDP_BUFFER_SIZE, 0, NULL, NULL);

	if (Buffer[0] == PKT_UDP_UPNP)
	{
		if (Sys.Verbose) printf ("ProcUdp - Received PKT_UDP_UPNP.\n");

		Pkt = Buffer+1;

		// Replace the Src MAC with ours.
		memcpy (Pkt+ETH_SRC_MAC, Sys.MacAddress, 6);

		// And re-send. It was a broadcast from the cube, we need only re-broadcast it.
		memset (&SockAddr, 0, sizeof (struct sockaddr_ll));
		SockAddr.sll_ifindex = Sys.IfIndex;
		ret = sendto (Sockets.Raw, Pkt, len-1, 0, (struct sockaddr *)&SockAddr, sizeof (struct sockaddr_ll));

		if (ret > 0)
		{
			if (Sys.Verbose == 2) printf ("ProcUdp - Re-transmitted UPNP packet from %s.\n", IPtoASC (*(unsigned long *)(Pkt+0x1A)));
		}
		else
		{
			if (Sys.Verbose) printf ("ProcUdp - Error %d :  %s.\n", errno, strerror (errno));
		}

	}
	else if (Buffer[0] == PKT_UDP_GAME)
	{
		if (Sys.Verbose) printf ("ProcUdp - Received PKT_UDP_GAME.\n");

		// For now packet is uncompressed. Eventually it will be RLE compressed.
		Pkt = Buffer + 1;

		// Replace the SrcMac with our own
		memcpy (Pkt+ETH_SRC_MAC, Sys.MacAddress, 6);

		// Find the local cube this is destined for
		for (i=0; i < MAX_CUBES; i++)
		{
			if (!memcmp (&LocalCubes[i].CubeIP, Pkt+IP_OFS_DST_IP, 4))
				break;
		}
		if (i < MAX_CUBES)
		{
			// make the dst mac address that of the cube.
			memcpy (Pkt+ETH_DST_MAC, LocalCubes[i].MAC, 6);

			// Re-Send it.
			memset (&SockAddr, 0, sizeof (struct sockaddr_ll));
			SockAddr.sll_ifindex = Sys.IfIndex;
			ret = sendto (Sockets.Raw, Pkt, len-1, 0, (struct sockaddr *)&SockAddr, sizeof (struct sockaddr_ll));

			if (ret > 0)
			{
				if (Sys.Verbose == 2) printf ("ProcUdp - Re-transmitted UDP Game packet.\n");
			}
			else
			{
				if (Sys.Verbose) printf ("ProcUdp - Error %d : %s.\n", errno, strerror (errno));
			}
		}
		else
			if (Sys.Verbose) printf ("ProcUdp - COuld not match to a local cube entry.\n");
	}
	else
		printf ("ProcUdp - Unknown Packet Type %02X.\n", Buffer[0]);

	return 0;
}

// -------------------------------------------------------------------------------
// ProcRawPacket - Deals with RAW packets
// -------------------------------------------------------------------------------
#define RAW_BUFFER_SIZE		1500

#define UDP_OFS_BASE		0x22
#define UDP_OFS_SRC_PORT	0x22
#define UDP_OFS_DST_PORT	0x24
#define UDP_OFS_LENGTH		0x26
#define UDP_OFS_CRC		0x28
 
int ProcRaw (void)
{
	unsigned char Buf[RAW_BUFFER_SIZE];
	unsigned char *Buffer;
	struct sockaddr_in DstAddr;
	proxylink_typ *Proxy;
	remotecube_typ *Cube;
	int len;
	int ret;

	Buffer = Buf + 1;

	memset (&DstAddr, 0, sizeof (struct sockaddr_in));
	DstAddr.sin_family = AF_INET;

	// get the packet
	len = recvfrom (Sockets.Raw, Buffer, RAW_BUFFER_SIZE, 0, NULL, 0);

	// We only want traffic from cubes
	if (isCubeMAC (Buffer+ETH_SRC_MAC))
	{
		// See if it is destined for the MultiCast IP 239.255.255.250
		ret = inet_addr ("239.255.255.250");
		if (!memcmp (Buffer+IP_OFS_DST_IP, &ret, 4))
		{
			// Make sure the Src IP is in the LocalCube list. No need to transmit non-cube SSDP traffic.

			if (Sys.Verbose) printf ("ProcRaw - UPnP received.\n");

			Buf[0] = PKT_UDP_UPNP;
			Proxy = ProxyLinks;
			while (Proxy)
			{
				DstAddr.sin_addr.s_addr = Proxy->Ip;
				DstAddr.sin_port = Proxy->Port;

				ret = sendto (Sockets.Udp, Buf, len+1, 0, (struct sockaddr *)&DstAddr, sizeof (struct sockaddr_in));

				Proxy = Proxy->Next;
			}
		}
		else
		{
			Buf[0] = PKT_UDP_GAME;

			// Compression would be here. When implemented
			Cube = RemoteCubes;
			while (Cube)
			{
				if (!memcmp (Buffer+IP_OFS_DST_IP, &Cube->CubeIp, 4))
				{
					DstAddr.sin_addr.s_addr = Cube->Proxy->Ip;
					DstAddr.sin_port = Cube->Proxy->Port;

					ret = sendto (Sockets.Udp, Buf, len+1, 0, (struct sockaddr *)&DstAddr, sizeof (struct sockaddr_in));
				}

				Cube = Cube->Next;
			}
		}
	}

	return 0;
}

// -------------------------------------------------------------------------------
// Proxy Link - Functiuons that handle the links between proxies
// -------------------------------------------------------------------------------
int OpenProxyLink (char *Host)
{
	char host[24];
	char IP[16];
	char Port[6];
	char *chr;
	struct sockaddr_in DstAddr;
	int Socket;
	proxylink_typ *Proxy;
	int ret;

	printf ("OpenProxyLink - Connecting to: %s\n", Host);

	// Convert IP:Port into two strings
	strcpy (host, Host);	// Preserver Host for printing purposes.
	chr = strchr (host, ':');
	if (chr)
	{
		*chr = 0;
		chr ++;
		strcpy (Port, chr);
	}
	strcpy (IP, host);

	// Create the socket for connecting
	Socket = socket (AF_INET, SOCK_STREAM, 0);
	if (Socket == -1)
	{
		printf ("OpenProxyLink - Failed to create Socket for connection.\n");
		return 0;
	}

	// connect to remote host
	memset (&DstAddr, 0, sizeof (struct sockaddr_in));
	DstAddr.sin_family = AF_INET;
	DstAddr.sin_addr.s_addr = inet_addr (IP);
	DstAddr.sin_port = htons (atoi (Port));
	ret = connect (Socket, (struct sockaddr *)&DstAddr, sizeof (struct sockaddr_in));
	if (ret)
	{
		close (Socket);
		printf ("OpenProxyLink - Failed to connect to: %s.\n", Host);
		return 0;
	}

	// Create a new list entry for the new connection
	Proxy = (proxylink_typ *)malloc(sizeof(proxylink_typ));
	if (!Proxy)
	{
		printf ("AcceptProxyLink - proxylink_typ malloc failed.\n");
		return -1;
	}
	memset (Proxy, 0, sizeof(proxylink_typ));

	// fill in the values.
	Proxy->Ip = DstAddr.sin_addr.s_addr;
	Proxy->Port = DstAddr.sin_port;
	Proxy->Socket = Socket;

	// add it to the master list
	if (ProxyLinks)
	{
		Proxy->Next = ProxyLinks;
		ProxyLinks->Prev = Proxy;
	}
	ProxyLinks = Proxy;

	// Send hello paclet
	host[0] = PKT_CTRL_HELLO;
	host[1] = PROXY_PROTO_VER;
	memcpy (host+2, &Sys.CtrlPort, 2);
	ret = send (Socket, host, 4, 0);

	printf ("OpenProxyLink - Connected to %s\n", Host);

	return 0;
}

int AcceptProxyLink (void)
{
	int Socket;
	unsigned char Buffer[4];
	struct sockaddr_in SrcAddr;
	proxylink_typ *Proxy;
	int ret;

	memset (&SrcAddr, 0, sizeof (struct sockaddr_in));

	// Accept the new Socket
	ret = sizeof(struct sockaddr_in);
	Socket = accept (Sockets.Listen, (struct sockaddr *)&SrcAddr, &ret);
	if (Socket == -1)
	{
		printf ("AcceptProxyLink - Failed to accept connection on Proxy Listen Socket.\n");
		return 0;
	}

	if (Sys.Verbose) printf ("AcceptProxyLink - Processing connection attempt.\n");

	// Create a new list entry for the new connection
	Proxy = (proxylink_typ *)malloc(sizeof(proxylink_typ));
	if (!Proxy)
	{
		printf ("AcceptProxyLink - proxylink_typ malloc failed.\n");
		return -1;
	}
	memset (Proxy, 0, sizeof(proxylink_typ));

	// fill in the values.
	Proxy->Ip = SrcAddr.sin_addr.s_addr;
	Proxy->Socket = Socket;

	// add it to the master list
	if (ProxyLinks)
	{
		Proxy->Next = ProxyLinks;
		ProxyLinks->Prev = Proxy;
	}
	ProxyLinks = Proxy;

	// Send the Hello / Ver packet
	Buffer[0] = PKT_CTRL_HELLO;
	Buffer[1] = PROXY_PROTO_VER;
	memcpy (Buffer+2, &Sys.CtrlPort, 2);
	ret = send (Socket, Buffer, 4, 0);

	if (Sys.Verbose) printf ("AcceptProxyLink - Connection accepted. Ip: %s\n", IPtoASC (Proxy->Ip));

	return 0;
}

int ProcProxyPkt (proxylink_typ *Proxy)
{
	ipverify_typ *Verify;
	remotecube_typ *Cube;
	unsigned long Ip;
	unsigned char Cmd;
	int ret;
	int i;

	// Get the cmd ID from the socket
	ret = recv (Proxy->Socket, &Cmd, 1, 0);
	if (ret < 1)
	{
		CloseProxyLink (Proxy);
		if (Sys.Verbose) printf ("ProcProxyPkt - Proxy Link Connection Closed.\n");
		return 0;
	}

	// Deal with the CMD
	if (!Proxy->Validated)
	{
		switch (Cmd)
		{
			case PKT_CTRL_HELLO:
				if (Sys.Verbose) printf ("ProcProxyPkt - Recieved PKT_CTRL_HELLO.\n");

				// Get the protocol Version
				ret = recv (Proxy->Socket, &Cmd, sizeof (unsigned char), 0);
				ret = recv (Proxy->Socket, &Proxy->Port, sizeof (unsigned short), 0);

				// Check version passed with packet
				if (Cmd < PROXY_PROTO_VER)
				{
					CloseProxyLink (Proxy);
					printf ("ProcProxyPkt - Old Protocol Version. %s disconnected.\n", IPtoASC (Proxy->Ip));
				}
				else if (Cmd > PROXY_PROTO_VER)
				{
					CloseProxyLink (Proxy);
					printf ("ProcProxyPkt - Unknown Protocol Version. %s disconnected.\n", IPtoASC (Proxy->Ip));
				}
				else
				{
					Proxy->Validated = 1;
					if (Sys.Verbose) printf ("ProcProxyPkt - Protocol Version OK. Connected to Proxy: %s\n", IPtoASC (Proxy->Ip));
				}
				break;
			case PKT_CTRL_FULL:
				CloseProxyLink (Proxy);
				printf ("ProcProxyPkt - Proxy Full. Disconnected.\n");
				break;
			default:
				printf ("ProcProxyPkt - Unknown Control Packet for non-validated link: %02X\n", Cmd);
				break;
		}
	}
	else
	{	// CMD from validated proxy
		switch (Cmd)
		{
			case PKT_CTRL_IPVERIFY:
				if (Sys.Verbose) printf ("ProcProxyPkt - Recieved PKT_CTRL_IPVERIFY\n");

				// Add an IpVerify Entry to the list
				Verify = (ipverify_typ *)malloc(sizeof(ipverify_typ));
				if (!Verify)
				{
					printf ("ProcProxyPkt - Failed to allocate memory for Verify Entry.\n");
					return -1;
				}
				if (VerifyList)
					VerifyList->Prev = Verify;
				Verify->Next = VerifyList;
				Verify->Prev = NULL;
				VerifyList = Verify;
				VerifyList->TimeStamp = 0;
				ret = recv (Proxy->Socket, &VerifyList->IP, 4, 0);

				// Send out an ARP for the Ip in the packet
				SendArpReq (&VerifyList->IP);

				break;
			case PKT_CTRL_IPNERF:
				if (Sys.Verbose) printf ("ProcProxyPkt - Recieved PKT_CTRL_IPNERF.\n");

				ret = recv (Proxy->Socket, &Ip, 4, 0);

				// Add this IP to blacklist.
				for (i=0; i<BLACKLIST_SIZE; i++)
				{
					if (!BlackList[i].IP)
						break;
				}
				if (i < BLACKLIST_SIZE)
				{
					BlackList[i].IP = Ip;
					BlackList[i].TimeStamp = 0;
					if (Sys.Verbose) printf ("ProcProxyPkt - %s has been BlackListed.\n", IPtoASC (Ip));
				}
				else
					if (Sys.Verbose) printf ("ProcProxyPkt - No more free BlackList entries.\n");

				// Look for IPVerify Entry
				Verify = VerifyList;
				while (Verify)
				{
					if (Verify->IP == Ip)
						break;
					Verify = Verify->Next;
				}
				if (Verify)
				{
					// Send out ARP sayinbg we own this IP. This'll nerf the Cube
					Ip = 0;
					ret = SendArpReply (Verify->MAC, &Ip, Sys.MacAddress, &Verify->IP);

					if (Verify->Next)
						Verify->Next->Prev = Verify->Prev;
					if (Verify->Prev)
						Verify->Prev->Next = Verify->Next;
					else
						VerifyList = Verify->Next;

					free (Verify);
				}
				break;
			case PKT_CTRL_CUBEALERT:
				if (Sys.Verbose) printf ("ProcProxyPkt - Received PKT_CTRL_CUBEALERT\n");

				// Create a new entry
				Cube = (remotecube_typ *)malloc(sizeof(remotecube_typ));
				if (!Cube)
				{
					printf ("ProcProxyPkt - Failed to create remote cube entry.\n");
					return -1;
				}
				memset (Cube, 0, sizeof(remotecube_typ));

				// Fill in the info
				ret = recv (Proxy->Socket, &Cube->CubeIp, 4, 0);
				Cube->Proxy = Proxy;

				if (Sys.Verbose) printf ("ProcProxyPkt - New Cube added. Ip: %s\n", IPtoASC (Cube->CubeIp));

				// Add it to the list
				if (RemoteCubes)
					RemoteCubes->Prev = Cube;
				Cube->Next = RemoteCubes;
				RemoteCubes = Cube;

				break;
			default:
				printf ("ProcProxyPkt - Unknown Control Packet for validated link: %02X\n", Cmd);
				break;
		}
	}

	return 0;
}

void CloseProxyLink (proxylink_typ *Proxy)
{
	remotecube_typ *Cube;
	remotecube_typ *Next;

	close (Proxy->Socket);

	Cube = RemoteCubes;
	while (Cube)
	{
		if (Cube->Proxy == Proxy)
		{
			Next = Cube->Next;
			
			if (Cube->Next)
				Cube->Next->Prev = Cube->Prev;
			if (Cube->Prev)
				Cube->Prev->Next = Cube->Next;
			else
				RemoteCubes = Cube->Next;

			free (Cube);

			Cube = Next;
		}
		else
			Cube = Cube->Next;
	}

	if (Proxy->Next)
		Proxy->Next->Prev = Proxy->Prev;
	if (Proxy->Prev)
		Proxy->Prev->Next = Proxy->Next;
	else
		ProxyLinks = Proxy->Next;

	free (Proxy);
}

// -------------------------------------------------------------------------------
// RLE Compression
// -------------------------------------------------------------------------------
unsigned long RLECompress (unsigned char *Src, unsigned char *Dst, unsigned long Len)
{
	int i;
	unsigned long Size;

	i = 0;
	while (i < Len)
	{

	}

	return Size;
}

unsigned long RLEExpand (unsigned char *Src, unsigned char *Dst, unsigned long Len)
{
	int Size;

	Size = 0;
	while (Len)
	{
		if (*Src & 0x80)
		{
			*Src &= 0x7F;

			memset (Dst, *(Src+1), (*Src & 0x7F));
			Src += 2;
		}
		else
		{
			memcpy (Dst, Src+1, *Src);
			Src += *Src + 1;
		}

		Dst += *Src;
		Len -= *Src;
		Size += *Src;
	}

	return Size;
}

// -------------------------------------------------------------------------------
// Utility Funcs
// -------------------------------------------------------------------------------
int isCubeMAC (unsigned char *MAC)
{
	if (MAC[0] != 0x00)
		return 0;
	if (MAC[1] != 0x09)
		return 0;
	if (MAC[2] != 0xBF)
		return 0;

	return 1;
}

// WARNING: This func is intel specific. It will still compile, just the address it produces will be backwards.
//		Need some conditional If's to make this cross-platform.
char *IPtoASC (unsigned long IP)
{
	static char Text[16];
	unsigned char *ip;

	ip = (unsigned char *)&IP;
	sprintf (Text, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

	return Text;
}

// -------------------------------------------------------------------------------
// Siganl Handler
// -------------------------------------------------------------------------------
void SigHandler (int Signal)
{
	Sys.Quit = 1;

	// Program won't quit until a packet is recieved, but atleast it will quit gracefully.
}

