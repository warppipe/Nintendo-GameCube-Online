# Nintendo GameCube Online
The daemon portion of the Nintendo GameCube tunneling software, written in C.

## Warp Pipe V1.0


### Whats Broken - Things you'll need to know until we fix them:

	1) The cubes have to be on the same subnet. For instance if Cube 1's
		ip is 192.168.1.100 and Cube 2's ip is 192.168.2.100 it
		will not work. There is a solution to this it just has not
		been implemented yet.

	2) More than two people should be possible but it has not been tested
		yet. To do this a link needs to be made from every daemon
		to every other daemon. When the GUI gets completed this will
		become transparent.


### Getting Started - Hardware

	To use WarpPipe the following is needed:
 
 	1) a GCN with a broadband adapter. 
  	2) a i386 machine running some flavor of linux and root access. 
   	3) a connection to the internet.

	Network setup:
 
	1) Make sure your GCN and Linux machine can access the internet. The
		GCN only needs to be visible to the Linuc Machine.
	2) If your Linux machine is behind a router/firewall then you need to
	     direct port 4000 for both UPD and TCP to the Linux machine.
	3) That should be it.

	Running the Software:
 
	1) You need root access to the linux machine.
	2) The software runs as both a server and client. One person acts as
	     server and simply runs the deamon, the second connects to the
	     other person by providing the ip:port of the other Linux Machine.

	Server Ex: ./WarpPipe -V
	Client Ex: ./WarpPipe -V 192.168.1.100:4000

	To get a list of options: ./WarpPipe -?

Once the software is running each party can turn on there game cube and start
a game as if the person was right there. If you can see the output of the Linux
machine than you should see various info scrolling about finding cubes etc.

Good Luck
