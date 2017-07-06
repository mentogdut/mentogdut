#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h> 

//-------------------------------------------------------------------------

int ifstatus(const char *if_name)
{
	struct ifaddrs *ifList;
	if (getifaddrs(&ifList) < 0) return -1; // error

	int state = 0; // not found
	for (struct ifaddrs *ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
			if (ifa->ifa_name && strcmp(ifa->ifa_name, if_name) == 0) {
				return ifa->ifa_flags;
			} //if
		} //if
	}

	freeifaddrs(ifList);
	return state;
}

//-------------------------------------------------------------------------

int main()
{
	ifstatus("pppoe_wan") & (IFF_UP | IFF_RUNNING); // active
	return 0;
}
