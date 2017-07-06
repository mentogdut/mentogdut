#include "mentogdut.h"
#include "mbedtls/md5.h"
#include "mbedtls/md4.h"
#include "mbedtls/sha1.h"
#ifdef _WINDOWS
# include <signal.h>
# include "windows/lib.h"
# pragma comment(lib, "ws2_32.lib")
#else   
typedef int SOCKET;
# define INVALID_SOCKET -1
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <signal.h>
#endif // _WINDOWS

#define CALC(algorithm, data, length, output) algorithm((const unsigned char *)data, length, (unsigned char *)output)

//-------------------------------------------------------------------------

static void hprint(const char *data, int len)
{
#ifndef NDEBUG
	for (int i = 0; i < len; ++i) {
		fprintf(stdout, "%02hhx ", *(data + i));
		if (i % 16 == 0 && i != 0) fprintf(stdout, "\n");
	}
    fprintf(stdout, "\n");
	fflush(stdout);
#endif // !NDEBUG
}

//-------------------------------------------------------------------------

static inline void platform_sleep(int seconds)
{
#ifdef _WINDOWS
# ifdef _WINLIB
	__alertable_wait(seconds * 1000u);
# else
	SleepEx(seconds * 1000, TRUE); // QueueUserAPC
# endif // _WINLIB
#else 
	sleep(seconds);
#endif // _WINDOWS
}

//-------------------------------------------------------------------------

static int construct_challenge_request(char *data, char id)
{
	// [send]PKT1: challenge request
    data[0] = 0x07; // code
    data[1] = id;   // id
    data[2] = 0x08; // length 08 00
    data[3] = 0x00;
    data[4] = 0x01; // type
    data[5] = 0x00; // other[3]
    data[6] = 0x00;
    data[7] = 0x00;

    return 8;
}

//-------------------------------------------------------------------------

static int calc_heartbeat_request_checksum(char checksum[8], const char *seed, int check_mode)
{
	char crc[32];
	switch (check_mode) 
	{
	case 0:
		*((int *)checksum)     = INT32_LE(INT32_C(20000711));
		*((int *)checksum + 1) = INT32_LE(INT32_C(126));
		break;
	case 1: // md5
		CALC(mbedtls_md5, seed, 4, crc);
		checksum[0] = crc[2];
		checksum[1] = crc[3];
		checksum[2] = crc[8];
		checksum[3] = crc[9];
		checksum[4] = crc[5];
		checksum[5] = crc[6];
		checksum[6] = crc[13];
		checksum[7] = crc[14];
		break;
	case 2: // md4
		CALC(mbedtls_md4, seed, 4, crc);
		checksum[0] = crc[1];
		checksum[1] = crc[2];
		checksum[2] = crc[8];
		checksum[3] = crc[9];
		checksum[4] = crc[4];
		checksum[5] = crc[5];
		checksum[6] = crc[11];
		checksum[7] = crc[12];
		break;
	case 3: // sha1
		CALC(mbedtls_sha1, seed, 4, crc);
		checksum[0] = crc[2];
		checksum[1] = crc[3];
		checksum[2] = crc[9];
		checksum[3] = crc[10];
		checksum[4] = crc[5];
		checksum[5] = crc[6];
		checksum[6] = crc[15];
		checksum[7] = crc[16];
		break;
	default: // need this?
		__fprintf(stderr, "Unknown encryption type %d!\n", check_mode);
		memset(checksum, 0, 8);
		break;
	}

	return 8;
}

//-------------------------------------------------------------------------

static int calc_drcom_crc32(char *data, int len)
{
	int ret = 0;
	for (int i = 0; i < len; i += 4) {
		ret ^= *(int *)(data + i);
	}
	return ret;
}

//-------------------------------------------------------------------------

static int construct_heartbeat_request(char *data, char id, char encrypt, const char *challenge_seed, const char *auth_host_ip)
{
	// [send]PKT3: heartbeat request
    static int first_send = 1;

	/*
	struct _tagDrcomDialExtProtoHeader
	{
		char  code;
		char  id;
		short length;
		char  type;
	};	
	struct _tagDrcomDialExtProtoLoginPacket
	{
		struct _tagDrcomDialExtProtoHeader header; // 5 byte

		char uidlength;
		char mac[6];
		long sip;
		long option; // bit0=dhcp, bit1=请求封装, bit2-7(verno)
					 // b8=(no first),b9=有tcpipdog.dll, b10-12 选择出口线路 2006-12-18
					 // b13(mydll mark2007-2-28), bit14-31 unuse
					 // b14(mydll mark b15=find proxy cut line (pppoe模式2007-11-22)
				     // bit16-31 unuse
		char challengeseed[4];
		long crc[2];

		//struct _tagDrcomDialExtProtoNetWorkInfo netinfo[MAX_DRCOM_DIAL_EXT_PROTO_NET_NUM];
	};
	*/
    data[0] = 0x07;   // code, PPPoE ext = 0x07
    data[1] = id;     // id
    data[2] = 0x60;   // length = Loginpack + uidlength + networkinfo * 4
    data[3] = 0x00;   //        = 96(0x0060) 
    data[4] = 0x03;   // type, PPPoE = 0x03
    data[5] = 0x00;   // uid length (strlen(us.Account))

	memset(data + 6, 0, 6); // MAC

    int index = 12;
	memcpy(data + index, auth_host_ip, 4); // AuthHostIP
    index += 4;

	if (first_send) {
		memcpy(data + index, "\x00\x62\x00", 3);
		*(data + index + 3) = dconfig.pppoe_flag;
		first_send = 0;
	} else {
		memcpy(data + index, "\x00\x63\x00", 3);
		*(data + index + 3) = dconfig.pppoe_flag;
	} //if
    index += 4;

	memcpy(data + index, challenge_seed, 4); // ChallengeSeed[4]
    index += 4;

	if (encrypt == '\0') {
		/*
		// 先初始化为20000711,126
		// 66 cc 58 2f 00 00 00 00 // crc[2] (unsigned long)
		// 旧版本, 不采用加密，此时CRC计算方法为
		// crc[0]: 19680126 * calc_drcom_crc32(0, loginpacket, 96)
		// crc[1]: 0
		*/
		// DRCOM_DIAL_EXT_PROTO_CRC_INIT
		*((int *)(data + index)) = INT32_LE(INT32_C(20000711)); // crc[0]
		index += 4;
		*((int *)(data + index)) = INT32_LE(INT32_C(126)); // crc[1]
		index += 4;
		
		int crc = (INT32_LE(calc_drcom_crc32(data, index)) * 19680126);
		index -= 8;
		*((int *)(data + index)) = INT32_LE(crc); // crc[0]
		index += 4;
		*((int *)(data + index)) = 0; // crc[1]
		index += 4;

		// DRCOM_DIAL_EXT_PROTO_HEADER_END
	} else {
		// checksum[8]
		index += calc_heartbeat_request_checksum(data + index, challenge_seed, challenge_seed[0] & 0x03);
	} //if

	/*
	struct _tagDrcomDialExtProtoNetWorkInfo
	{
		char mac[6];
		char netmark;
		char type;
		long sip;
		long smask;
	};
	00 00 00 00 00 00 // mac
	00                // netmark, dhcp mark
	8b                // type, interface type(ether,ppp)
	ac 2a 14 78       // sip
	ff ff ff ff       // smask
	// the same as above
	00 a0 59 06 00 20  00  03  c0 51 25 08  ff ff ff 00
	00 a0 59 06 00 01  00  03  c0 51 2b 08  ff ff ff 00
	00 00 00 00 00 00  00  00  00 00 00 00  00 00 00 00
	*/
	memset(data + index, 0, 16 * 4);

    return index + 16 * 4;
}

//-------------------------------------------------------------------------

static int construct_keep_alive2_req_first(char *data, char id, short flag, const char *rand, int key)
{   
	// normal heartbeat packet 1
	data[0] = 0x07; // code
	data[1] = id;   // id
	data[2] = 0x28; // length
 
	int index = 3;
	memcpy(data + index, "\x00\x0b\x01", 3);
    index += 3;

	memcpy(data + index, &flag, 2);
    index += 2;

    memcpy(data + index, rand, 2);
    index += 2;

	memset(data + index, 0, 6);
    index += 6;

	memcpy(data + index, &key, 4);
    index += 4;

	memset(data + index, 0, 20);
    return index + 20;
}

//-------------------------------------------------------------------------

static void calc_keep_alive2_checksum(char *data, int len, char *checksum)
{
	short *block = (short *)data;
	int crc32    = 0;
	for (int i = 0; i < len / 2; ++i) {
		crc32 ^= *(block + i);
	}
	((short *)&crc32)[1] = 0; // crc32 &= 0xffff;
	*((int *)checksum)   = INT32_LE(INT32_LE(crc32) * 0x2c7); // fixed
}

//-------------------------------------------------------------------------

static int construct_keep_alive2_second(char *data, char id, short flag, char *rand, int key, char *host_ip)
{
	// normal heartbeat packet 2
    data[0] = 0x07; // code
    data[1] = id;   // id
    data[3] = 0x28; // length

	int index = 3;
	memcpy(data + index, "\x00\x0b\x03", 3);
    index += 3;

	memcpy(data + index, &flag, 2);
    index += 2;

	memcpy(data + index, rand, 2);
    index += 2;

	memset(data + index, 0, 6);
    index += 6;

	memcpy(data + index, &key, 4);
    index += 4;

	memset(data + index, 0, 4);
    index += 4;

	// checksum placeholder
	int crc_index = index;
	memset(data + index, 0, 4);
	index += 4;

	memcpy(data + index, host_ip, 4);
    index += 4;

	memset(data + index, 0, 8);
	index += 8;

	calc_keep_alive2_checksum(data, index, data + crc_index);

    return index;
}

//-------------------------------------------------------------------------

static struct
{
	SOCKET fd;
	union
	{
		struct sockaddr sa;
		struct sockaddr_in inet;
	} addr;

	char packet[1024];
	
	// pppoe heartbeat
	char encrypt;
	char seed[4], host_ip[4];
	char pppoe_idx;
	
	// drcom heartbeat
	int   ka2_key;
	short ka2_flag;
	char  ka2_idx;
} shared;

//-------------------------------------------------------------------------

static int pppoe_heartbeat()
{
	int retry_count = 0, nrecv;
	int packet_len  = construct_challenge_request(shared.packet, shared.pppoe_idx);
	do {
		sendto(shared.fd, shared.packet, packet_len, 0, &shared.addr.sa, sizeof(shared.addr.inet));
		dprintf(stdout, "-->pppoe: send challenge request[%u], %d bytes\n",
				shared.pppoe_idx, packet_len);
		hprint(shared.packet, packet_len);

		nrecv = recvfrom(shared.fd, shared.packet, sizeof(shared.packet), 0, NULL, 0);
		if (nrecv <= 0) {
#ifdef _WINLIB
			if (__signal_exit() != 0) return 0;
#endif // _WINLIB
			if (++retry_count >= 5) {
				dprintf(stderr, "--!pppoe: recv %d, reset idx to 0x01\n", nrecv);
				return 0;
			} //if
			dprintf(stdout, "--!pppoe: challenge request failed, retry %d\n", retry_count);
		} else break; //if
	} while (1);

	dprintf(stdout, "<--pppoe: received challenge response[%u], %d bytes\n", shared.pppoe_idx, nrecv);
	hprint(shared.packet, nrecv);

	/*
	07       // header.code
	55       // header.id
	10 00    // header.length
	02       // header.type
	00 00 00 // other[3] other[0]确定加密方式, 0为不加密
	cf 89 a8 03 // ChallengeSeed[4]
	ac 15 05 0f // ClientSouIp
	a8 a4 00 00 3a ae 6f 3c 00 00 00 00 d8 02 00 00
	*/
	shared.encrypt = dconfig.checksum == 0 ? shared.packet[5] : (dconfig.checksum == 2);
	memcpy(shared.seed, shared.packet + 8, 4);
	memcpy(shared.host_ip, shared.packet + 12, 4);
#ifndef NDEBUG
	if (shared.pppoe_idx == 0x01) {
		static char encrypt = '\xff';
		static long host_ip = 0;
		if (shared.encrypt != encrypt || *(long *)shared.host_ip != host_ip) {
			encrypt = shared.encrypt;
			host_ip = *(long *)shared.host_ip;
			dprintf(stdout, "!--pppoe: checksum %s\n", shared.encrypt == '\0' ? "unencrypted" : "encrypted");
			unsigned char *ip = (unsigned char *)shared.host_ip;
			dprintf(stdout, "!--pppoe: auth host %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
		} //if
	} //if
#endif // !NDEBUG
	++shared.pppoe_idx;

	retry_count = 0;
	packet_len  = construct_heartbeat_request(shared.packet, shared.pppoe_idx, shared.encrypt, shared.seed, shared.host_ip);
	do {	
		sendto(shared.fd, shared.packet, packet_len, 0, &shared.addr.sa, sizeof(shared.addr.inet));
		dprintf(stdout, "-->pppoe: send heartbeat request[%u], %d bytes\n", shared.pppoe_idx, packet_len);
		hprint(shared.packet, packet_len);

		nrecv = recvfrom(shared.fd, shared.packet, sizeof(shared.packet), 0, NULL, 0);
		if (nrecv <= 0) {
#ifdef _WINLIB
			if (__signal_exit() != 0) return 0;
#endif // _WINLIB
			if (++retry_count >= 5) {
				dprintf(stderr, "!--pppoe: recv %d, reset idx to 0x01\n", nrecv);
				return 0;
			} //if
			dprintf(stdout, "!--pppoe: heartbeat response failed, retry %d\n", retry_count);
		} else break; //if
	} while (1);

	dprintf(stdout, "<--pppoe: received challenge response[%u], %d bytes\n", shared.pppoe_idx, nrecv);
	hprint(shared.packet, nrecv);

	++shared.pppoe_idx;

	return 1;
}

//-------------------------------------------------------------------------

static int drcom_heartbeat()
{
	char rand_num[2];
	short rtval = rand() % 0x10000;
	rand_num[0] = rtval / 0x100;
	rand_num[1] = rtval % 0x100;

	int retry_count = 0, packet_len;
	platform_sleep(3);
#ifdef _WINLIB
	if (__signal_exit() != 0) return 0;
#endif // _WINLIB
	while (1) {
		packet_len = construct_keep_alive2_req_first(shared.packet, shared.ka2_idx, shared.ka2_flag, rand_num, shared.ka2_key);
		sendto(shared.fd, shared.packet, packet_len, 0, &shared.addr.sa, sizeof(shared.addr.inet));
		dprintf(stdout, "-->keep-alive2: send request_1[%u], %d bytes\n", shared.ka2_idx, packet_len);
		hprint(shared.packet, packet_len);

		packet_len = recvfrom(shared.fd, shared.packet, sizeof(shared.packet), 0, NULL, 0);
		if (packet_len <= 0) {
#ifdef _WINLIB
			if (__signal_exit() != 0) return 0;
#endif // _WINLIB
			if (++retry_count >= 5) {
				dprintf(stderr, "--!keep-alive2: recv %d, reset idx to 0x01\n", packet_len);
				return 0;
			} //if
			dprintf(stdout, "--!keep-alive2: send request_1 failed, retry %d\n", retry_count);
		} else {
			if (shared.packet[0] == 0x07 && shared.packet[2] == 0x10) {
				memcpy(&shared.ka2_flag, shared.packet + 6, 2);	// dc 02
				dprintf(stdout, "<--keep-alive2: received response_1[%u], %d bytes\n", shared.ka2_idx, packet_len);
				hprint(shared.packet, packet_len);
				dprintf(stdout, "!--keep-alive2: recv file, set flag to %04hx, resending...\n", htons(shared.ka2_flag));
				++shared.ka2_idx;
			} else break; //if
		} //if
	}

	dprintf(stdout, "<--keep-alive2: received response_1[%u], %d bytes\n", shared.ka2_idx, packet_len);
	hprint(shared.packet, packet_len);

	memcpy(&shared.ka2_key, shared.packet + 16, select_min(sizeof(shared.ka2_key), 4));
	++shared.ka2_idx;

	int nrecv;
	retry_count = 0;
	packet_len  = construct_keep_alive2_second(shared.packet, shared.ka2_idx, shared.ka2_flag, rand_num, shared.ka2_key, shared.host_ip);
	do {
		sendto(shared.fd, shared.packet, packet_len, 0, &shared.addr.sa, sizeof(shared.addr.inet));
		dprintf(stdout, "-->keep-alive2: send request_2[%u], %d bytes\n", shared.ka2_idx, packet_len);
		hprint(shared.packet, packet_len);

		nrecv = recvfrom(shared.fd, shared.packet, sizeof(shared.packet), 0, NULL, 0);
		if (nrecv <= 0) {
#ifdef _WINLIB
			if (__signal_exit() != 0) return 0;
#endif // _WINLIB
			if (++retry_count >= 5) {
				dprintf(stderr, "--!keep-alive2: recv %d, reset idx to 0x01\n", nrecv);
				return 0;
			} //if
			dprintf(stdout, "--!keep-alive2: send request_2 failed, retry %d\n", retry_count);
		} else break; //if
	} while (1);
	dprintf(stdout, "<--keep-alive2: received response_2[%u], %d bytes\n", shared.ka2_idx, packet_len);
	hprint(shared.packet, packet_len);

	++shared.ka2_idx;

#ifdef _WINLIB
	if (__signal_exit() != 0) return 0;
#endif // _WINLIB
	platform_sleep(17);

	return 1;
}

//-------------------------------------------------------------------------

static void __cdecl _crt_signal_stop(int _signo)
{
	fflush(stdout);
	fflush(stderr);
	exit(_signo);
}

//-------------------------------------------------------------------------

void heartbeat()
{
	signal(SIGINT, _crt_signal_stop);
	
#ifdef _WINDOWS
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		__fprintf(stderr, "WSAStartup error!\n");
		return;
	} //if
#endif // _WINDOWS

	shared.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (shared.fd == INVALID_SOCKET) {
		__fprintf(stderr, "socket error!\n");
		return;
	} //if

#ifdef _WINDOWS
	int timeout = 2000;
#else
	struct timeval timeout;
	timeout.tv_sec  = 2;
	timeout.tv_usec = 0;
#endif // _WINDOWS
	setsockopt(shared.fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
// 	int sopt = TRUE;
// 	setsockopt(shared.fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&sopt, sizeof(sopt));
// 	setsockopt(shared.fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&sopt, sizeof(sopt));
//	setsockopt(shared.fd, SOL_SOCKET, SO_BROADCAST, (const char *)&sopt, sizeof(sopt));

	shared.addr.inet.sin_family      = AF_INET;
	shared.addr.inet.sin_addr.s_addr = dconfig.localip;
	shared.addr.inet.sin_port        = htons(dconfig.port);
	if (bind(shared.fd, &shared.addr.sa, sizeof(shared.addr.inet)) == -1) {
#ifdef _WINDOWS
		int err = WSAGetLastError();
		if (err == WSAEADDRINUSE) {
			__fprintf(stderr, "bind failed! port %d in used.\n", dconfig.port);
		} else {
			__fprintf(stderr, "bind failed with %d! port %d.\n", err, dconfig.port);
		} //if
#else
		__fprintf(stderr, "bind failed! port %d may in used.\n", dconfig.port);
		return;
#endif // _WINDOWS		
	} //if

	srand(shared.fd + 0U); // moved out
	shared.addr.inet.sin_addr.s_addr = inet_addr(dconfig.server);

	__fprintf(stdout,
			  "auth svr: %s\n"
			  "pppoe_flag: %02hhx\n"
			  "keep_alive2_flag: %02hhx\n"
			  "open local port: %d\n"
			  "checksum mode: %d\n"
			  "cpu arch: %s\n"
			  "DEBUG MODE : %s\n"
			  "\n", dconfig.server, dconfig.pppoe_flag, dconfig.keep_alive2_flag, dconfig.port, dconfig.checksum,
#if (BYTE_ORDER == _BIG_ENDIAN)
			  "BIG_ENDIAN",
#else
			  "LITTLE_ENDIAN",
#endif // BYTE_ORDER == _BIG_ENDIAN
#ifndef NDEBUG
			  "True"
#else
			  "False"
#endif // !NDEBUG
	);

#ifdef NDEBUG
	unsigned long failed_count = 0;
#endif // NDEBUG

__heart_beat_start:
	shared.pppoe_idx = 0x01;
	shared.ka2_idx   = 0x00;
	shared.ka2_key   = 0;
	shared.ka2_flag  = 0;
#ifdef _WINLIB
	while (__signal_exit() == 0)
#else
	while (1) 
#endif // _WINLIB
	{
		if (!pppoe_heartbeat() || !drcom_heartbeat()) {
#ifdef NDEBUG
			// output error always
			if (++failed_count > 3) {
				failed_count = 0;
				__fprintf(stderr, "heartbeat failed!\n");
				platform_sleep(1);
			} //if
#endif // NDEBUG
			goto __heart_beat_start;
		} //if
	}

#ifdef _WINDOWS
	closesocket(shared.fd);
	WSACleanup();
#else
	close(shared.fd);
#endif // !_WINDOWS
}

