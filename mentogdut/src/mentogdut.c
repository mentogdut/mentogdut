#include "mentogdut.h"
#include "windows/lib.h"
#ifdef _WINDOWS
# include "windows/vsgetopt.h"
#else
# include <getopt.h>
#endif // _WINDOWS

//-------------------------------------------------------------------------

int __cdecl __fprintf(FILE* const _Stream, char const* const _Format, ...)
{
	va_list _Args;
	va_start(_Args, _Format);
#ifdef _WINLIB
	char _Msg[1024];
	int  _Ret = vsprintf(_Msg, _Format, _Args);
	if (__lib_fprintf != NULL) {
		__lib_fprintf(_Stream == stderr, _Msg, _Ret);
	} //if
#else
	int _Ret = vfprintf(_Stream, _Format, _Args);
	fflush(_Stream);
#endif // _WINLIB

	va_end(_Args);
	return _Ret;
}

//-------------------------------------------------------------------------

#ifndef _WINLIB

static int print_help(const char *name)
{
	const char *bin = strrchr(name, '/');
	if (bin == NULL) bin = strrchr(name, '\\');
	if (bin == NULL) bin = name - 1;

	__fprintf(stdout,
			  "\033[31m              __      ___  __   __   __       ___    \n"
			  "   /\\    /\\  |__ |\\ |  |  /  \\ / __ |  \\ |  |  |\n"
			  "  /  \\  /  \\ |__ | \\|  |  \\__/ \\__/ |__/ |__|  |\n"
			  " /    \\/    \\ \033[32mA third-party client of Dr.COM 5.2.1(p) for gdut\033[0m\n"
	);
	__fprintf(stdout, "Usage:\n"
			  "     %s -s svrip [-p port] [-f pppoe-flag] [-k keepalive2_flag] [-m checksum]\n", bin + 1);
	__fprintf(stdout, "     %s -c conf\n"
			  "Options:\n", bin + 1);
	__fprintf(stdout,
			  "     -s,--server <ip>               the auth server ip\n"
			  "     [-p,--port <port>]             the auth server port [default: 61440]\n"
			  "     [-f,--pppoe_flag <flag>]       the pppoe flag [default: 6a]\n"
			  "     [-k,--keep_alive2_flag <flag>] the keep alive2 flag [default: dc]\n"
			  "     [-m,--checksum <mode>]         the checksum mode [default: 0 automatic]\n"
			  "     [-c,--config <file>]           the path to configuration file\n"
			  "     [-h,--help]                    give this help\n"
	);

	return 0;
}

//-------------------------------------------------------------------------

int main(int argc, char *argv[])
{
	struct option long_options[] =
	{
		{ "server",           required_argument,  0,  's' },
		{ "port",             required_argument,  0,  'p' },
		{ "pppoe_flag",       required_argument,  0,  'f' },
		{ "keep_alive2_flag", required_argument,  0,  'k' },
		{ "checksum",         required_argument,  0,  'm' },
		{ "config",           required_argument,  0,  'c' },
		{ "help",             no_argument,        0,  'h' },
		{ NULL,               no_argument,        0,  0 },
	};
	int option;
    while ((option = getopt_long(argc, argv, "s:p:f:k:m:c:h", long_options, NULL)) != -1)
    {    
        switch (option)
        {
		case 's': // auth server ip
			strcpy(dconfig.server, optarg);
			break;
		case 'p': // auth server port
			dconfig.port = (unsigned short)atoi(optarg);
			break;
		case 'f': // pppoe_flag
			dconfig.pppoe_flag = strtol(optarg, NULL, 16);
			break;
		case 'k': // keep_alive2_flag
			dconfig.keep_alive2_flag = strtol(optarg, NULL, 16);
			break;
		case 'm': // checksum mode
			dconfig.checksum = atoi(optarg);
			break;
		case 'c': // configuration file
			parse_config(optarg);
			break;
//		case 'h': // help		
		default:
			return print_help(argv[0]);
        }
    }

	if (dconfig.server[0] == '\0') {
		print_help(argv[0]);
	} else {
		heartbeat();
	} //if

    return 0;
}

#endif // !_WINLIB
