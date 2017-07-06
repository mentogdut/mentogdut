#ifdef _WINDOWS
# define _CRT_SECURE_NO_WARNINGS
# define _WINSOCK_DEPRECATED_NO_WARNINGS
# include <winsock2.h>
# include <netiodef.h>
#else
# include <unistd.h>
#endif // _WINDOWS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define select_min(a,b) (((a) < (b)) ? (a) : (b))

#ifndef BYTE_ORDER
# define BYTE_ORDER  __BYTE_ORDER__
#endif // !BYTE_ORDER

#ifndef _BIG_ENDIAN
#define  _BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif // !_BIG_ENDIAN

#ifndef _PDP_ENDIAN
#define  _PDP_ENDIAN __ORDER_PDP_ENDIAN__
#endif // !_PDP_ENDIAN

#ifdef BIG_ENDIAN
# undef BIG_ENDIAN
#endif // BIG_ENDIAN

# ifdef __GNUC__
#  ifdef __clang__
#   pragma clang diagnostic ignored "-Wshift-overflow"
#  elif defined(__INTEL_COMPILER)
    // ignored
#  else
#   pragma gcc diagnostic ignored "-Wshift-overflow"
#   define __cdecl //__attribute__((__cdecl__))
#  endif
# else
   // ignored
# endif

#if (BYTE_ORDER == _BIG_ENDIAN)
# define INT32_LE(v) _byteswap_ulong(v)
# define INT32_LE_INPLACE(v) (((v << 8) & 0x00ff0000) | (v << 24) | ((v >> 8) & 0x0000ff00) | (v >> 24))
#elif (BYTE_ORDER == _PDP_ENDIAN)
# error pdp-endian not supported
#else // BYTE_ORDER == _LITTLE_ENDIAN
# define INT32_LE(v) v
#endif // BYTE_ORDER == _BIG_ENDIAN

#ifndef NDEBUG
# define dprintf(io, f, ...) __fprintf((snprintf(NULL, 0, f, __VA_ARGS__), io), f, __VA_ARGS__)
#else
# define dprintf(io, f, ...) ((void)0)
#endif // !NDEBUG

struct drcom_config {
	unsigned long localip;
    char server[16];
    char pppoe_flag;
	char keep_alive2_flag;
	unsigned short port;
	int  checksum; // 0 auto, 1 no encryption, 2 encryption
};

extern struct drcom_config dconfig;
extern int __cdecl __fprintf(FILE* const _Stream, char const* const _Format, ...);

