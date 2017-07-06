#pragma once
#ifndef MENTOGDUT_LIB
# define MENTOGDUT_LIB
#endif // !MENTOGDUT_LIB

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern int  (__cdecl *__signal_exit)();
extern void (__cdecl *__alertable_wait)(unsigned long milliseconds);
extern void (__cdecl *__lib_fprintf)(int bstderr, char *lpszmsg, int length);
extern void parse_config(const char *);
extern void heartbeat();
extern void set_host_ip(unsigned long ip);

#ifdef __cplusplus
}
#endif // __cplusplus