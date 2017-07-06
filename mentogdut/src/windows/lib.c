#ifdef _WINLIB
#include "lib.h"
#include <stdlib.h>

//-------------------------------------------------------------------------

int (__cdecl *__signal_exit)() = NULL;
void(__cdecl *__alertable_wait)(unsigned long milliseconds) = NULL;
void(__cdecl *__lib_fprintf)(int bstderr, char *lpszmsg, int length) = NULL;

#endif // _WINLIB