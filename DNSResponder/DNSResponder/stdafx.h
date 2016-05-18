///Daniel Whatley
///CSCE 463-500 Spring 2016

// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#define _GNU_SOURCE

#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <cstring>
#include <ctime>
#include <cstdlib>

// STL stuff
#include <fstream>
#include <string>
#include <set>
#include <queue>
#include <algorithm>
// END STL stuff

#include <windows.h>
#include <shlwapi.h>

//#include <winsock2.h>
//#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define _return(a)        WSACleanup(); exit(a)

// TODO: reference additional headers your program requires here
