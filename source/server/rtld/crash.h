#ifndef CRASH_H
#define CRASH_H

#define crash() \
	do { \
		printf("%s:%d called crash()\n", __FILE__, __LINE__); \
		fflush(stdout); \
		fflush(stderr); \
		(*(unsigned char *)NULL) = 0xcc; \
	} while(0)

#endif
