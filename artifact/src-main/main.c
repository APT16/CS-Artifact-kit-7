/*
 * Cobalt Strike Artifact Kit
 *
 * (c) 2012-2024 Fortra, LLC and its group of companies. All trademarks and registered trademarks are the property of their respective owners.
 *

 *
 * This is a plain jane executable
 */

#include "windows.h"

void start(HINSTANCE handle);

int main(int argc, char * argv[]) {
	start(NULL);

	/* sleep so we don't exit */
	while (TRUE)
		WaitForSingleObject(GetCurrentProcess(), 10000);

	return 0;
}
