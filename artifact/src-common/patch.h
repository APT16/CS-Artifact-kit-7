/*
 * Artifact Kit - A means to disguise and inject our payloads... *pHEAR*
 * (c) 2012-2024 Fortra, LLC and its group of companies. All trademarks and registered trademarks are the property of their respective owners.
 *
 *
 * Shared code to accept a binary patch in a way that's compatible with
 * the Cortana script artifact.cna.
 *
 * If you choose to modify the patching process--you will need to modify
 * this file and recompile the artifact kit.
 */

#pragma once

void spawn(void * buffer, int length, char * key);

typedef struct {
	int  offset;
	int  length;
	char key[8]; // 8 byte XoR
	int  gmh_offset;
	int  gpa_offset;
	char payload[DATA_SIZE];
} phear;



extern char data[sizeof(phear)];

