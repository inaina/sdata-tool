#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>

typedef unsigned long long u64;

inline int se32(int i)
{
    return ((i & 0xFF000000) >> 24) | ((i & 0xFF0000) >>  8) | ((i & 0xFF00) <<  8) | ((i & 0xFF) << 24);
}

inline u64 se64(u64 i)
{
    return ((i & 0x00000000000000ff) << 56) | ((i & 0x000000000000ff00) << 40) |
		   ((i & 0x0000000000ff0000) << 24) | ((i & 0x00000000ff000000) <<  8) |
           ((i & 0x000000ff00000000) >>  8) | ((i & 0x0000ff0000000000) >> 24) |
           ((i & 0x00ff000000000000) >> 40) | ((i & 0xff00000000000000) >> 56);
}

int sdata_check(int version, int flags, u64 filesizeInput, u64 filesizeTmp)
{
	if (version > 4 || flags & 0x7EFFFFC0){
		printf("ERROR: unknown version");
		return 1;
	}

	if ((version == 1 && (flags & 0x7FFFFFFE)) ||
		(version == 2 && (flags & 0x7EFFFFC0))){
		printf("ERROR: unknown or unsupported type");
		return 1;
	}

	if (filesizeTmp > filesizeInput){
		printf("ERROR: input file size is too short.");
		return 1;
	}

	if (!(flags & 0x80000000)){
		printf("ERROR: cannot extract finalized edata.");
		return 1;
	}

	return 0;
}

int sdata_decompress_block(char *src, int blockSize, char *dest, void *wtf_is_this_shit)
{
	char buffer [3340];
	int k1 = se32(*(int*)&src[1]);
	if (src[0]){
		memset(buffer, 0x80, 3240);
		//TODO
	}
	//TODO
	return 0;
}

void sdata_extract(FILE *input, FILE *output)
{
	//Read header
	char buffer [0x10200];
	fread(buffer, 256, 1, input);
	
	// Check Magic number
	if (se32(*(int*)&buffer[0]) != 0x4E504400){ // "NPD\x00"
		printf("ERROR: illegal format.");
		return;
	}

	// Get filesizes
	fseek(input, 0, SEEK_END);
	u64 filesizeInput = (u64)ftell(input);
	u64 filesizeOutput = se64(*(u64*)&buffer[0x88]);
	fseek(input, 0, SEEK_SET);

	// Read some integers
	int version	   = se32(*(int*)&buffer[0x04]);
	int flags      = se32(*(int*)&buffer[0x80]);
	int blockSize  = se32(*(int*)&buffer[0x84]);
	int blockCount = (filesizeOutput + blockSize-1) / blockSize;


	// SDATA file is compressed
	if (flags & 0x1){
		printf("Warning: Compressed SDATA files are not supported (yet)!");

		char blockHeader [32];
		int startOffset = ((blockCount - 1) * 0x20) + 0x100;
		fseek(input, startOffset, SEEK_SET);
		fread(blockHeader, 32, 1, input);

		u64 i1 = se64(*(u64*)&blockHeader[0x10]);
		int i2 = se32(*(int*)&blockHeader[0x18]);
		u64 filesizeTmp = (i1 + (u64)i2 + 0xF) & 0xFFFFFFF0;

		if (sdata_check(version, flags, filesizeInput, filesizeTmp))
			return;
		
		for (int i = 0; i < blockCount; i++){
			fseek(input, 0x100 + i*0x20, SEEK_SET);
			fread(blockHeader, 32, 1, input);

			u64 i1 = se64(*(u64*)&blockHeader[0x10]); // Pointer to block
			int i2 = se32(*(int*)&blockHeader[0x18]); // Some shit
			int isCompressed = se32(*(int*)&blockHeader[0x1C]);

			int blockSizeCompressed = (i2 + 0xF) & 0xFFFFFFF0;
			if (blockSizeCompressed > 0x8000){
				printf("ERROR: illegal format.");
				return;
			}
			fseek(input, i1, SEEK_SET);
			fread(buffer+256, blockSizeCompressed, 1, input);
			if (!isCompressed){
				fwrite(buffer+256, blockSizeCompressed, 1, output);
				continue;
			}
			if (sdata_decompress_block(buffer+256, blockSize, buffer+256+0x8000, NULL)){
				printf("ERROR: data expand error.");
				return;
			}
			fwrite(buffer+256+0x8000, blockSize, 1, output);
		}
	}
	
	// SDATA file is NOT compressed
	else{
		int t1 = (flags & 0x20) ? 0x20 : 0x10;
		int startOffset = (blockCount * t1) + 0x100;
		u64 filesizeTmp = (filesizeOutput+0xF)&0xFFFFFFF0 + startOffset;

		if (sdata_check(version, flags, filesizeInput, filesizeTmp))
			return;
	
		if (flags & 0x20)
			fseek(input, 0x100, SEEK_SET);
		else
			fseek(input, startOffset, SEEK_SET);

		for (int i = 0; i < blockCount; i++){

			if (flags & 0x20)
				fseek(input, ftell(input)+t1, SEEK_SET);
			if (!(blockCount-i-1))
				blockSize = filesizeOutput-i*blockSize;

			fread(buffer+256, blockSize, 1, input);
			fwrite(buffer+256, blockSize, 1, output);
		}
	}
}
	
int main(int argc, char **argv)
{
	if (argc <= 1){
		printf("Usage: sdata-tool <input> <output>\n");
		return 0;
	}

    FILE* input = fopen(argv[1], "rb");
    FILE* output = fopen(argv[2], "wb");
    sdata_extract(input, output);

	fclose(input);
	fclose(output);
    return 0;
}