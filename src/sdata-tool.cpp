#define _CRT_SECURE_NO_WARNINGS
#include "sdata-tool.h"

typedef unsigned long long u64;

// Auxiliary functions (endian swap and xor).
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

void xor(unsigned char *dest, unsigned char *src1, unsigned char *src2, int size)
{
	int i;
	for(i = 0; i < size; i++)
	{
		dest[i] = src1[i] ^ src2[i];
	}
}

// Crypto functions (AES128-CBC, AES128-ECB, SHA1-HMAC and AES-CMAC).
void aescbc128_decrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len)
{
	aes_context ctx;
	aes_setkey_dec(&ctx, key, 128);
	aes_crypt_cbc(&ctx, AES_DECRYPT, len, iv, in, out);

	// Reset the IV.
	memset(iv, 0, 0x10);
}

void aesecb128_encrypt(unsigned char *key, unsigned char *in, unsigned char *out)
{
	aes_context ctx;
	aes_setkey_enc(&ctx, key, 128);
	aes_crypt_ecb(&ctx, AES_ENCRYPT, in, out);
}

bool hmac_hash_compare(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash)
{
	unsigned char *out = new unsigned char[key_len];

	sha1_hmac(key, key_len, in, in_len, out);

	for (int i = 0; i < 0x10; i++)
	{
		if (out[i] != hash[i])
		{
			delete[] out;
			return false;
		}
	}

	delete[] out;

	return true;
}

bool cmac_hash_compare(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash)
{
	unsigned char *out = new unsigned char[key_len];

	aes_context ctx;
	aes_setkey_enc(&ctx, key, 128);
	aes_cmac(&ctx, in_len, in, out);

	for (int i = 0; i < key_len; i++)
	{
		if (out[i] != hash[i])
		{
			delete[] out;
			return false;
		}
	}

	delete[] out;

	return true;
}

void generate_key(int crypto_mode, int version, unsigned char *key_final, unsigned char *iv_final, unsigned char *key, unsigned char *iv) {
	int mode = (int) (crypto_mode & 0xF0000000);
	switch (mode) {
	case 0x10000000:
		// Encrypted ERK.
		// Decrypt the key with EDAT_KEY + EDAT_IV and copy the original IV.
		aescbc128_decrypt(version ? EDAT_KEY_1 : EDAT_KEY_0, EDAT_IV, key, key_final, 0x10);
		memcpy(iv_final, iv, 0x10);
		break;
	case 0x20000000:
		// Default ERK.
		// Use EDAT_KEY and EDAT_IV.
		memcpy(key_final, version ? EDAT_KEY_1 : EDAT_KEY_0, 0x10);
		memcpy(iv_final, EDAT_IV, 0x10);
		break;
	case 0x00000000:
		// Unencrypted ERK.
		// Use the original key and iv.
		memcpy(key_final, key, 0x10);
		memcpy(iv_final, iv, 0x10);
		break;
	};
}

void generate_hash(int hash_mode, int version, unsigned char *hash_final, unsigned char *hash) {
	int mode = (int) (hash_mode & 0xF0000000);
	switch (mode) {
	case 0x10000000:
		// Encrypted HASH.
		// Decrypt the hash with EDAT_KEY + EDAT_IV.
		aescbc128_decrypt(version ? EDAT_KEY_1 : EDAT_KEY_0, EDAT_IV, hash, hash_final, 0x10);
		break;
	case 0x20000000:
		// Default HASH.
		// Use EDAT_HASH.
		memcpy(hash_final, version ? EDAT_HASH_1 : EDAT_HASH_0, 0x10);
		break;
	case 0x00000000:
		// Unencrypted ERK.
		// Use the original hash.
		memcpy(hash_final, hash, 0x10);
		break;
	};
}

bool crypto(int hash_mode, int crypto_mode, int version, unsigned char *in, unsigned char *out, int lenght, unsigned char *key, unsigned char *iv, unsigned char *hash, unsigned char *test_hash) 
{
	// Setup buffers for key, iv and hash.
	unsigned char key_final[0x10] = {};
	unsigned char iv_final[0x10] = {};
	unsigned char hash_final_10[0x10] = {};
	unsigned char hash_final_14[0x14] = {};

	// Generate crypto key and hash.
	generate_key(crypto_mode, version, key_final, iv_final, key, iv);
	if ((hash_mode & 0xFF) == 0x01)
		generate_hash(hash_mode, version, hash_final_14, hash);
	else
		generate_hash(hash_mode, version, hash_final_10, hash);

	if ((crypto_mode & 0xFF) == 0x01)  // No algorithm.
	{
		memcpy(out, in, lenght);
	}
	else if ((crypto_mode & 0xFF) == 0x02)  // AES128-CBC
	{
		aescbc128_decrypt(key_final, iv_final, in, out, lenght);
	}
	else
	{
		printf("ERROR: Unknown crypto algorithm!\n");
		return false;
	}

	if ((hash_mode & 0xFF) == 0x01) // 0x14 SHA1-HMAC
	{
		return hmac_hash_compare(hash_final_14, 0x14, in, lenght, test_hash);
	}
	else if ((hash_mode & 0xFF) == 0x02)  // 0x10 AES-CMAC
	{
		return cmac_hash_compare(hash_final_10, 0x10, in, lenght, test_hash);
	}
	else if ((hash_mode & 0xFF) == 0x04) //0x10 SHA1-HMAC
	{
		return hmac_hash_compare(hash_final_10, 0x10, in, lenght, test_hash);
	}
	else
	{
		printf("ERROR: Unknown hashing algorithm!\n");
		return false;
	}
}

unsigned char* dec_section(unsigned char* metadata) {
	unsigned char* dec = new unsigned char[0x10];
	dec[0x00] = (metadata[0xC] ^ metadata[0x8] ^ metadata[0x10]);
	dec[0x01] = (metadata[0xD] ^ metadata[0x9] ^ metadata[0x11]);
	dec[0x02] = (metadata[0xE] ^ metadata[0xA] ^ metadata[0x12]);
	dec[0x03] = (metadata[0xF] ^ metadata[0xB] ^ metadata[0x13]);
	dec[0x04] = (metadata[0x4] ^ metadata[0x8] ^ metadata[0x14]);
	dec[0x05] = (metadata[0x5] ^ metadata[0x9] ^ metadata[0x15]);
	dec[0x06] = (metadata[0x6] ^ metadata[0xA] ^ metadata[0x16]);
	dec[0x07] = (metadata[0x7] ^ metadata[0xB] ^ metadata[0x17]);
	dec[0x08] = (metadata[0xC] ^ metadata[0x0] ^ metadata[0x18]);
	dec[0x09] = (metadata[0xD] ^ metadata[0x1] ^ metadata[0x19]);
	dec[0x0A] = (metadata[0xE] ^ metadata[0x2] ^ metadata[0x1A]);
	dec[0x0B] = (metadata[0xF] ^ metadata[0x3] ^ metadata[0x1B]);
	dec[0x0C] = (metadata[0x4] ^ metadata[0x0] ^ metadata[0x1C]);
	dec[0x0D] = (metadata[0x5] ^ metadata[0x1] ^ metadata[0x1D]);
	dec[0x0E] = (metadata[0x6] ^ metadata[0x2] ^ metadata[0x1E]);
	dec[0x0F] = (metadata[0x7] ^ metadata[0x3] ^ metadata[0x1F]);
	return dec;
}

unsigned char* get_block_key(int block, NPD_HEADER *npd) {
	unsigned char empty_key[0x10] = {};
	unsigned char* src_key = (npd->version <= 1) ? empty_key : npd->dev_hash;
	unsigned char* dest_key = new unsigned char[0x10];
	memcpy(dest_key, src_key, 0xC);
	dest_key[0xC] = (block >> 24 & 0xFF);
	dest_key[0xD] = (block >> 16 & 0xFF);
	dest_key[0xE] = (block >> 8 & 0xFF);
	dest_key[0xF] = (block & 0xFF);
	return dest_key;
}

// SDAT functions.
int sdata_decompress(unsigned char *out, unsigned char *in, unsigned int size)
{
	char *tmp = new char[3272];
	char *p;
	char *p2;
	char *sub;
	char *sub2;
	char *sub3;
	int offset;
	int index;
	int index2;
	int unk;

	int flag;
	int flag2;
	unsigned int c;
	int cc;
	int sp;
	unsigned int sc;
	int scc;
	char st;
	char t;
	unsigned int n_size;
	unsigned int r_size;
	signed int f_size;
	signed int b_size;
	signed int diff;
	signed int diff_pad;

	int pos;
	int end;
	int n_end;
	signed int end_size;
	int chunk_size;
	char pad;
	unsigned int remainder;
	int result;

	offset = 0;
	index = 0;
	remainder = -1;
	end = (int)((char *)out + size);
	pos = (int)in;
	pad = *in;
	chunk_size = (*(in + 1) << 24) | (*(in + 2) << 16) | (*(in + 3) << 8) | *(in + 4);

	if (*in >= 0) // Check if we have a valid starting byte.
	{
		memset(tmp, 128, 0xCA8u);
		end_size = 0;
		while (1)
		{
			while (1)
			{
				p = &tmp[offset];
				c = (unsigned char)tmp[offset + 2920];

				if (!(remainder >> 24))
				{
					int add = *(unsigned char *)(pos + 5);
					remainder <<= 8;
					++pos;
					chunk_size = (chunk_size << 8) + add;
				}

				cc = c - (c >> 3);
				r_size = c * (remainder >> 8);
				f_size = (unsigned int)chunk_size < r_size;

				if ((unsigned int)chunk_size < r_size)
					break;

				remainder -= r_size;
				chunk_size -= r_size;
				p[2920] = cc;
				offset = (offset - 1) & ((u64)~(offset - 1) >> 32);

				if (out == (void *)end)
					return -1;

				sub = &tmp[255 * ((((((unsigned char)out & 7) << 8) | index & 0xFFFFF8FFu) >> pad) & 7)];
				index = 1;

				do
				{
					sp = (int)&sub[index];
					sc = (unsigned char)sub[index - 1];

					if (!(remainder >> 24))
					{
						int add = *(unsigned char *)(pos++ + 5);
						remainder <<= 8;
						chunk_size = (chunk_size << 8) + add;
					}

					index *= 2;
					n_size = sc * (remainder >> 8);
					scc = sc - (sc >> 3);
					st = scc;

					if ((unsigned int)chunk_size < n_size)
					{
						remainder = n_size;
						++index;
						st = scc + 31;
					}
					else
					{
						remainder -= n_size;
						chunk_size -= n_size;
					}
					*(unsigned char *)(sp - 1) = st;
				}
				while (index <= 255);

				out += 1;
				++end_size;
				*(out - 1) = index;
			}

			remainder = c * (remainder >> 8);
			p[2920] = cc + 31;
			index = -1;

			while (1)
			{
				c = (unsigned char)p[2928];

				if (!(r_size >> 24))
				{
					int add = *(unsigned char *)(pos++ + 5);
					remainder = r_size << 8;
					chunk_size = (chunk_size << 8) + add;
				}

				p += 8;
				r_size = c * (remainder >> 8);
				cc = c - (c >> 3);

				if ((unsigned int)chunk_size >= r_size)
					break;

				remainder = r_size;
				p[2920] = cc + 31;
				++index;

				if (index == 6)
					goto SKIP;

			}
			remainder -= r_size;
			chunk_size -= r_size;
			p[2920] = cc;
SKIP:
			p2 = &tmp[index];
			if (index >= 0)
			{
				sub3 = &tmp[offset & 7 | 8 * (((unsigned int)out << index) & 3) | 32 * index];
				flag = index - 3;
				c = (unsigned char)sub3[2984];

				if (!(remainder >> 24))
				{
					int add = *(unsigned char *)(pos++ + 5);
					remainder <<= 8;
					chunk_size = (chunk_size << 8) + add;
				}

				n_size = c * (remainder >> 8);
				cc = c - (c >> 3);
				t = cc;
				index2 = 2;

				if ((unsigned int)chunk_size >= n_size)
				{
					remainder -= n_size;
					chunk_size -= n_size;
				}
				else
				{
					remainder = n_size;
					index2 = 3;
					t = cc + 31;
				}

				if (flag < 0)
				{
					sub3[2984] = t;
				}
				else
				{
					if (flag <= 0)
					{
						sub3[2984] = t;
					}
					else
					{
						c = (unsigned char)t;

						if (!(remainder >> 24))
						{
							int add = *(unsigned char *)(pos++ + 5);
							remainder <<= 8;
							chunk_size = (chunk_size << 8) + add;
						}
						index2 *= 2;
						n_size = c * (remainder >> 8);
						cc = c - (c >> 3);
						t = cc;

						if ((unsigned int)chunk_size >= n_size)
						{
							remainder -= n_size;
							chunk_size -= n_size;
						}
						else
						{
							remainder = n_size;
							++index2;
							t = cc + 31;
						}
						sub3[2984] = t;

						if (flag != 1)
						{
							if (!(remainder >> 24))
							{
								int add = *(unsigned char *)(pos + 5);
								remainder <<= 8;
								++pos;
								chunk_size = (chunk_size << 8) + add;
							}
							do
							{
								remainder >>= 1;
								index2 = ((unsigned int)chunk_size < remainder) + 2 * index2;

								if ((unsigned int)chunk_size >= remainder)
									chunk_size -= remainder;

								--flag;
							}
							while (flag != 1);
						}
					}
					c = (unsigned char)sub3[3008];

					if (!(remainder >> 24))
					{
						int add = *(unsigned char *)(pos + 5);
						remainder <<= 8;
						++pos;
						chunk_size = (chunk_size << 8) + add;
					}
					index2 *= 2;
					n_size = c * (remainder >> 8);
					cc = c - (c >> 3);
					t = cc;

					if ((unsigned int)chunk_size >= n_size)
					{
						remainder -= n_size;
						chunk_size -= n_size;
					}
					else
					{
						remainder = n_size;
						++index2;
						t = cc + 31;
					}
					sub3[3008] = t;
				}
				if (index > 0)
				{
					c = (unsigned char)sub3[2992];

					if (!(remainder >> 24))
					{
						int add = *(unsigned char *)(pos++ + 5);
						remainder <<= 8;
						chunk_size = (chunk_size << 8) + add;
					}

					index2 *= 2;
					n_size = c * (remainder >> 8);
					cc = c - (c >> 3);
					t = cc;

					if ((unsigned int)chunk_size >= n_size)
					{
						remainder -= n_size;
						chunk_size -= n_size;
					}
					else
					{
						remainder = n_size;
						++index2;
						t = cc + 31;
					}
					sub3[2992] = t;

					if (index != 1)
					{
						c = (unsigned char)sub3[3000];

						if (!(remainder >> 24))
						{
							int add = *(unsigned char *)(pos + 5);
							remainder <<= 8;
							++pos;
							chunk_size = (chunk_size << 8) + add;
						}

						index2 *= 2;
						n_size = c * (remainder >> 8);
						cc = c - (c >> 3);
						t = cc;

						if ((unsigned int)chunk_size >= n_size)
						{
							remainder -= n_size;
							chunk_size -= n_size;
						}
						else
						{
							remainder = n_size;
							++index2;
							t = cc + 31;
						}
						sub3[3000] = t;
					}
				}
				f_size = index2;

				if (index2 == 255)
					break;
			}
			index = 8;
			b_size = 352;

			if (f_size <= 2)
			{
				p2 += 248;
				b_size = 64;
			}
			do
			{
				unk = (int)&p2[index];

				if (!(remainder >> 24))
				{
					int add = *(unsigned char *)(pos++ + 5);
					remainder <<= 8;
					chunk_size = (chunk_size << 8) + add;
				}

				c = *(unsigned char *)(unk + 2033);
				index *= 2;
				n_size = c * (remainder >> 8);
				cc = c - (c >> 3);
				t = cc;

				if ((unsigned int)chunk_size < n_size)
				{
					remainder = n_size;
					t = cc + 31;
					index += 8;
				}
				else
				{
					remainder -= n_size;
					chunk_size -= n_size;
				}
				*(unsigned char *)(unk + 2033) = t;
				diff = index - b_size;
			}
			while ((index - b_size) < 0);

			if (index != b_size)
			{
				diff_pad = diff >> 3;
				flag = diff_pad - 1;
				flag2 = diff_pad - 4;
				sub2 = &tmp[32 * (diff_pad - 1)];
				c = (unsigned char)sub2[2344];

				if (!(remainder >> 24))
				{
					int add = *(unsigned char *)(pos + 5);
					remainder <<= 8;
					++pos;
					chunk_size = (chunk_size << 8) + add;
				}

				n_size = c * (remainder >> 8);
				cc = c - (c >> 3);
				t = cc;
				index2 = 2;

				if ((unsigned int)chunk_size >= n_size)
				{
					remainder -= n_size;
					chunk_size -= n_size;
				}
				else
				{
					remainder = n_size;
					index2 = 3;
					t = cc + 31;
				}

				if (flag2 < 0)
				{
					sub2[2344] = t;
				}
				else
				{
					if (flag2 <= 0)
					{
						sub2[2344] = t;
					}
					else
					{
						c = (unsigned char)t;

						if (!(remainder >> 24))
						{
							int add = *(unsigned char *)(pos++ + 5);
							remainder <<= 8;
							chunk_size = (chunk_size << 8) + add;
						}

						index2 *= 2;
						n_size = c * (remainder >> 8);
						cc = c - (c >> 3);
						t = cc;

						if ((unsigned int)chunk_size >= n_size)
						{
							remainder -= n_size;
							chunk_size -= n_size;
						}
						else
						{
							remainder = n_size;
							++index2;
							t = cc + 31;
						}
						sub2[2344] = t;

						if (flag2 != 1)
						{
							if (!(remainder >> 24))
							{
								int add = *(unsigned char *)(pos + 5);
								remainder <<= 8;
								++pos;
								chunk_size = (chunk_size << 8) + add;
							}
							do
							{
								remainder >>= 1;
								index2 = ((unsigned int)chunk_size < remainder) + 2 * index2;

								if ((unsigned int)chunk_size >= remainder)
									chunk_size -= remainder;

								--flag2;
							}
							while (flag2 != 1);
						}
					}
					c = (unsigned char)sub2[2368];

					if (!(remainder >> 24))
					{
						int add = *(unsigned char *)(pos + 5);
						remainder <<= 8;
						++pos;
						chunk_size = (chunk_size << 8) + add;
					}

					index2 *= 2;
					n_size = c * (remainder >> 8);
					cc = c - (c >> 3);
					t = cc;

					if ((unsigned int)chunk_size >= n_size)
					{
						remainder -= n_size;
						chunk_size -= n_size;
					}
					else
					{
						remainder = n_size;
						++index2;
						t = cc + 31;
					}
					sub2[2368] = t;
				}
				if (flag > 0)
				{
					c = (unsigned char)sub2[2352];
					if (!(remainder >> 24))
					{
						int add = *(unsigned char *)(pos++ + 5);
						remainder <<= 8;
						chunk_size = (chunk_size << 8) + add;
					}
					index2 *= 2;
					n_size = c * (remainder >> 8);
					cc = c - (c >> 3);
					t = cc;
					if ((unsigned int)chunk_size >= n_size)
					{
						remainder -= n_size;
						chunk_size -= n_size;
					}
					else
					{
						remainder = n_size;
						++index2;
						t = cc + 31;
					}
					sub2[2352] = t;
					if (flag != 1)
					{
						c = (unsigned char)sub2[2360];
						if (!(remainder >> 24))
						{
							int add = *(unsigned char *)(pos + 5);
							remainder <<= 8;
							++pos;
							chunk_size = (chunk_size << 8) + add;
						}
						index2 *= 2;
						n_size = c * (remainder >> 8);
						cc = c - (c >> 3);
						t = cc;

						if ((unsigned int)chunk_size >= n_size)
						{
							remainder -= n_size;
							chunk_size -= n_size;
						}
						else
						{
							remainder = n_size;
							++index2;
							t = cc + 31;
						}
						sub2[2360] = t;
					}
				}
				diff = index2 - 1;
			}

			if (end_size <= diff)
				return -1;

			index = *(out - diff - 1);
			n_end = (int)(out + f_size);
			offset = (((unsigned char)f_size + (unsigned char)out) & 1) + 6;

			if ((unsigned int)(out + f_size) >= (unsigned int)end)
				return -1;

			do
			{
				out += 1;
				++end_size;
				*(out - 1) = index;
				index = *(out - diff - 1);
			}
			while (out != (void *)n_end);

			out += 1;
			++end_size;
			*((unsigned char *)out - 1) = index;
		}
		result = end_size;
	}
	else // Starting byte is invalid.
	{
		result = -1;
		if (chunk_size <= (int)size)
		{
			memcpy(out, (const void *)(in + 5), chunk_size);
			result = chunk_size;
		}
	}
	delete[] tmp;

	return result;
}

int sdata_decrypt(FILE *in, FILE *out, SDAT_HEADER *sdat, NPD_HEADER *npd, unsigned char* crypt_key)
{
	// Get metadata info and setup buffers.
	int block_num = (int) ((sdat->file_size + sdat->block_size - 1) / sdat->block_size);
	int metadata_section_size = ((sdat->flags & SDAT_COMPRESSED_FLAG) != 0 || (sdat->flags & SDAT_FLAG_0x20) != 0) ? 0x20 : 0x10;
	int metadata_offset = 0x100;

	unsigned char *enc_data;
	unsigned char *dec_data;
	unsigned char *b_key;
	unsigned char *iv;

	unsigned char empty_iv[0x10] = {};

	// Decrypt the metadata.
	int i;
	for (i = 0; i < block_num; i++) {
		fseek(in, metadata_offset + i * metadata_section_size, SEEK_SET);
		unsigned char hash_result[0x10];
		long offset;
		int lenght;
		int compression_end = 0;

		if ((sdat->flags & SDAT_COMPRESSED_FLAG) != 0) {
			unsigned char metadata[0x20];
			fread(metadata, 0x20, 1, in);

			// If the data is compressed, decrypt the metadata.
			unsigned char *result = dec_section(metadata);
			offset = ((se32(*(int*)&result[0]) << 4) | (se32(*(int*)&result[4])));
			lenght = se32(*(int*)&result[8]);
			compression_end = se32(*(int*)&result[12]);
			delete[] result;

			memcpy(hash_result, metadata, 0x10);
		} else if ((sdat->flags & SDAT_FLAG_0x20) != 0) {
			unsigned char metadata[0x20];
			fread(metadata, 0x20, 1, in);

			// If FLAG 0x20 is set, apply custom xor.
			int j;
			for (j = 0; j < 0x10; j++) {
				hash_result[j] = (unsigned char)(metadata[j] ^ metadata[j+0x10]);
			}

			offset = metadata_offset + i * sdat->block_size + (i + 1) * metadata_section_size;
			lenght = sdat->block_size;
			if (i == (block_num - 1)) {
				lenght = (int) (sdat->file_size % sdat->block_size);
			}
		} else {
			fread(hash_result, 0x10, 1, in);
			offset = metadata_offset + i * sdat->block_size + block_num * metadata_section_size;
			lenght = sdat->block_size;
			if (i == (block_num - 1)) {
				lenght = (int) (sdat->file_size % sdat->block_size);
			}

		}

		// Locate the real data.
		int pad_lenght = lenght;
		lenght = (int) ((pad_lenght + 0xF) & 0xFFFFFFF0);
		fseek(in, offset, SEEK_SET);

		// Setup buffers for decryption and read the data.
		enc_data = new unsigned char[lenght];
		dec_data = new unsigned char[lenght];
		unsigned char key_result[0x10];
		unsigned char hash[0x10];
		fread(enc_data, lenght, 1, in);

		// Generate a key for the current block.
		b_key = get_block_key(i, npd);

		// Encrypt the block key with the crypto key.
		aesecb128_encrypt(crypt_key, b_key, key_result);
		if ((sdat->flags & SDAT_FLAG_0x10) != 0) {
			aesecb128_encrypt(crypt_key, key_result, hash);  // If FLAG 0x10 is set, encrypt again to get the final hash.
		} else {
			memcpy(hash, key_result, 0x10);
		}

		// Setup the crypto and hashing mode based on the extra flags.
		int crypto_mode = ((sdat->flags & SDAT_FLAG_0x02) == 0) ? 0x2 : 0x1;
		int hash_mode;

		if ((sdat->flags  & SDAT_FLAG_0x10) == 0) {
			hash_mode = 0x02;
		} else if ((sdat->flags & SDAT_FLAG_0x20) == 0) {
			hash_mode = 0x04;
		} else {
			hash_mode = 0x01;
		}

		if ((sdat->flags  & SDAT_ENCRYPTED_KEY_FLAG) != 0) {
			crypto_mode |= 0x10000000;
			hash_mode |= 0x10000000;
		}

		if ((sdat->flags  & SDAT_DEBUG_DATA_FLAG) != 0) {
			// Reset the flags.
			crypto_mode |= 0x01000000;
			hash_mode |= 0x01000000;
			// Simply copy the data without the header or the footer.
			memcpy(dec_data, enc_data, lenght);
		} else {
			// IV is null if NPD version is 1 or 0.
			iv = (npd->version <= 1) ? empty_iv : npd->digest;
			// Call main crypto routine on this data block.
			if (!crypto(hash_mode, crypto_mode, (npd->version == 4), enc_data, dec_data, lenght, key_result, iv, hash, hash_result))
				return 1;
		}

		// Apply additional compression if needed and write the decrypted data.
		if (((sdat->flags & SDAT_COMPRESSED_FLAG) != 0) && compression_end) {
			int decomp_size = (int)sdat->file_size;
			unsigned char *decomp_data = new unsigned char[decomp_size];
			memset(decomp_data, 0, decomp_size);

			printf("Decompressing SDATA...\n");
			int res = sdata_decompress(decomp_data, dec_data, decomp_size);
			fwrite(decomp_data, res, 1, out);

			printf("Compressed block size: %d\n", pad_lenght);
			printf("Decompressed block size: %d\n", res);

			sdat->file_size -= res;

			if (sdat->file_size == 0) 
			{
				if (res < 0)
					printf("SDATA decompression failed!\n");
				else
					printf("SDATA successfully decompressed!\n");	
			}

			delete[] decomp_data;
		} else {
			fwrite(dec_data, pad_lenght, 1, out);
		}

		delete[] enc_data;
		delete[] dec_data;
	}

	return 0;
}

int sdata_check(unsigned char *key, SDAT_HEADER *sdat, NPD_HEADER *npd, FILE *f)
{
	fseek(f, 0, SEEK_SET);
	unsigned char *header = new unsigned char[0xA0];
	unsigned char *tmp = new unsigned char[0xA0];
	unsigned char *hash_result = new unsigned char[0x10];

	// Check NPD version and SDAT flags.
	if ((npd->version == 0) || (npd->version == 1))
	{
		if (sdat->flags & 0x7EFFFFFE) 
		{
			printf("ERROR: Bad header flags!\n");
			return 1;
		}
	}
	else if (npd->version == 2) 
	{
		if (sdat->flags & 0x7EFFFFE0) 
		{
			printf("ERROR: Bad header flags!\n");
			return 1;
		}
	}
	else if ((npd->version == 3) || (npd->version == 4))
	{
		if (sdat->flags & 0x7EFFFFC0)
		{
			printf("ERROR: Bad header flags!\n");
			return 1;
		}
	}
	else
	{
		printf("ERROR: Unknown version!\n");
		return 1;
	}

	// Read in the file header.
	fread(header, 0xA0, 1, f);
	fread(hash_result, 0x10, 1, f);

	// Setup the hashing mode and the crypto mode used in the file.
	int crypto_mode = 0x1;
	int hash_mode = ((sdat->flags & SDAT_ENCRYPTED_KEY_FLAG) == 0) ? 0x00000002 : 0x10000002;
	if ((sdat->flags & SDAT_DEBUG_DATA_FLAG) != 0) {
		printf("DEBUG data detected!\n");
		hash_mode |= 0x01000000;
	}

	// Setup header key and iv buffers.
	unsigned char header_key[0x10] = {};
	unsigned char header_iv[0x10] = {};

	// Test the header hash (located at offset 0xA0).
	if (!crypto(hash_mode, crypto_mode, (npd->version == 4), header, tmp, 0xA0, header_key, header_iv, key, hash_result))
		printf("WARNING: Header hash is invalid!\n");

	// Parse the metadata info.
	int metadata_section_size = 0x10;
	if (((sdat->flags & SDAT_COMPRESSED_FLAG) != 0)) {
		printf("COMPRESSED data detected!\n");
		metadata_section_size = 0x20;
	}
	int block_num = (int) ((sdat->file_size + sdat->block_size - 11) / sdat->block_size);
	int bytes_read = 0;
	int metadata_offset = 0x100;

	long bytes_to_read = metadata_section_size * block_num;
	while (bytes_to_read > 0) {
		// Locate the metadata blocks.
		int block_size = (0x3C00 > bytes_to_read) ? (int) bytes_to_read : 0x3C00;  // 0x3C00 is the maximum block size.
		fseek(f, metadata_offset + bytes_read, SEEK_SET);
		unsigned char *data = new unsigned char[block_size];

		// Read in the metadata.
		tmp = new unsigned char[block_size];
		fread(data, block_size, 1, f);

		// Check the generated hash against the metadata hash located at offset 0x90 in the header.
		memset(hash_result, 0, 0x10);
		fseek(f, 0x90, SEEK_SET);
		fread(hash_result, 0x10, 1, f);

		// Generate the hash for this block.
		if (!crypto(hash_mode, crypto_mode, (npd->version == 4), data, tmp, block_size, header_key, header_iv, key, hash_result))
			printf("WARNING: Metadata hash from block 0x%08x is invalid!\n", metadata_offset + bytes_read);

		// Adjust sizes.
		bytes_read += block_size;
		bytes_to_read -= block_size;

		delete[] data;
	}

	// Cleanup.
	delete[] header;
	delete[] tmp;
	delete[] hash_result;

	return 0;
}

void sdata_extract(FILE *input, FILE *output)
{
	// Setup NPD and SDAT structs.
	NPD_HEADER *NPD = new NPD_HEADER();
	SDAT_HEADER *SDAT = new SDAT_HEADER();

	// Read in the NPD and SDAT headers.
	char npd_header[0x80];
	char sdat_header[0x10];
	fread(npd_header, sizeof(npd_header), 1, input);
	fread(sdat_header, sizeof(sdat_header), 1, input);

	memcpy(NPD->magic, npd_header, 4);
	NPD->version = se32(*(int*)&npd_header[4]);
	NPD->license = se32(*(int*)&npd_header[8]);
	NPD->type = se32(*(int*)&npd_header[12]);
	memcpy(NPD->content_id, (unsigned char*)&npd_header[16], 0x30);
	memcpy(NPD->digest, (unsigned char*)&npd_header[64], 0x10);
	memcpy(NPD->title_hash, (unsigned char*)&npd_header[80], 0x10);
	memcpy(NPD->dev_hash, (unsigned char*)&npd_header[96], 0x10);
	NPD->unk1 = se64(*(u64*)&npd_header[112]);
	NPD->unk2 = se64(*(u64*)&npd_header[120]);

	unsigned char npd_magic[4] = {0x4E, 0x50, 0x44, 0x00};  //NPD0
	if(memcmp(NPD->magic, npd_magic, 4)) {
		printf("ERROR: File has invalid NPD header.");
		return;
	}

	SDAT->flags = se32(*(int*)&sdat_header[0]);
	SDAT->block_size = se32(*(int*)&sdat_header[4]);
	SDAT->file_size = se64(*(u64*)&sdat_header[8]);

	if(!(SDAT->flags & SDAT_FLAG)) {
		printf("ERROR: File is not SDAT.");
		return;
	}

	printf("NPD HEADER\n");
	printf("NPD version: %d\n", NPD->version);
	printf("NPD license: %d\n", NPD->license);
	printf("NPD type: %d\n", NPD->type);
	printf("\n");
	printf("SDAT HEADER\n");
	printf("SDAT flags: 0x%08X\n", SDAT->flags);
	printf("SDAT block size: 0x%08X\n", SDAT->block_size);
	printf("SDAT file size: 0x%08X\n", SDAT->file_size);
	printf("\n");

	// Generate decryption key.
	unsigned char *key = new unsigned char[0x10];
	xor(key, NPD->dev_hash, SDAT_KEY, 0x10);

	int i;
	printf("DECRYPTION KEY: ");
	for(i = 0; i < 0x10; i++)
		printf("%02X", key[i]);
	printf("\n\n");

	printf("Parsing SDATA...\n");
	if (sdata_check(key, SDAT, NPD, input))
		printf("SDATA parsing failed!\n");

	printf("\n");

	printf("Decrypting SDATA...\n");
	if (sdata_decrypt(input, output, SDAT, NPD, key))
		printf("SDATA decryption failed!");
	else
		printf("File successfully decrypted!");

	delete[] key;
	delete NPD;
	delete SDAT;
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