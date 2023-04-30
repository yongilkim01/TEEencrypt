/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	
	char plaintext[1024] = {0,};
	char ciphertext[1024] = {0,};
	int len=1024;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].value.a = 0;

	/*file open*/
	FILE* pfile = fopen(argv[2],"r");
	if(pfile == NULL){
		printf("no such file");
	}
	while(fgets(plaintext, sizeof(plaintext), pfile) != NULL);
	fclose(pfile);
	
	memcpy(op.params[0].tmpref.buffer, plaintext, len);

	if(strcmp(argv[1], "-e") == 0){
		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Ciphertext : %s\n", ciphertext);
		
		//encrypted file create
		FILE* encryptedfile = fopen("ciphertext.txt","w");
		fprintf(encryptedfile, ciphertext);
		fclose(encryptedfile);

		//key file create
		FILE* keyfile = fopen("encryptedkey.txt","w");
		fprintf(keyfile,"%d",op.params[1].value.a);
		fclose(keyfile);
		printf("ciphertext.txt + encryptedkey.txt\n");
		

	}else if(strcmp(argv[1], "-d") == 0){
		//keyfile open
		int key;
		FILE* keyfile = fopen(argv[3],"r");
		if(keyfile == NULL){
			printf("no file");
		}
		fscanf(keyfile, "%d", &key);
		fclose(keyfile);
		
		op.params[1].value.a = key;
		printf("keyfile key : %d\n", key);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext : %s\n", plaintext);

		//decrypted file create
		FILE* decryptfile = fopen("decrypted.txt", "w");
		fprintf(decryptfile, plaintext);
		fclose(decryptfile);
	}else{
		printf("can't do anything\n");	
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
