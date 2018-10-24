#ifndef __CIPHER_STREAM_H_
#define __CIPHER_STREAM_H_

#include "mediastreamer2/mscommon.h"
#include "mediastreamer2/msqueue.h"

//#define MS_CIPHER_USELESS
//#define MS_DO_NOT_CRYPT
//#define _CIP_DEBUG_OUTPUT_
#define	_CIP_DEBUG_KEY			1
#define ENCRYPT_BUF_LEN			16

#ifdef __cplusplus
extern "C" {
#endif

struct _cipher_stream_data_ {
	MSQueue *inputs;
	MSQueue *outputs;
	ms_mutex_t in_locker;
	ms_mutex_t out_locker;
	ms_thread_t cipher_thread;
	ms_mutex_t thread_lock;
	ms_cond_t thread_cond;
	int bRuning;
	int v_a_idx;
	unsigned char lastbuf[ENCRYPT_BUF_LEN+1];
	int lastlen;
	int bsync;
	int bcaller;
	void *cipher_ctx;
};

typedef struct _cipher_stream_data_ CipherStreamData;

// function definations
int cipherstream_is_enable();

int cipherstream_start(const char *key_iv, int is_caller);

int cipherstream_stop();

int cipherstream_enc_put(MSQueue *msq, int v_a_idx);

mblk_t *cipherstream_enc_getq(int v_a_idx);

int cipherstream_dec_put(mblk_t *im, int v_a_idx);

mblk_t *cipherstream_dec_getq(int v_a_idx);

//-------------------------- local function ------------------------
mblk_t *cipherstream_encrypt_sync_block(mblk_t *im, int v_a_idx, FILE *fp, FILE *fp1);
mblk_t *cipherstream_decrypt_sync_block(mblk_t *im, int v_a_idx, FILE *fp, FILE *fp1);

#ifdef __cplusplus
}
#endif	// __cplusplus

#endif	//__CIPHER_STREAM_H_