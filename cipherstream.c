#include "cipherstream.h"
#include "ciphercommon.h"
#include "aes.h"

#include <assert.h>
#ifdef WIN32
#include <malloc.h>
#endif
CipherStreamData *g_encrypt_dev[2] = {NULL};
CipherStreamData *g_decrypt_dev[2] = {NULL};
static uint8_t g_key[ENCRYPT_BUF_LEN] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
static uint8_t g_iv[ENCRYPT_BUF_LEN]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
static uint8_t g_cipher_enable = 0;
static uint8_t g_file_cnt = 0;
#define getimecur		gettimeofday


static char *_hex_dump(void *buf, int len)
{
	const char tmpbuf[] = "0123456789abcdef";
	char outbuf[1024*10] = {0};
	char *pbuf = (char *)buf;
	int i = 0;
	int j = 0;
	for (i = 0, j = 0; i < len; i++)
	{
		int nl = pbuf[i] & 0xf;
		int nh = (pbuf[i] & 0xf0) >> 4;

		outbuf[j++] = tmpbuf[nh];
		outbuf[j++] = tmpbuf[nl];
		outbuf[j++] = ' ';
		if ( (0 != i) && (0 == (i+1)%16))
			outbuf[j++] = '\n';
	}
	outbuf[j] = 0;
	return outbuf;
}

void *decrypt_func(void *arg)
{
	CipherStreamData *d = (CipherStreamData*)arg;
	mblk_t *im = NULL;
	mblk_t *outm = NULL;
	int ilen = 0;
	FILE *fp=NULL;
	FILE *fp1=NULL;
#ifdef		_CIP_DEBUG_OUTPUT_
	struct timeval t1v;
	struct timeval t2v;
	const char *pfilepath = "rtp_de";
	char szfpath[256] = {0};
	char szfpath1[256] = {0};
	if (1 == d->v_a_idx)
	{
		snprintf(szfpath, 256, "d:\\%d_%s_%s_%s_%d", g_file_cnt,d->bcaller?"caller":"callee",pfilepath, d->v_a_idx?"a":"v",d->cipher_thread);
		fp = fopen(szfpath, "wb+");
		if (NULL == fp)
		{
			ms_error("decrypt_func fopen %s failed", szfpath);
			return (void*)0;
		}
		ms_message("decrypt_func fopen %s sucess", szfpath);

		snprintf(szfpath1, 256, "d:\\%d_%s_%s_%s_%d_before", g_file_cnt,d->bcaller?"caller":"callee",pfilepath, d->v_a_idx?"a":"v",d->cipher_thread);
		fp1 = fopen(szfpath1, "wb+");
		if (NULL == fp1)
		{
			ms_error("decrypt_func fopen %s failed", szfpath1);
			return (void*)0;
		}
		ms_message("decrypt_func fopen %s sucess", szfpath1);
	}
#endif
	d->bRuning = TRUE;
	d->lastlen = 0;
	d->bsync = 0;
	memset(d->lastbuf, 0, sizeof(d->lastbuf));
	ms_message("decrypt_func started.");
	for (;;)
	{
		//ms_cond_signal
		ms_mutex_lock(&d->thread_lock);
		ms_cond_wait(&d->thread_cond,&d->thread_lock);
		ms_mutex_unlock(&d->thread_lock);

		if (!d->bRuning)
		{
			break;
		}

		for (;;)
		{
			im = safe_getq(&d->inputs->q, d->in_locker);
			if (NULL == im)
			{
				//ms_error("decrypt_func im buf NULL!");
				break;
			}
#ifdef	_CIP_DEBUG_OUTPUT_
			ilen = msgdsize(im);
			getimecur(&t1v, NULL);
#endif
#ifdef	MS_DO_NOT_CRYPT
			outm = im;
#else
			outm = cipherstream_decrypt_sync_block(im, d->v_a_idx, fp, fp1);
#endif
#ifdef	_CIP_DEBUG_OUTPUT_
			getimecur(&t2v, NULL);
			if (1 == d->v_a_idx)
			{
				ms_message("t2v %d %d -- t1v %lu %lu", t2v.tv_sec, t2v.tv_usec, t1v.tv_sec, t1v.tv_usec);
				ms_message("cipherstream_decrypt_sync time %lu(s):%lu(us) len %d", (t2v.tv_sec-t1v.tv_sec), ((t2v.tv_sec-t1v.tv_sec)*1000*1000+t2v.tv_usec)-t1v.tv_usec, ilen);
			}
#endif
			if (NULL != outm)
			{
				ms_mutex_lock(&d->out_locker);
				ms_queue_put(d->outputs, outm);
				ms_mutex_unlock(&d->out_locker);
			}
		}
		if (!d->bRuning)
		{
			break;
		}
	}
#ifdef _CIP_DEBUG_OUTPUT_
	if (fp)
		fclose(fp);
#endif
	ms_message("decrypt_func stop.");
	ms_thread_exit((void*)0);
	return (void*)0;
}

void *encrypt_func(void *arg)
{
	CipherStreamData *d = (CipherStreamData*)arg;
	mblk_t *im = NULL;
	mblk_t *outm = NULL;
	int ilen = 0;
	struct timeval t1v;
	struct timeval t2v;
	FILE *fp=NULL;
	FILE *fp1=NULL;
#ifdef		_CIP_DEBUG_OUTPUT_
	const char *pfilepath = "rtp_en";
	char szfpath[256] = {0};
	char szfpath1[256] = {0};
	if (1 == d->v_a_idx)
	{
		snprintf(szfpath, 256, "d:\\%d_%s_%s_%s_%d", g_file_cnt,d->bcaller?"caller":"callee",pfilepath, d->v_a_idx?"a":"v",d->cipher_thread);
		fp = fopen(szfpath, "wb+");
		if (NULL == fp)
		{
			ms_error("encrypt_func fopen %s failed", szfpath);
			return (void*)0;
		}
		ms_message("encrypt_func fopen %s sucess", szfpath);

		snprintf(szfpath1, 256, "d:\\%d_%s_%s_%s_%d_after", g_file_cnt,d->bcaller?"caller":"callee",pfilepath, d->v_a_idx?"a":"v",d->cipher_thread);
		fp1 = fopen(szfpath1, "wb+");
		if (NULL == fp1)
		{
			ms_error("encrypt_func fopen %s failed", szfpath1);
			return (void*)0;
		}
		ms_message("encrypt_func fopen %s sucess", szfpath1);
	}
#endif
	d->bRuning = TRUE;
	d->lastlen = 0;
	memset(d->lastbuf, 0, sizeof(d->lastbuf));
	ms_message("encrypt_func started.");
	for (;;)
	{
		//ms_cond_signal
		ms_mutex_lock(&d->thread_lock);
		ms_cond_wait(&d->thread_cond,&d->thread_lock);
		ms_mutex_unlock(&d->thread_lock);

		if (!d->bRuning)
		{
			break;
		}

		for (;;)
		{
			im = safe_getq(&d->inputs->q, d->in_locker);
			if (NULL == im)
			{
				//ms_error("encrypt_func im buf is NULL!");
				break;
			}
#ifdef	_CIP_DEBUG_OUTPUT_
			ilen = msgdsize(im);
			getimecur(&t1v, NULL);
#endif
#ifdef	MS_DO_NOT_CRYPT
			outm = im;
#else
			outm = cipherstream_encrypt_sync_block(im, d->v_a_idx, fp, fp1);
#endif
#ifdef _CIP_DEBUG_OUTPUT_
			getimecur(&t2v, NULL);
			if (1 == d->v_a_idx)
			{
				ms_message("t2v %d %d -- t1v %lu %lu", t2v.tv_sec, t2v.tv_usec, t1v.tv_sec, t1v.tv_usec);
				ms_message("cipherstream_encrypt_sync time %lu(s):%lu(us) len %d", (t2v.tv_sec-t1v.tv_sec), ((t2v.tv_sec-t1v.tv_sec)*1000*1000+t2v.tv_usec)-t1v.tv_usec, ilen);
			}
#endif
			if (NULL != outm)
			{
				ms_mutex_lock(&d->out_locker);
				ms_queue_put(d->outputs, outm);
				ms_mutex_unlock(&d->out_locker);
			}
		}
		if (!d->bRuning)
		{
			break;
		}
	}
#ifdef _CIP_DEBUG_OUTPUT_
	if (fp)
		fclose(fp);
#endif
	ms_message("encrypt_func stop.");
	ms_thread_exit((void*)0);
	return (void*)0;
}

static int _cipher_config(int bEncrypt, int bCaller)
{
	CipherStreamData *tmpv = (CipherStreamData*)malloc(sizeof(CipherStreamData));
	CipherStreamData *tmpa = (CipherStreamData*)malloc(sizeof(CipherStreamData));

	ms_message("_cipher_config step1...");
	if (NULL == tmpv || NULL == tmpa)
	{
		ms_error("malloc CipherStreamData");
		return -1;
	}
	if ((bEncrypt && (g_encrypt_dev[0] || g_encrypt_dev[1])) || (!bEncrypt && (g_decrypt_dev[0] || g_decrypt_dev[1])))
	{
		ms_error("alread started! stop first!");
		return -2;
	}

	ms_message("_cipher_config step2...");

	tmpv->cipher_ctx = malloc(sizeof(struct AES_ctx));
	if (NULL == tmpv->cipher_ctx)
		return -1;
	tmpa->cipher_ctx = malloc(sizeof(struct AES_ctx));
	if (NULL == tmpa->cipher_ctx)
		return -1;

	AES_init_ctx_iv((struct AES_ctx*)tmpv->cipher_ctx, g_key, g_iv);
	AES_init_ctx_iv((struct AES_ctx*)tmpa->cipher_ctx, g_key, g_iv);

	ms_mutex_init(&tmpv->in_locker, NULL);
	ms_mutex_init(&tmpv->out_locker, NULL);
	tmpv->inputs = ms_queue_new(0, 0, 0, 0);
	tmpv->outputs = ms_queue_new(0, 0, 0, 0);
	if (NULL == tmpv->inputs || NULL == tmpv->outputs)
	{
		ms_error("malloc tmpv ms_queue_new ");
		return -1;
	}
	ms_mutex_init(&tmpa->in_locker, NULL);
	ms_mutex_init(&tmpa->out_locker, NULL);
	tmpa->inputs = ms_queue_new(0, 0, 0, 0);
	tmpa->outputs = ms_queue_new(0, 0, 0, 0);
	if (NULL == tmpa->inputs || NULL == tmpa->outputs)
	{
		ms_error("malloc tmpa ms_queue_new ");
		return -1;
	}

	ms_mutex_init(&tmpv->thread_lock, NULL);
	ms_cond_init(&tmpv->thread_cond, NULL);
	tmpv->bRuning = FALSE;
	ms_mutex_init(&tmpa->thread_lock, NULL);
	ms_cond_init(&tmpa->thread_cond, NULL);
	tmpa->bRuning = FALSE;
	tmpv->v_a_idx = 0;
	tmpa->v_a_idx = 1;
	tmpv->bcaller = bCaller;
	tmpa->bcaller = bCaller;

	if (bEncrypt)
	{
		ms_thread_create(&tmpv->cipher_thread, NULL, encrypt_func, (void*)tmpv);
		ms_thread_create(&tmpa->cipher_thread, NULL, encrypt_func, (void*)tmpa);
		g_encrypt_dev[0] = tmpv;
		g_encrypt_dev[1] = tmpa;
	}
	else
	{
		ms_thread_create(&tmpv->cipher_thread, NULL, decrypt_func, (void*)tmpv);
		ms_thread_create(&tmpa->cipher_thread, NULL, decrypt_func, (void*)tmpa);
		g_decrypt_dev[0] = tmpv;
		g_decrypt_dev[1] = tmpa;
	}
	return 0;
}

static int _cipher_unconfig(int bEncrypt)
{
	CipherStreamData *pDev = NULL;
	int idx = 0;
	ms_message("_cipher_unconfig step1...");
	for (idx = 0; idx < 2; idx++)
	{
		if (bEncrypt)
		{
			pDev = g_encrypt_dev[idx];
			g_encrypt_dev[idx] = NULL;
		}
		else
		{
			pDev = g_decrypt_dev[idx];
			g_decrypt_dev[idx] = NULL;
		}
		if (NULL == pDev)
			return -1;
		ms_message("_cipher_unconfig step2 idx %d...", idx);
		// .stop thread && desdroy thread lock
		pDev->bRuning = FALSE;
		ms_mutex_lock(&pDev->thread_lock);
		ms_cond_signal(&pDev->thread_cond);
		ms_mutex_unlock(&pDev->thread_lock);
		pDev->bRuning = FALSE;
		ms_thread_join(pDev->cipher_thread, NULL);

		ms_message("_cipher_unconfig step3 idx %d...", idx);
		ms_mutex_destroy(&pDev->thread_lock);
		ms_cond_destroy(&pDev->thread_cond);

		ms_message("_cipher_unconfig step4 idx %d...", idx);
		// .desdroy queue && queue lock
		ms_queue_destroy(pDev->inputs);
		pDev->inputs = NULL;
		ms_queue_destroy(pDev->outputs);
		pDev->outputs = NULL;
		ms_mutex_destroy(&pDev->in_locker);
		ms_mutex_destroy(&pDev->out_locker);

		// .free memery
		if (pDev->cipher_ctx)
			free(pDev->cipher_ctx);
		free(pDev);
		pDev = NULL;
	}
	return 0;
}
int cipherstream_start(const char *key_iv, int is_caller)
{
	ms_message("cipherstream_start ...");
#ifndef	MS_CIPHER_USELESS
	if (NULL == key_iv)
	{
		g_cipher_enable = 0;
		ms_error("cipherstream_start disable");
		return 0;
	}
	else
	{
		memcpy(g_key, key_iv, ENCRYPT_BUF_LEN);
		memcpy(g_iv, key_iv+ENCRYPT_BUF_LEN, ENCRYPT_BUF_LEN);
#if	_CIP_DEBUG_KEY
		ms_message("key: %s", _hex_dump(g_key, ENCRYPT_BUF_LEN));
		ms_message("iv: %s", _hex_dump(g_iv, ENCRYPT_BUF_LEN));
#endif
	}
	g_cipher_enable = 1;

	if (0 != _cipher_config(1, is_caller) )
	{
		ms_error("start encrypt thread failed!");
		return -1;
	}
	if (0 != _cipher_config(0, is_caller) )
	{
		_cipher_unconfig(1);
		ms_error("start decrypt thread failed!");
		return -1;
	}
#endif
	crcInit();
	g_file_cnt += 1;
	ms_message("cipherstream_start !!!");
	return 0;
}

int cipherstream_stop()
{
	ms_message("cipherstream_stop ...");
	_cipher_unconfig(1);
	_cipher_unconfig(0);
	g_cipher_enable = 0;
	memset(g_key, 0, ENCRYPT_BUF_LEN);
	memset(g_iv, 0, ENCRYPT_BUF_LEN);
	ms_message("cipherstream_stop !!!");
	return 0;
}

int cipherstream_enc_put(MSQueue *msq, int v_a_idx)
{
	mblk_t *tmp = NULL;
	CipherStreamData *pDev = g_encrypt_dev[v_a_idx];

	if (NULL == msq || NULL == pDev)
		return -1;
	if (!pDev->bRuning)
		return -2;

	ms_mutex_lock(&pDev->in_locker);
	while ( tmp = ms_queue_get(msq) )
	{
		ms_queue_put(pDev->inputs, tmp);
	}
	ms_mutex_unlock(&pDev->in_locker);

	ms_mutex_lock(&pDev->thread_lock);
	ms_cond_signal(&pDev->thread_cond);
	ms_mutex_unlock(&pDev->thread_lock);
	return 0;
}

mblk_t *cipherstream_enc_getq(int v_a_idx)
{
	if (!g_encrypt_dev[v_a_idx]->bRuning)
		return NULL;
	return safe_getq(&g_encrypt_dev[v_a_idx]->outputs->q, g_encrypt_dev[v_a_idx]->out_locker);
}

int cipherstream_dec_put(mblk_t *im, int v_a_idx)
{
	CipherStreamData *pDev = g_decrypt_dev[v_a_idx];

	if (NULL == im || NULL == pDev)
		return -1;
	if (!pDev->bRuning)
		return -2;

	ms_mutex_lock(&pDev->in_locker);
	ms_queue_put(pDev->inputs, im);
	ms_mutex_unlock(&pDev->in_locker);

	ms_mutex_lock(&pDev->thread_lock);
	ms_cond_signal(&pDev->thread_cond);
	ms_mutex_unlock(&pDev->thread_lock);
	return 0;
}

mblk_t *cipherstream_dec_getq(int v_a_idx)
{
	CipherStreamData *pDev = g_decrypt_dev[v_a_idx];
	mblk_t *m = NULL;

	if (!pDev->bRuning)
		return NULL;

	m = safe_getq(&pDev->outputs->q, pDev->out_locker);

	return m;
}

mblk_t *cipherstream_encrypt_sync_block(mblk_t *im, int v_a_idx, FILE *fp, FILE *fp1)
{
	CipherStreamData *pDev = g_encrypt_dev[v_a_idx];
	mblk_t *om = NULL;
	unsigned char *pbuf = NULL;
	int ilen = 0, sz = 0, cplen = 0, relen = 0,i=0, cnt = 0;
	crc *cv = NULL;
	int cvlen = 0;

	ilen = msgdsize(im);
	if (NULL == im || 0 >= ilen || NULL == pDev)
	{
		ms_error("cipherstream_encrypt_sync_block param error im:%p ilen:%d g_encrypt_dev[%d]:%p!",\
			im, ilen, v_a_idx, g_encrypt_dev[v_a_idx]);
		return NULL;
	}
	relen = (ilen / AES_BLOCKLEN)*AES_BLOCKLEN + AES_BLOCKLEN;
	om = allocb(relen+AES_BLOCKLEN, 0);
	if (NULL == om)
	{
		ms_error("cipherstream_encrypt_sync_block system call allocb error!");
		return NULL;
	}
	pbuf = (unsigned char*)alloca(relen+AES_BLOCKLEN*2);//data len + pading len(most AES_BLOCKLEN) + crc byte len(most AES_BLOCKLEN)
	memset(pbuf, 0, relen+AES_BLOCKLEN*2);//
	/*
	* if ilen is mutile of AES_BLOCKLEN, then relen = ilen + AES_BLOCKLEN, 
	* the last AES_BLOCKLEN bytes is Synchronous bytes.
	* if ilen is not mutile of AES_BLOCKLEN, then relen = ilen + padinglen + AES_BLOCKLEN,
	* the Second-to-bottom AES_BLOCKLEN bytes is Synchronous bytes,
	* the last AES_BLOCKLEN bytes is fraglen bytes + padding bytes.
	*/
	om->reserved1 = im->reserved1;
	om->reserved2 = im->reserved2;
	om->reserved3 = im->reserved3;
	om->reserved4 = im->reserved4;
	om->reserved5 = im->reserved5;
	om->reserved6 = im->reserved6;

	while (sz<ilen)
	{
		cplen = MIN(im->b_wptr-im->b_rptr, ilen-sz);
		memcpy(pbuf+sz, im->b_rptr, cplen);
		sz+=cplen;
		im->b_rptr+=cplen;
		
		if (im->b_rptr == im->b_wptr)
		{
			if (im->b_cont)
				im = im->b_cont;
			else
				break;
		}
	}

	if (0 < sz)
	{
		//add padding
#ifdef	_CIP_DEBUG_OUTPUT_
		if (fp && 1 == v_a_idx){
			fwrite(pbuf, 1, sz, fp);
			fflush(fp);
		}
#endif
		
		for (i = sz%AES_BLOCKLEN,cnt=0; i < AES_BLOCKLEN; i++)
		{
			pbuf[sz+cnt] = AES_BLOCKLEN-sz%AES_BLOCKLEN;
			cnt++;
		}
		// add crc value
		cv = (crc*)(pbuf+sz+cnt);
		*cv = crcFast(pbuf, sz+cnt);
		cvlen = sizeof(crc);// unsigned short
#ifdef	_CIP_DEBUG_OUTPUT_
// 		ms_message("[hdr] %s", _hex_dump(pbuf, AES_BLOCKLEN));
// 		ms_message("[end] %s", _hex_dump(pbuf+sz+cnt-AES_BLOCKLEN, AES_BLOCKLEN+cvlen));
#endif
		AES_CBC_encrypt_buffer((struct AES_ctx*)pDev->cipher_ctx, pbuf, sz+cnt);
		
		memcpy(om->b_wptr, pbuf, sz+cnt+cvlen);
		om->b_wptr+=sz+cnt+cvlen;
#ifdef	_CIP_DEBUG_OUTPUT_
		if (fp1 && 1 == v_a_idx){
			fwrite(pbuf, 1, sz+cnt, fp1);
			fflush(fp1);
		}
		/*ms_message("[end] %s", _hex_dump(pbuf+sz+cnt-AES_BLOCKLEN, AES_BLOCKLEN+cvlen));*/
#endif
	}
#ifdef	_CIP_DEBUG_OUTPUT_
	ms_message("cipherstream_encrypt_sync_block sz %d ilen %d pad byte %d sz+i+cvlen %d crc:%u ts:%lu", \
		sz, ilen, cnt, sz+cnt+cvlen, *cv, mblk_get_timestamp_info(om));
#endif
	freemsg(im);
	return om;
}

mblk_t *cipherstream_decrypt_sync_block(mblk_t *im, int v_a_idx, FILE *fp, FILE *fp1)
{
	CipherStreamData *pDev = g_decrypt_dev[v_a_idx];
	mblk_t *om = NULL;
	unsigned char *pbuf;
	unsigned char *pbenbuf = NULL;
	int ilen = 0, sz = 0, cplen = 0, i = 0, cnt = 0;
	crc *cv = NULL;
	crc chcv = 0;

	ilen = msgdsize(im);
	if (NULL == im || 0 >= ilen || NULL == pDev)
	{
		ms_error("cipherstream_decrypt_sync_block param error im:%p ilen:%d g_encrypt_dev[%d]:%p!",\
			im, ilen, v_a_idx, g_encrypt_dev[v_a_idx]);
		return NULL;
	}
	cnt = (ilen / AES_BLOCKLEN)*AES_BLOCKLEN+AES_BLOCKLEN;
	om = allocb(cnt+AES_BLOCKLEN, 0);
	if (NULL == om)
		return NULL;
	pbuf = (unsigned char*)alloca(cnt+AES_BLOCKLEN+AES_BLOCKLEN);

	/*
	* 1.find first synchronous bytes (16 bytes)
	* 2.skip synchronous bytes
	* 3.decrypt data by Step of AES_BLOCKLEN bytes, check first AES_BLOCKLEN after synchronous bytes for padding or not.
	* 4.loop exec step 3.until met next synchronous bytes, then skip to step 2.
	*/
	om->reserved1 = im->reserved1;
	om->reserved2 = im->reserved2;
	om->reserved3 = im->reserved3;
	om->reserved4 = im->reserved4;
	om->reserved5 = im->reserved5;
	om->reserved6 = im->reserved6;

	while (sz<ilen)
	{
		cplen = MIN(im->b_wptr-im->b_rptr, ilen-sz);
		memcpy(pbuf+sz, im->b_rptr, cplen);
		sz+=cplen;
		im->b_rptr+=cplen;

		if (im->b_rptr==im->b_wptr)
		{
			if (im->b_cont)
				im = im->b_cont;
			else
				break;
		}
	}

	if (0 < sz)
	{
		if (0 != (sz-sizeof(crc))%AES_BLOCKLEN || ilen != sz)
		{
			ms_message("cipherstream_decrypt_sync_block recv error buf %d ilen %d", sz, ilen);
		}
		
		sz-=sizeof(crc);
#ifdef _CIP_DEBUG_OUTPUT_
		pbenbuf = (unsigned char*)alloca(cnt+AES_BLOCKLEN+AES_BLOCKLEN);
		memcpy(pbenbuf, pbuf, sz);
		if (fp1 && 1==v_a_idx)
		{
			fwrite(pbuf, 1, sz, fp1);
			fflush(fp1);
		}

#endif
		AES_CBC_decrypt_buffer((struct AES_ctx*)pDev->cipher_ctx, pbuf, sz);
		
		// check crc value first
		cv = (crc*)(pbuf+sz);
		chcv = crcFast(pbuf, sz);
		if (*cv != chcv)
		{
			ms_message("%s", _hex_dump(pbuf, sz));
			ms_message("[end]%s", _hex_dump(pbuf+sz-AES_BLOCKLEN, AES_BLOCKLEN));
			ms_error("cipherstream_decrypt_sync_block crc check error *cv:%d chcv:%d", *cv, chcv);
			freemsg(im);
			freemsg(om);
			return NULL; // drop error data
		}

		cnt=0;
#ifdef	_CIP_DEBUG_OUTPUT_
// 		if (0  != pbuf[0] && 0x3c != pbuf[0])
// 		{
// 			ms_message("%s", _hex_dump(pbenbuf, sz));
// 			ms_message("[hdr]%s", _hex_dump(pbuf, AES_BLOCKLEN));
// 			ms_message("[end]%s", _hex_dump(pbuf+sz-AES_BLOCKLEN, AES_BLOCKLEN+sizeof(crc)));
// 		}
#endif
		if (pbuf[sz-1] > 0 && pbuf[sz-1] <= AES_BLOCKLEN)
		{
			for (cnt=0,i = AES_BLOCKLEN-pbuf[sz-1]; i < AES_BLOCKLEN; i++)
			{
				if (pbuf[sz-AES_BLOCKLEN+i] == pbuf[sz-1])
					cnt++;
			}
			
			if (cnt==pbuf[sz-1])
			{
// #ifdef	_CIP_DEBUG_OUTPUT_
// 				ms_error("cipherstream_decrypt_sync_block has pading");
// #endif
				sz-=cnt;
			}
		}
		
		memcpy(om->b_wptr, pbuf, sz);
		om->b_wptr+=sz;
#ifdef _CIP_DEBUG_OUTPUT_
		if(fp && 1 == v_a_idx){
			fwrite(pbuf, 1, sz, fp);
			fflush(fp);
		}
		ms_message("cipherstream_decrypt_sync_block pubf[%d] %d cnt %d ilen %d sz %d crc:%d ts:%lu", \
			ilen-1-sizeof(crc), pbuf[ilen-1-sizeof(crc)], cnt, ilen, sz, chcv, mblk_get_timestamp_info(om));
#endif
	}
	
	freemsg(im);
	return om;
}

int cipherstream_is_enable()
{
#ifdef	MS_CIPHER_USELESS
	return 0;
#else
	return g_cipher_enable?1:0;
#endif
}