// gcc -O1 -Wall -Wextra -Wno-format-truncation -pedantic -pthread proxytun.c -o proxytun

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "sha2.h"

#define SIZE (8192 * 4)
#define SEPA "\x00\x13\x37\xff"
#define SEPB "\xff\x73\x31\x00"
#define MACS "%02x%02x%02x%02x%02x%02x%02x%02x"

typedef unsigned char uchar;

struct data {
	int size;
	uchar *buff;
};

struct keys {
	char spwd[512], init[512];
	int sbox[256];
};

struct args {
	int inpt, outp;
	char mode, meth;
	struct keys *skey;
	struct data *hold;
};

void auth(char mode, struct keys *skey, char *smac) {
	int k = 0, w = 0, x, y, z;
	uchar hmac[8];
	bzero(hmac, 8 * sizeof(uchar));
	for (x = 0; x < 256; ++x) {
		z = ((skey->sbox[x] + 1) * (x + 1));
		w = (((w + 1) ^ ((z >> 8) | z)) % 256);
		for (y = 0; y < 8; ++y) {
			z = ((hmac[y] + 1) * (y + 1));
			k = (((k + 1) ^ ((z >> 8) | z)) % 256);
			hmac[y] = ((w ^ k) & 0xff);
		}
	}
	snprintf(smac, 24, MACS, hmac[0], hmac[1], hmac[2], hmac[3], hmac[4], hmac[5], hmac[6], hmac[7]);
}

void ciph(char mode, struct keys *skey, unsigned char *buff, int leng) {
	int x, m, k, t = 0, u = 0, i = 0, j = 0;
	for (x = 0; x < leng; ++x) {
		m = buff[x]; t = skey->sbox[i];
		k = ((u + t) % 256);
		i = ((i + 1) % 256);
		j = ((j + k) % 256);
		t = skey->sbox[i]; u = skey->sbox[j];
		skey->sbox[i] = u; skey->sbox[j] = t;
		k = (skey->sbox[i] ^ skey->sbox[j]);
		buff[x] = (m ^ k);
		if (mode == 'e') { u = m; }
		else { u = buff[x]; }
	}
	i = skey->sbox[t]; j = skey->sbox[u];
	skey->sbox[t] = j; skey->sbox[u] = i;
}

void xors(struct keys *skey, char *init, char *spwd) {
	char *seps = SEPA;
	uchar hash[512];
	sha256_ctx dgst;
	if (spwd != NULL) {
		bzero(skey->spwd, 512 * sizeof(char));
		strncpy(skey->spwd, spwd, 256);
	}
	if (init != NULL) {
		bzero(skey->init, 512 * sizeof(char));
		strncpy(skey->init, init, 256);
	}
	for (int x = 0; x < 256; ++x) {
		skey->sbox[x] = x;
	}
	bzero(hash, SHA256_BLOCK_SIZE * sizeof(uchar));
	for (int x = 0; x < 8; ++x) {
		sha256_init(&dgst);
		sha256_update(&dgst, &(hash[x*SHA256_BLOCK_SIZE]), SHA256_BLOCK_SIZE);
		sha256_update(&dgst, (uchar *)skey->init, strlen(skey->init));
		sha256_update(&dgst, (uchar *)seps, 4);
		sha256_update(&dgst, (uchar *)skey->spwd, strlen(skey->spwd));
		sha256_final(&dgst, &(hash[(x+1)*SHA256_BLOCK_SIZE]));
	}
	int t, u, i = 0, j = 0, k = hash[i+SHA256_BLOCK_SIZE];
	for (int x = 0; x < 256; ++x) {
		t = skey->sbox[i]; u = skey->sbox[j];
		skey->sbox[i] = u; skey->sbox[j] = t;
		i = ((i + 1) % 256);
		j = ((j + k) % 256);
		k = hash[i+SHA256_BLOCK_SIZE];
	}
}

int drop(struct data *p, int leng) {
	if (leng < 1) { leng = p->size; }
	if (leng > p->size) { leng = p->size; }
	int diff = (p->size - leng);
	uchar *temp = malloc((diff + 1) * sizeof(uchar));
	if (temp == NULL) { return -3; }
	memcpy(temp, &(p->buff[leng]), diff);
	if (p->buff != NULL) { free(p->buff); }
	p->buff = temp; p->buff[diff] = '\0'; p->size = diff;
	return 0;
}

int push(struct data *p, uchar *b, int leng) {
	if (leng <= 0) { return -1; }
	int size = p->size;
	p->size = (size + leng);
	p->buff = realloc(p->buff, (p->size + 1) * sizeof(uchar));
	if (p->buff == NULL) { printf("push\n"); return -1; }
	memcpy(&(p->buff[size]), b, leng);
	p->buff[p->size] = '\0';
	if (p->size >= (SIZE * 8)) { printf("push\n"); return -2; }
	return 0;
}

void dels(struct data *p) {
	if (p->buff != NULL) {
		free(p->buff);
		p->buff = NULL;
	}
}

int find(uchar *a, int l, char c, int s) {
	if (a == NULL) { return -1; }
	int x;
	for (x = 0; x < l; ++x) {
		if (a[x] == c) {
			if (s > 0) { --s; }
			else { return x; }
		}
	}
	return -1;
}

int subs(uchar *a, int l, uchar *b, int m, int s) {
	if ((a == NULL) || (b == NULL)) { return -1; }
	if (s < 0) { s = 0; }
	int x, i = 0;
	for (x = s; x < l; ++x) {
		if (a[x] == b[i]) { ++i; }
		else { i = 0; }
		if (i == m) { return ((x+1)-i); }
	}
	return -1;
}

void chop(char *s) {
	while (*s != '\0') {
		if (*s == '\n') { *s = '\0'; break; }
		++s;
	}
}

int decr(int sock, uchar **pntr, struct data *hold, struct keys *skey, char mode, char meth) {
	int leng = 0;
	uchar buff[SIZE], temp[SIZE];
	if (((mode == 'e') && (meth == 'o')) || ((mode == 'd') && (meth == 'i'))) {
		char dstr[32], dini[32], dmac[32];
		uchar *data = NULL;
		if (hold->size < 8) {
			leng = read(sock, buff, SIZE);
			if (leng > 0) {
				if (push(hold, buff, leng) < 0) {
					printf("decr:push\n");
					return -1;
				}
			}
		}
		while (hold->size > 0) {
			int a = -1, b = -1, c = -1, d = -1, e, f, g;
			int dlen = -1, rlen = (hold->size - d);
			while ((dlen < 1) || (rlen < dlen)) {
				a = subs(hold->buff, hold->size, (uchar *)SEPA, 4, 0);
				b = (a + 4);
				c = subs(hold->buff, hold->size, (uchar *)SEPB, 4, b);
				d = (c + 4);
				if ((a > -1) && (b > a) && (c > b) && (d > c)) {
					f = find(hold->buff, hold->size, ':', 0);
					e = (f - b);
					if ((f > 0) && (0 < e) && (e < 24)) {
						bzero(dstr, 32 * sizeof(char));
						strncpy(dstr, (char *)&(hold->buff[b]), e);
					}
					g = find(hold->buff, hold->size, ':', 1);
					e = (g - (f + 1));
					if ((g > 0) && (0 < e) && (e < 24)) {
						bzero(dini, 32 * sizeof(char));
						strncpy(dini, (char *)&(hold->buff[f+1]), e);
					}
					e = (c - (g + 1));
					if ((c > 0) && (0 < e) && (e < 24)) {
						bzero(dmac, 32 * sizeof(char));
						strncpy(dmac, (char *)&(hold->buff[g+1]), e);
					}
					if ((dstr[0] == '\0') || (dini[0] == '\0') || (dmac[0] == '\0')) {
						printf("decr:null:[%s][%s][%s]\n",dstr,dini,dmac);
					} else { dlen = atoi((char *)dstr); }
				}
				if ((dlen < 1) || (rlen < dlen)) {
					leng = read(sock, temp, SIZE);
					if (leng > 0) {
						if (push(hold, temp, leng) < 0) { printf("decr:more\n"); return -2; }
					} else { printf("decr:read\n"); return -3; }
				}
				rlen = (hold->size - d);
			}
			data = &(hold->buff[d]);
			/* ciph */
			xors(skey, (char *)dini, NULL);
			ciph('d', skey, data, dlen);
			/* auth */
			char smac[32];
			bzero(smac, 32 * sizeof(char));
			auth('d', skey, smac);
			if (strncmp(smac, dmac, 24) == 0) {
				/* keys */
				bzero(skey->init, 32 * sizeof(char));
				strncpy(skey->init, smac, 24);
				/* data */
				if (*pntr != NULL) { free(*pntr); }
				*pntr = malloc((dlen + 1) * sizeof(uchar));
				memcpy(*pntr, data, dlen);
				(*pntr)[dlen] = '\0';
				/* return */
				drop(hold, d + dlen);
				return dlen;
			}
			printf("decr:auth:[%s][%s]\n",smac,dmac);
			drop(hold, d + dlen);
		}
	} else {
		leng = read(sock, buff, SIZE);
		if (leng > 0) {
			if (*pntr != NULL) { free(*pntr); }
			*pntr = malloc((leng + 1) * sizeof(uchar));
			memcpy(*pntr, buff, leng);
			(*pntr)[leng] = '\0';
			return leng;
		}
	}
	//printf("decr:end:[%d]\n",leng);
	return -5;
}

int encr(int sock, uchar *data, int leng, struct keys *skey, char mode, char meth) {
	if (((mode == 'e') && (meth == 'i')) || ((mode == 'd') && (meth == 'o'))) {
		int w, x, y, z;
		/* ciph */
		xors(skey, NULL, NULL);
		ciph('e', skey, data, leng);
		/* auth */
		char smac[32];
		bzero(smac, 32 * sizeof(char));
		auth('e', skey, smac);
		/* head */
		char head[96];
		bzero(head, 96 * sizeof(char));
		x = 0; memcpy(&(head[x]), SEPA, 4);
		y = (x + 4); snprintf(&(head[y]), 64, "%d:%s:%s", leng, skey->init, smac);
		z = (y + strlen(&(head[y]))); memcpy(&(head[z]), SEPB, 4);
		/* keys */
		bzero(skey->init, 64 * sizeof(char));
		strncpy(skey->init, smac, 24);
		/* send */
		w = write(sock, head, z+4);
		if (w < 0) { return -1; }
		w = write(sock, data, leng);
		if (w < 0) { return -1; }
		return (x+4+leng);
	} else {
		int stat = write(sock, data, leng);
		if (stat < 0) { return -1; }
		return leng;
	}
	printf("send:error\n");
	return -1;
}

void fins(int sock, char mode, char meth) {
	if ((mode != '*') && (meth != '*')) {
		shutdown(sock, SHUT_RDWR);
	}
	close(sock);
}

void *func(void *argv) {
	struct args argf = *((struct args *)argv);
	int inpt = argf.inpt, outp = argf.outp;
	char mode = argf.mode, meth = argf.meth;
	struct keys *skey = argf.skey;
	struct data *hold = argf.hold;
	int leng = 0;
	uchar *data = NULL;
	while (1) {
		leng = decr(inpt, &data, hold, skey, mode, meth);
		if (leng < 1) { break; }
		leng = encr(outp, data, leng, skey, mode, meth);
		if (leng < 1) { break; }
	}
	fins(outp, mode, meth);
	fins(inpt, mode, meth);
	return NULL;
}

int proc(char mode, char *prox, char *skey, int inpt, char *addr, int port) {
	int stat;
	char host[128], spwd[128];
	uchar *pntr;
	FILE *fobj;
	pthread_t tidi, tido;
	struct args argi, argo;
	struct keys keyi, keyo;
	struct data hold;

	bzero(&hold, sizeof(struct data));

	fobj = fopen(prox, "r");
	if (fobj == NULL) {
		fins(inpt, 'p', 'p');
		dels(&hold);
		printf("proc:prox\n");
		return -1;
	}
	bzero(host, 128 * sizeof(char));
	fgets(host, 100, fobj);
	fclose(fobj);

	fobj = fopen(skey, "r");
	if (fobj == NULL) {
		fins(inpt, 'p', 'p');
		dels(&hold);
		printf("proc:skey\n");
		return -2;
	}
	bzero(spwd, 128 * sizeof(char));
	fgets(spwd, 100, fobj);
	fclose(fobj);

	xors(&keyi, "1337", spwd);
	xors(&keyo, "1337", spwd);

	if (mode == 'd') {
		pntr = NULL;
		stat = decr(inpt, &pntr, &hold, &keyi, mode, 'i');
		if (stat < 1) {
			fins(inpt, 'p', 'p');
			dels(&hold);
			printf("proc:decr\n");
			return -3;
		}
		bzero(host, 128 * sizeof(char));
		strncpy(host, (char *)pntr, stat);
		free(pntr);
		//printf("info:[%s]\n",host);
	}

	int dest = 0;
	int outp = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in serv;
	if (outp < 0) {
		fins(inpt, 'p', 'p');
		dels(&hold);
		printf("proc:sock\n");
		return -4;
	}
	char *p = host; chop(p);
	while (*p != '\0') {
		if (*p == ':') {
			*p = '\0'; dest = atoi(p+1); break;
		}
		++p;
	}
	bzero(&serv, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(host);
	serv.sin_port = htons(dest);
	stat = connect(outp, (struct sockaddr *)&serv, sizeof(serv));
	if (stat < 0) {
		fins(outp, 'p', 'p');
		fins(inpt, 'p', 'p');
		dels(&hold);
		printf("proc:conn\n");
		return -5;
	}

	if (mode == 'e') {
		char comd[128], data[128];
		bzero(comd, 128 * sizeof(char));
		snprintf(comd, 100, "/etc/conn.sh %s %d", addr, port);
		fobj = popen(comd, "r");
		if (fobj == NULL) {
			fins(outp, 'p', 'p');
			fins(inpt, 'p', 'p');
			dels(&hold);
			printf("proc:exec\n");
			return -6;
		}
		bzero(comd, 128 * sizeof(char));
		fgets(comd, 100, fobj);
		fclose(fobj);
		chop(comd);
		bzero(data, 128 * sizeof(char));
		snprintf(data, 100, "%s:%s:%d\n", comd, addr, port);
		//printf("info:comd:[%s]\n",data);
		stat = encr(outp, (uchar *)data, strlen(data), &keyo, mode, 'i');
		if (stat < 0) {
			fins(outp, 'p', 'p');
			fins(inpt, 'p', 'p');
			dels(&hold);
			printf("proc:encr\n");
			return -7;
		}
	}

	argi.inpt = inpt; argi.outp = outp; argi.hold = &hold; argi.skey = &keyi; argi.mode = mode; argi.meth = 'i';
	argo.inpt = outp; argo.outp = inpt; argo.hold = &hold; argo.skey = &keyo; argo.mode = mode; argo.meth = 'o';

	pthread_create(&tidi, NULL, func, (void *)&argi);
	pthread_create(&tido, NULL, func, (void *)&argo);

	pthread_join(tidi, NULL);
	pthread_join(tido, NULL);

	fins(outp, 'p', 'p');
	fins(inpt, 'p', 'p');
	dels(&hold);

	return 0;
}

int main(int argc, char **argv) {
	if (argc < 6) { printf("main\n"); return -1; }
	//char *prog = argv[0];
	char *mode = argv[1];

	if ((mode[0] == 's') || (mode[0] == 'r')) {
		char *addr = argv[2];
		char *port = argv[3];
		char *prox = argv[4];
		char *skey = argv[5];

		int opts = 1, inpt;
		struct sockaddr_in sadr;

		inpt = socket(AF_INET, SOCK_STREAM, 0);
		sadr.sin_family = AF_INET;
		sadr.sin_port = htons(atoi(port));
		sadr.sin_addr.s_addr = inet_addr(addr);

		if (inpt < 0) { printf("main\n"); return 1; }
		setsockopt(inpt, SOL_SOCKET, SO_REUSEADDR, &opts , sizeof(int));

		opts = bind(inpt, (struct sockaddr *)&sadr, sizeof(sadr));
		if (opts < 0) { printf("main\n"); return 2; }

		opts = listen(inpt, 2048);
		if (opts < 0) { printf("main\n"); return 3; }

		unsigned int leng = sizeof(sadr);
		int serv, cpor, stat, plen = 0;
		char maps;
		char *cadr;
		pid_t pidn;
		pid_t *pids = NULL;
		while (1) {
			serv = accept(inpt, (struct sockaddr *)&sadr, &leng);
			if (serv < 0) { printf("main\n"); return 4; }

			cadr = inet_ntoa(sadr.sin_addr);
			cpor = ntohs(sadr.sin_port);
			printf("conn: %s:%d\n", cadr, cpor);

			pidn = fork();
			if (pidn == 0) {
				if (mode[0] == 's') { maps = 'e'; }
				if (mode[0] == 'r') { maps = 'd'; }
				fins(inpt, '*', '*');
				proc(maps, prox, skey, serv, cadr, cpor);
				printf("exit:proc:%d\n", getpid());
				exit(0);
			} else if (pidn > 0) {
				int indx = -1;
				for (int x = 0; x < plen; ++x) {
					if (pids[x] == pidn) { indx = x; }
					waitpid(pids[x], &stat, WNOHANG);
					// todo remove pid
				}
				if (indx < 0) {
					++plen;
					pids = realloc(pids, plen * sizeof(pid_t));
					if (pids == NULL) { printf("main\n"); return 5; }
					pids[plen-1] = pidn;
				}
			}

			fins(serv, '*', '*');
		}

		fins(inpt, '*', '*');
	}

	return 0;
}
