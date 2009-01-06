// libTorrent - BitTorrent library
// Copyright (C) 2005-2007, Jari Sundell
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// In addition, as a special exception, the copyright holders give
// permission to link the code of portions of this program with the
// OpenSSL library under certain conditions as described in each
// individual source file, and distribute linked combinations
// including the two.
//
// You must obey the GNU General Public License in all respects for
// all of the code used other than OpenSSL.  If you modify file(s)
// with this exception, you may extend this exception to your version
// of the file(s), but you are not obligated to do so.  If you do not
// wish to do so, delete this exception statement from your version.
// If you delete this exception statement from all source files in the
// program, then also delete it here.
//
// Contact:  Jari Sundell <jaris@ifi.uio.no>
//
//           Skomakerveien 33
//           3185 Skoppum, NORWAY

#include "config.h"

#include <string>

#ifdef USE_OPENSSL
#include <openssl/bn.h>
#endif

#include "diffie_hellman.h"
#include "torrent/exceptions.h"

namespace torrent {

static int generate_key(DH *dh)
	{
	int ok=0;
	int generate_new_key=0;
	unsigned l;
	BN_CTX *ctx;
	BN_MONT_CTX *mont=NULL;
	BIGNUM *pub_key=NULL,*priv_key=NULL;

	ctx = BN_CTX_new();
	if (ctx == NULL) goto err;

	if (dh->priv_key == NULL)
		{
		priv_key=BN_new();
		if (priv_key == NULL) goto err;
		generate_new_key=1;
		}
	else
		priv_key=dh->priv_key;

	if (dh->pub_key == NULL)
		{
		pub_key=BN_new();
		if (pub_key == NULL) goto err;
		}
	else
		pub_key=dh->pub_key;


	if (dh->flags & DH_FLAG_CACHE_MONT_P)
		{
		mont = BN_MONT_CTX_set_locked((BN_MONT_CTX **)(&dh->method_mont_p),
				CRYPTO_LOCK_DH, dh->p, ctx);
		if (!mont)
			goto err;
		}

	if (generate_new_key)
		{
		l = dh->length ? dh->length : BN_num_bits(dh->p)-1; /* secret exponent length */
		if (!BN_rand(priv_key, l, 0, 0))
			if (!BN_pseudo_rand(priv_key, l, 0, 0)) goto err;
		}

	{
		BIGNUM local_prk;
		BIGNUM *prk;

		if ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) == 0)
			{
			BN_init(&local_prk);
			prk = &local_prk;
			BN_with_flags(prk, priv_key, BN_FLG_EXP_CONSTTIME);
			}
		else
			prk = priv_key;

		if (!dh->meth->bn_mod_exp(dh, pub_key, dh->g, prk, dh->p, ctx, mont)) goto err;
	}

	dh->pub_key=pub_key;
	dh->priv_key=priv_key;
	ok=1;
err:
	if (ok != 1) {
	}

	if ((pub_key != NULL)  && (dh->pub_key == NULL))  BN_free(pub_key);
	if ((priv_key != NULL) && (dh->priv_key == NULL)) BN_free(priv_key);
	BN_CTX_free(ctx);
	return(ok);
}

DiffieHellman::DiffieHellman(const unsigned char *prime, int primeLength,
                             const unsigned char *generator, int generatorLength) :
  m_secret(NULL) {

#ifdef USE_OPENSSL
  m_dh = DH_new();
  m_dh->p = BN_bin2bn(prime, primeLength, NULL);
  m_dh->g = BN_bin2bn(generator, generatorLength, NULL);

  if (!generate_key(m_dh))
    throw internal_error("Unable to generate encryption key.");
#else
  throw internal_error("Compiled without encryption support.");
#endif
};

DiffieHellman::~DiffieHellman() {
  delete [] m_secret;
#ifdef USE_OPENSSL
  DH_free(m_dh);
#endif
};

void
DiffieHellman::compute_secret(const unsigned char *pubkey, unsigned int length) {
#ifdef USE_OPENSSL
  BIGNUM* k = BN_bin2bn(pubkey, length, NULL);

  delete [] m_secret;
  m_secret = new char[DH_size(m_dh)];

  m_size = DH_compute_key((unsigned char*)m_secret, k, m_dh);
  
  BN_free(k);
#endif
};

void
DiffieHellman::store_pub_key(unsigned char* dest, unsigned int length) {
#ifdef USE_OPENSSL
  std::memset(dest, 0, length);

  if ((int)length >= BN_num_bytes(m_dh->pub_key))
    BN_bn2bin(m_dh->pub_key, dest + length - BN_num_bytes(m_dh->pub_key));
#endif
}

};
