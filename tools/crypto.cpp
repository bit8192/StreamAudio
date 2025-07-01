//
// Created by Bincker on 2025/7/1.
//

#include "crypto.h"

EVP_PKEY * Crypto::generate_ecc_keypair() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) handleErrors();

    if (EVP_PKEY_keygen_init(pctx) <= 0) handleErrors();

    // 使用 secp384r1 曲线
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <= 0) handleErrors();

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

std::vector<unsigned char> Crypto::export_public_key(EVP_PKEY *pkey) {
}

std::vector<unsigned char> Crypto::export_private_key(EVP_PKEY *pkey) {
}

EVP_PKEY * Crypto::import_public_key(const std::vector<unsigned char> &pubkey_data) {
}

EVP_PKEY * Crypto::import_private_key(const std::vector<unsigned char> &private_data) {
}

std::vector<unsigned char> Crypto::derive_shared_secret(EVP_PKEY *prv_key, EVP_PKEY *pub_key) {
}

std::vector<unsigned char> Crypto::derive_key_with_hkdf(
    const std::vector<unsigned char> &shared_secret,
    const std::vector<unsigned char> &salt,
    const std::vector<unsigned char> &info,
    size_t output_length
) {
}
