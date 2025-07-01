//
// Created by Bincker on 2025/7/1.
//

#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <openssl/ec.h>

class Crypto {
public:
    static EVP_PKEY* generate_ecc_keypair();

    static std::vector<unsigned char> export_public_key(EVP_PKEY* pkey);

    static std::vector<unsigned char> export_private_key(EVP_PKEY* pkey);

    static EVP_PKEY* import_public_key(const std::vector<unsigned char>& pubkey_data);

    static EVP_PKEY* import_private_key(const std::vector<unsigned char>& private_data);

    static std::vector<unsigned char> derive_shared_secret(EVP_PKEY* prv_key, EVP_PKEY* pub_key);

    static std::vector<unsigned char> derive_key_with_hkdf(
        const std::vector<unsigned char> &shared_secret,
        const std::vector<unsigned char> &salt,
        const std::vector<unsigned char> &info,
        size_t output_length
    );
};


#endif //CRYPTO_H
