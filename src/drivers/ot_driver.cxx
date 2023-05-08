#include <iostream>
#include <stdexcept>
#include <string>

#include "crypto++/base64.h"
#include "crypto++/dsa.h"
#include "crypto++/osrng.h"
#include "crypto++/rsa.h"
#include <crypto++/cryptlib.h>
#include <crypto++/elgamal.h>
#include <crypto++/files.h>
#include <crypto++/hkdf.h>
#include <crypto++/nbtheory.h>
#include <crypto++/queue.h>
#include <crypto++/sha.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/ot_driver.hpp"

/*
 * Constructor
 */
OTDriver::OTDriver(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->AES_key = keys.first;
  this->HMAC_key = keys.second;
  this->cli_driver = std::make_shared<CLIDriver>();
}

/*
 * Send either m0 or m1 using OT. This function should:
 * 1) Sample a public DH value and send it to the receiver
 * 2) Receive the receiver's public value
 * 3) Encrypt m0 and m1 using different keys
 * 4) Send the encrypted values
 * You may find `byteblock_to_integer` and `integer_to_byteblock` useful
 * Disconnect and throw errors only for invalid MACs
 */
void OTDriver::OT_send(std::string m0, std::string m1) {
  // DONE: implement me!
  auto dh = this->crypto_driver->DH_initialize();
  SenderToReceiver_OTPublicValue_Message pub_val_msg;
  pub_val_msg.public_value = std::get<2>(dh);
  std::vector<unsigned char> pub_val_msg_data = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &pub_val_msg);
  this->network_driver->send(pub_val_msg_data);

  ReceiverToSender_OTPublicValue_Message ot_pub_val_msg;
  auto ot_pub_val_msg_data = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, this->network_driver->read());
  if (!ot_pub_val_msg_data.second) {
    this->network_driver->disconnect();
    throw std::runtime_error("invalid message");
  }
  ot_pub_val_msg.deserialize(ot_pub_val_msg_data.first);

  auto first_shared_key = this->crypto_driver->DH_generate_shared_key(std::get<0>(dh), std::get<1>(dh),
      ot_pub_val_msg.public_value);
  auto second_shared_key_pv = (byteblock_to_integer(ot_pub_val_msg.public_value)
      * CryptoPP::EuclideanMultiplicativeInverse(byteblock_to_integer(std::get<2>(dh)), DL_P)) % DL_P;
  auto second_shared_key = this->crypto_driver->DH_generate_shared_key(
      std::get<0>(dh), std::get<1>(dh), integer_to_byteblock(second_shared_key_pv));

  auto first_shared_key_aes = this->crypto_driver->AES_generate_key(first_shared_key);
  auto second_shared_key_aes = this->crypto_driver->AES_generate_key(second_shared_key);

  auto e0 = this->crypto_driver->AES_encrypt(first_shared_key_aes, m0);
  auto e1 = this->crypto_driver->AES_encrypt(second_shared_key_aes, m1);

  SenderToReceiver_OTEncryptedValues_Message enc_msg;
  enc_msg.e0 = e0.first;
  enc_msg.iv0 = e0.second;
  enc_msg.e1 = e1.first;
  enc_msg.iv1 = e1.second;
  std::vector<unsigned char> enc_msg_data = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &enc_msg);
  this->network_driver->send(enc_msg_data);
}

/*
 * Receive m_c using OT. This function should:
 * 1) Read the sender's public value
 * 2) Respond with our public value that depends on our choice bit
 * 3) Generate the appropriate key and decrypt the appropriate ciphertext
 * You may find `byteblock_to_integer` and `integer_to_byteblock` useful
 * Disconnect and throw errors only for invalid MACs
 */
std::string OTDriver::OT_recv(int choice_bit) {
  // DONE: implement me!
  auto dh = this->crypto_driver->DH_initialize();

  SenderToReceiver_OTPublicValue_Message ot_pub_val_msg;
  auto ot_pub_val_msg_data = this->crypto_driver->decrypt_and_verify(this->AES_key,
                                                                     this->HMAC_key,
                                                                     this->network_driver->read());
  if (!ot_pub_val_msg_data.second) {
    this->network_driver->disconnect();
    throw std::runtime_error("oopsie poopsie");
  }
  ot_pub_val_msg.deserialize(ot_pub_val_msg_data.first);

  SecByteBlock pub_val;
  if (choice_bit == 0) {
    pub_val = std::get<2>(dh);
  } else {
    pub_val = integer_to_byteblock(byteblock_to_integer(ot_pub_val_msg.public_value) * byteblock_to_integer(std::get<2>(dh)) % DL_P);
  }

  ReceiverToSender_OTPublicValue_Message pub_val_msg;
  pub_val_msg.public_value = pub_val;
  auto pub_val_msg_data = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &pub_val_msg);
  this->network_driver->send(pub_val_msg_data);

  auto shared_secret = this->crypto_driver->DH_generate_shared_key(std::get<0>(dh), std::get<1>(dh), ot_pub_val_msg.public_value);
  auto choice_key = this->crypto_driver->AES_generate_key(shared_secret);

  SenderToReceiver_OTEncryptedValues_Message enc_val_msg;
  auto enc_val_msg_data = this->crypto_driver->decrypt_and_verify(this->AES_key,
                                                                  this->HMAC_key,
                                                                  this->network_driver->read());
  if (!enc_val_msg_data.second) {
    this->network_driver->disconnect();
    throw std::runtime_error("oopsie poopsie 2");
  }
  enc_val_msg.deserialize(enc_val_msg_data.first);

  if (choice_bit == 0) {
    return this->crypto_driver->AES_decrypt(choice_key, enc_val_msg.iv0, enc_val_msg.e0);
  } else {
    return this->crypto_driver->AES_decrypt(choice_key, enc_val_msg.iv1, enc_val_msg.e1);
  }
}