#include "../../include/pkg/evaluator.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../../include-shared/logger.hpp"

/*
Syntax to use logger: 
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
  src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor. Note that the OT_driver is left uninitialized.
 */
EvaluatorClient::EvaluatorClient(Circuit circuit,
                           std::shared_ptr<NetworkDriver> network_driver,
                           std::shared_ptr<CryptoDriver> crypto_driver) {
  this->circuit = circuit;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
}

/**
 * Handle key exchange with evaluator
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
EvaluatorClient::HandleKeyExchange() {
  // Generate private/public DH keys
  auto dh_values = this->crypto_driver->DH_initialize();

  // Listen for g^b
  std::vector<unsigned char> garbler_public_value_data = network_driver->read();
  DHPublicValue_Message garbler_public_value_s;
  garbler_public_value_s.deserialize(garbler_public_value_data);

  // Send g^a
  DHPublicValue_Message evaluator_public_value_s;
  evaluator_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> evaluator_public_value_data;
  evaluator_public_value_s.serialize(evaluator_public_value_data);
  network_driver->send(evaluator_public_value_data);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      garbler_public_value_s.public_value);
  CryptoPP::SecByteBlock AES_key =
      this->crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      this->crypto_driver->HMAC_generate_key(DH_shared_key);
  auto keys = std::make_pair(AES_key, HMAC_key);
  this->ot_driver =
      std::make_shared<OTDriver>(network_driver, crypto_driver, keys);
  return keys;
}

/**
 * run. This function should:
 * 1) Receive the garbled circuit and the garbler's input
 * 2) Reconstruct the garbled circuit and input the garbler's inputs
 * 3) Retrieve evaluator's inputs using OT
 * 4) Evaluate gates in order (use `GarbledCircuit::evaluate_gate` to help!)
 * 5) Send final labels to the garbler
 * 6) Receive final output
 * `input` is the evaluator's input for each gate
 * You may find `string_to_byteblock` useful for converting OT output to wires
 * Disconnect and throw errors only for invalid MACs
 */
std::string EvaluatorClient::run(std::vector<int> input) {
  // Key exchange
  auto keys = this->HandleKeyExchange();
  auto AES_key = keys.first;
  auto HMAC_key = keys.second;

  // TODO: implement me!
  GarblerToEvaluator_GarbledTables_Message ge_gt_msg;
  auto ge_gt_msg_data = this->crypto_driver->decrypt_and_verify(AES_key, HMAC_key, this->network_driver->read());
  if (!ge_gt_msg_data.second) {
    this->network_driver->disconnect();
    throw std::runtime_error("oopsie poopsie");
  }
  ge_gt_msg.deserialize(ge_gt_msg_data.first);
  auto garbled_gates = ge_gt_msg.garbled_tables;

  GarblerToEvaluator_GarblerInputs_Message ge_gi_msg;
  auto ge_gi_msg_data = this->crypto_driver->decrypt_and_verify(AES_key, HMAC_key, this->network_driver->read());
  if (!ge_gi_msg_data.second) {
    this->network_driver->disconnect();
    throw std::runtime_error("oopsie poopsie 2");
  }
  ge_gi_msg.deserialize(ge_gi_msg_data.first);
  auto garbler_inputs = ge_gi_msg.garbler_inputs;

  std::vector<GarbledWire> evaluator_inputs;
  for (int i = 0; i < circuit.evaluator_input_length; ++i) {
    auto label = this->ot_driver->OT_recv(input.at(i));
    GarbledWire wire(string_to_byteblock(label));
    evaluator_inputs.push_back(wire);
  }

  GarbledWire curr_out;
  for (auto gate : garbled_gates) {
      curr_out =
  }
}

/**
 * Evaluate gate.
 * You may find CryptoPP::xorbuf and CryptoDriver::hash_inputs useful.
 * To determine if a decryption is valid, use verify_decryption.
 * To retrieve the label from a decryption, use snip_decryption.
 */
GarbledWire EvaluatorClient::evaluate_gate(GarbledGate gate, GarbledWire lhs,
                                        GarbledWire rhs) {
  // DONE: implement me!
  for (auto entry : gate.entries) {
    SecByteBlock hashed_val = this->crypto_driver->hash_inputs(lhs.value, rhs.value);
    CryptoPP::xorbuf(hashed_val, entry, LABEL_LENGTH + LABEL_TAG_LENGTH);
    if (verify_decryption(hashed_val)) {
      SecByteBlock head = snip_decryption(hashed_val);
      GarbledWire out(head);
      return out;
    }
  }
}

/**
 * Verify decryption. A valid dec should end with LABEL_TAG_LENGTH bits of 0s.
 */
bool EvaluatorClient::verify_decryption(CryptoPP::SecByteBlock decryption) {
  CryptoPP::SecByteBlock trail(decryption.data() + LABEL_LENGTH,
                               LABEL_TAG_LENGTH);
  return byteblock_to_integer(trail) == CryptoPP::Integer::Zero();
}

/**
 * Returns the first LABEL_LENGTH bits of a decryption.
 */
CryptoPP::SecByteBlock EvaluatorClient::snip_decryption(CryptoPP::SecByteBlock decryption) {
  CryptoPP::SecByteBlock head(decryption.data(), LABEL_LENGTH);
  return head;
}
