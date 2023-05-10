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
  this->AES_key = keys.first;
  this->HMAC_key = keys.second;

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
    GarbledWire wire;
    wire.value = string_to_byteblock(label);
    evaluator_inputs.push_back(wire);
  }

  std::vector<GarbledWire> garbled_wires(this->circuit.num_wire);
  // copy the garbler's inputs in
  for (int i = 0; i < circuit.garbler_input_length; i++) {
    garbled_wires.at(i) = garbler_inputs.at(i);
  }
  // copy the evaluators inputs in
  for (int i = 0; i < circuit.evaluator_input_length; i++) {
    garbled_wires.at(circuit.garbler_input_length + i) = evaluator_inputs.at(i);
  }
  // evaluate remaining wires
  for (int i = 0; i < circuit.num_gate; i++) {
    Gate gate = circuit.gates.at(i);
    GarbledWire wire;
    if (gate.type == GateType::NOT_GATE) {
      GarbledWire dummy_wire;
      dummy_wire.value = DUMMY_RHS;
      wire = this->evaluate_gate(
          garbled_gates.at(i), garbled_wires.at(gate.lhs), dummy_wire);
    } else if (gate.type == GateType::XOR_GATE) {
      wire.value = SecByteBlock(garbled_wires.at(gate.lhs).value);
      CryptoPP::xorbuf(wire.value, garbled_wires.at(gate.rhs).value, LABEL_LENGTH);
    } else {
      wire = this->evaluate_gate(
          garbled_gates.at(i), garbled_wires.at(gate.lhs), garbled_wires.at(gate.rhs));
    }
    garbled_wires.at(gate.output) = wire;
  }

  EvaluatorToGarbler_FinalLabels_Message finalLabelsMessage;
  for (int i = 0; i < circuit.output_length; i++) {
    finalLabelsMessage.final_labels.push_back(garbled_wires.at(circuit.num_wire - circuit.output_length + i));
  }
  this->network_driver->send(this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &finalLabelsMessage));

  // receive final output
  GarblerToEvaluator_FinalOutput_Message finalOutputMessage;
  auto finalOutputMessage_data = this->crypto_driver->decrypt_and_verify(AES_key, HMAC_key, this->network_driver->read());
  if (!finalOutputMessage_data.second) {
    this->network_driver->disconnect();
    throw std::runtime_error("oopsie poopsie 2");
  }
  finalOutputMessage.deserialize(finalOutputMessage_data.first);

  std::cout << finalOutputMessage.final_output << std::endl;
  return finalOutputMessage.final_output;
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
  GarbledWire out;
  auto lhs_b = first_bit(lhs.value);
  auto rhs_b = first_bit(rhs.value);

  SecByteBlock hashed_val = this->crypto_driver->hash_inputs(lhs.value, rhs.value);

  if (!lhs_b && !rhs_b) {
    out.value = hashed_val;
  } else {
    int idx = 2 * lhs_b + rhs_b - 1;
    auto entry = gate.entries[idx];
    CryptoPP::xorbuf(hashed_val, entry, LABEL_LENGTH + LABEL_TAG_LENGTH);
    out.value = hashed_val;
  }

  return out;
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
