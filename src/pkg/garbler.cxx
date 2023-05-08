#include <algorithm>
#include <crypto++/misc.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/garbler.hpp"
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
GarblerClient::GarblerClient(Circuit circuit,
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
GarblerClient::HandleKeyExchange() {
  // Generate private/public DH keys
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^b
  DHPublicValue_Message garbler_public_value_s;
  garbler_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> garbler_public_value_data;
  garbler_public_value_s.serialize(garbler_public_value_data);
  network_driver->send(garbler_public_value_data);

  // Listen for g^a
  std::vector<unsigned char> evaluator_public_value_data = network_driver->read();
  DHPublicValue_Message evaluator_public_value_s;
  evaluator_public_value_s.deserialize(evaluator_public_value_data);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      evaluator_public_value_s.public_value);
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
 * 1) Generate a garbled circuit from the given circuit in this->circuit
 * 2) Send the garbled circuit to the evaluator
 * 3) Send garbler's input labels in the clear
 * 4) Send evaluator's input labels using OT
 * 5) Receive final labels, recover and reveal final output
 * `input` is the evaluator's input for each gate
 * Final output should be a string containing only "0"s or "1"s
 * Throw errors only for invalid MACs
 */
std::string GarblerClient::run(std::vector<int> input) {
  // Key exchange
  auto keys = this->HandleKeyExchange();
  this->AES_key = keys.first;
  this->HMAC_key = keys.second;

  // DONE: implement me!
  GarbledLabels labels = this->generate_labels(this->circuit);

  GarblerToEvaluator_GarbledTables_Message garbledTablesMessage;
  garbledTablesMessage.garbled_tables = this->generate_gates(this->circuit, labels);
  auto garbledTablesMessage_data = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &garbledTablesMessage);
  this->network_driver->send(garbledTablesMessage_data);

  GarblerToEvaluator_GarblerInputs_Message garblerInputsMessage;
  garblerInputsMessage.garbler_inputs = this->get_garbled_wires(labels, input, 0);
  auto garblerInputsMessage_data = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &garblerInputsMessage);
  this->network_driver->send(garblerInputsMessage_data);

  for (int i = 0; i < this->circuit.evaluator_input_length; i++) {
    this->ot_driver->OT_send(byteblock_to_string(labels.zeros.at(this->circuit.garbler_input_length + i).value),
                             byteblock_to_string(labels.ones.at(this->circuit.garbler_input_length + i).value));
  }

  EvaluatorToGarbler_FinalLabels_Message finalLabelsMessage;
  auto finalLabelsMessage_data = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, this->network_driver->read());
  if (!finalLabelsMessage_data.second) {
    throw std::runtime_error("invalid mac");
  }
  finalLabelsMessage.deserialize(finalLabelsMessage_data.first);

  std::string output = "";
  for (int i = 0; i < circuit.output_length; i++) {
    GarbledWire label = finalLabelsMessage.final_labels.at(i);
    if (label.value == labels.zeros.at(circuit.num_wire - circuit.output_length + i).value) {
      output += "0";
    } else {
      output += "1";
    }
  }

  GarblerToEvaluator_FinalOutput_Message finalOutputMessage;
  finalOutputMessage.final_output = output;
  auto finalOutputMessage_data = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &finalOutputMessage);
  this->network_driver->send(finalOutputMessage_data);

  return output;
}

/**
 * Generate the gates for the circuit.
 * You may find `std::random_shuffle` useful
 */
std::vector<GarbledGate> GarblerClient::generate_gates(Circuit circuit,
                                                       GarbledLabels labels) {
  // DONE: implement me!
  std::vector<GarbledGate> gates;
  for (auto gate : circuit.gates) {
    std::vector<CryptoPP::SecByteBlock> entries;
    if (gate.type == GateType::AND_GATE) {
      entries.push_back(encrypt_label(
          labels.zeros.at(gate.lhs), labels.zeros.at(gate.rhs), labels.zeros.at(gate.output)));
      entries.push_back(encrypt_label(
          labels.zeros.at(gate.lhs), labels.ones.at(gate.rhs), labels.zeros.at(gate.output)));
      entries.push_back(encrypt_label(
          labels.ones.at(gate.lhs), labels.zeros.at(gate.rhs), labels.zeros.at(gate.output)));
      entries.push_back(encrypt_label(
          labels.ones.at(gate.lhs), labels.ones.at(gate.rhs), labels.ones.at(gate.output)));
    } else if (gate.type == GateType::XOR_GATE) {
      entries.push_back(encrypt_label(
          labels.zeros.at(gate.lhs), labels.zeros.at(gate.rhs), labels.zeros.at(gate.output)));
      entries.push_back(encrypt_label(
          labels.zeros.at(gate.lhs), labels.ones.at(gate.rhs), labels.ones.at(gate.output)));
      entries.push_back(encrypt_label(
          labels.ones.at(gate.lhs), labels.zeros.at(gate.rhs), labels.ones.at(gate.output)));
      entries.push_back(encrypt_label(
          labels.ones.at(gate.lhs), labels.ones.at(gate.rhs), labels.zeros.at(gate.output)));
    } else { // NOT_GATE
      GarbledWire dummy_wire;
      dummy_wire.value = DUMMY_RHS;
      entries.push_back(encrypt_label(
          labels.zeros.at(gate.lhs), dummy_wire, labels.ones.at(gate.output)));
      entries.push_back(encrypt_label(
          labels.zeros.at(gate.lhs), dummy_wire, labels.ones.at(gate.output)));
      entries.push_back(encrypt_label(
          labels.ones.at(gate.lhs), dummy_wire, labels.zeros.at(gate.output)));
      entries.push_back(encrypt_label(
          labels.ones.at(gate.lhs), dummy_wire, labels.zeros.at(gate.output)));
    }
    // shuffle entries
    std::random_shuffle(entries.begin(), entries.end());
    GarbledGate garbledGate;
    garbledGate.entries = entries;
    gates.push_back(garbledGate);
  }

  return gates;
}

/**
 * Generate *all* labels for the circuit. 
 * To generate an individual label, use `generate_label`.
 */
GarbledLabels GarblerClient::generate_labels(Circuit circuit) {
  // DONE: implement me!
  GarbledLabels output_labels;
  output_labels.zeros.resize(circuit.num_wire);
  output_labels.ones.resize(circuit.num_wire);
  for (auto gate : circuit.gates) {
    GarbledWire lhs0;
    lhs0.value = generate_label();
    GarbledWire lhs1;
    lhs1.value = generate_label();

    GarbledWire rhs0;
    rhs0.value = generate_label();
    GarbledWire rhs1;
    rhs1.value = generate_label();

    GarbledWire out0;
    out0.value = generate_label();
    GarbledWire out1;
    out1.value = generate_label();

    output_labels.zeros.at(gate.lhs) = lhs0; output_labels.zeros.at(gate.rhs) = rhs0; output_labels.zeros.at(gate.output) = out0;
    output_labels.ones.at(gate.lhs) = lhs1; output_labels.ones.at(gate.rhs) = rhs1; output_labels.ones.at(gate.output) = out1;
  }

  return output_labels;
}

/**
 * Generate encrypted label. Tags LABEL_TAG_LENGTH trailing 0s to end before encrypting.
 * You may find CryptoPP::xorbuf and CryptoDriver::hash_inputs useful.
 */
CryptoPP::SecByteBlock GarblerClient::encrypt_label(GarbledWire lhs,
                                                    GarbledWire rhs,
                                                    GarbledWire output) {
  // DONE: implement me!
  auto hashed_val = this->crypto_driver->hash_inputs(lhs.value, rhs.value);
  SecByteBlock expanded_output(output.value);
  expanded_output.CleanGrow(LABEL_LENGTH + LABEL_TAG_LENGTH);

  CryptoPP::xorbuf(hashed_val, expanded_output, LABEL_LENGTH + LABEL_TAG_LENGTH);
  return hashed_val;
}

/**
 * Generate label.
 */
CryptoPP::SecByteBlock GarblerClient::generate_label() {
  CryptoPP::SecByteBlock label(LABEL_LENGTH);
  CryptoPP::OS_GenerateRandomBlock(false, label, label.size());
  return label;
}

/*
 * Given a set of 0/1 labels and an input vector of 0's and 1's, returns the
 * labels corresponding to the inputs starting at begin.
 */
std::vector<GarbledWire>
GarblerClient::get_garbled_wires(GarbledLabels labels, std::vector<int> input,
                                 int begin) {
  std::vector<GarbledWire> res;
  for (int i = 0; i < input.size(); i++) {
    switch (input[i]) {
    case 0:
      res.push_back(labels.zeros[begin + i]);
      break;
    case 1:
      res.push_back(labels.ones[begin + i]);
      break;
    default:
      std::cerr << "INVALID INPUT CHARACTER" << std::endl;
    }
  }
  return res;
}
