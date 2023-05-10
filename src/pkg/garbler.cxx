#include <algorithm>
#include <crypto++/misc.h>
#include <set>

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
    } else if (label.value == labels.ones.at(circuit.num_wire - circuit.output_length + i).value) {
      output += "1";
    } else {
      throw std::runtime_error("didn't find a matching label");
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
    int ne = gate.type == GateType::NOT_GATE ? 2 : 4;
    std::vector<CryptoPP::SecByteBlock> entries(ne);

    auto w_left_0 = labels.zeros.at(gate.lhs);
    auto w_left_1 = labels.ones.at(gate.lhs);
    auto w_right_0 = labels.zeros.at(gate.rhs);
    auto w_right_1 = labels.ones.at(gate.rhs);

    byte p_left_0 = first_bit(w_left_0.value);
    byte p_left_1 = first_bit(w_left_1.value);
    byte p_right_0 = first_bit(w_right_0.value);
    byte p_right_1 = first_bit(w_right_1.value);

    if (gate.type == GateType::NOT_GATE) {
      GarbledWire dummy_wire;
      dummy_wire.value = DUMMY_RHS;

      w_right_0 = dummy_wire;
      w_right_1 = dummy_wire;

      p_right_0 = first_bit(DUMMY_RHS);
      p_right_1 = 1-p_right_0;
    }

    // No longer randomly shuffle, look at the last bit of each label to calculate where to put the correct encryption.
    // 2p_i + p_j th spot
    int index_0_0 = 2 * p_left_0 + p_right_0;
    int index_0_1 = 2 * p_left_0 + p_right_1;
    int index_1_0 = 2 * p_left_1 + p_right_0;
    int index_1_1 = 2 * p_left_1 + p_right_1;

    if (gate.type == GateType::AND_GATE) {
      entries[index_0_0] = encrypt_label(w_left_0, w_right_0, labels.zeros.at(gate.output));
      entries[index_0_1] = encrypt_label(w_left_0, w_right_1, labels.zeros.at(gate.output));
      entries[index_1_0] = encrypt_label(w_left_1, w_right_0, labels.zeros.at(gate.output));
      entries[index_1_1] = encrypt_label(w_left_1, w_right_1, labels.ones.at(gate.output));

      entries.erase(entries.begin());
    } else if (gate.type == GateType::XOR_GATE) {
      // entries[index_0_0] = encrypt_label(w_left_0, w_right_0, labels.zeros.at(gate.output));
      // entries[index_0_1] = encrypt_label(w_left_0, w_right_1, labels.ones.at(gate.output));
      // entries[index_1_0] = encrypt_label(w_left_1, w_right_0, labels.ones.at(gate.output));
      // entries[index_1_1] = encrypt_label(w_left_1, w_right_1, labels.zeros.at(gate.output));
    } else { // NOT_GATE
      int index_0 = p_left_0;
      int index_1 = p_left_1;
      entries[index_0] = encrypt_label(w_left_0, w_right_0, labels.ones.at(gate.output));
      entries[index_1] = encrypt_label(w_left_1, w_right_0, labels.zeros.at(gate.output));
    
      entries.erase(entries.begin());
    }
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

  std::set<int> idx_already_set;

  auto r = generate_label(1);
  for (auto gate : circuit.gates) {
    bool bit;
    std::vector<GarbledWire> lhs = {output_labels.zeros.at(gate.lhs), output_labels.ones.at(gate.lhs)};
    if (idx_already_set.find(gate.lhs) == idx_already_set.end()) {
      bit = random_bit();
      lhs[0].value = generate_label((byte) bit);
      lhs[1].value = CryptoPP::SecByteBlock(lhs[0].value);
      CryptoPP::xorbuf(lhs[1].value, r, LABEL_LENGTH);
    }

    std::vector<GarbledWire> rhs = {output_labels.zeros.at(gate.rhs), output_labels.ones.at(gate.rhs)};
    if (idx_already_set.find(gate.rhs) == idx_already_set.end() && gate.type != GateType::NOT_GATE) {
      bit = random_bit();
      rhs[0].value = generate_label((byte) bit);
      rhs[1].value = CryptoPP::SecByteBlock(rhs[0].value);
      CryptoPP::xorbuf(rhs[1].value, r, LABEL_LENGTH);
    }

    bit = random_bit();
    GarbledWire out0;
    GarbledWire out1;
    if (gate.type == GateType::XOR_GATE) {
      out0.value = CryptoPP::SecByteBlock(lhs[0].value);
      CryptoPP::xorbuf(out0.value, rhs[0].value, LABEL_LENGTH);

      out1.value = CryptoPP::SecByteBlock(out0.value);
      CryptoPP::xorbuf(out1.value, r, LABEL_LENGTH);
    } else {
      int lhs_for_idx_0 = first_bit(lhs[0].value);

      if (gate.type == GateType::AND_GATE) {
        int rhs_for_idx_0 = first_bit(rhs[0].value);

        if (lhs_for_idx_0 && rhs_for_idx_0) {
          out1.value = this->crypto_driver->hash_inputs(lhs[1].value, rhs[1].value);
          out0.value = CryptoPP::SecByteBlock(out1.value);
          CryptoPP::xorbuf(out0.value, r, LABEL_LENGTH);
        } else {
          out0.value = this->crypto_driver->hash_inputs(lhs[lhs_for_idx_0].value, rhs[rhs_for_idx_0].value);
          out1.value = CryptoPP::SecByteBlock(out0.value);
          CryptoPP::xorbuf(out1.value, r, LABEL_LENGTH);
        }
      } else { // NOT_GATE
        GarbledWire dummy_wire;
        dummy_wire.value = DUMMY_RHS;
        if (!lhs_for_idx_0) {
          out1.value = this->crypto_driver->hash_inputs(lhs[0].value, dummy_wire.value);
          out0.value = CryptoPP::SecByteBlock(out1.value);
          CryptoPP::xorbuf(out0.value, r, LABEL_LENGTH);
        } else {
          out0.value = this->crypto_driver->hash_inputs(lhs[1].value, dummy_wire.value);
          out1.value = CryptoPP::SecByteBlock(out0.value);
          CryptoPP::xorbuf(out1.value, r, LABEL_LENGTH);
        }
      }
    }

    output_labels.zeros.at(gate.lhs) = lhs[0]; output_labels.zeros.at(gate.output) = out0;
    output_labels.ones.at(gate.lhs) = lhs[1]; output_labels.ones.at(gate.output) = out1;
    if (gate.type != GateType::NOT_GATE) {
      output_labels.zeros.at(gate.rhs) = rhs[0];
      output_labels.ones.at(gate.rhs) = rhs[1];
    }

    idx_already_set.insert(gate.lhs);
    idx_already_set.insert(gate.rhs);
    idx_already_set.insert(gate.output);
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
CryptoPP::SecByteBlock GarblerClient::generate_label(byte select_bit) {
  CryptoPP::SecByteBlock label(LABEL_LENGTH);
  CryptoPP::OS_GenerateRandomBlock(false, label, label.size());
  label.BytePtr()[0] |= (select_bit << 7);
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
