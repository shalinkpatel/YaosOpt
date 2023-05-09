#include <crypto++/osrng.h>
#include "../include-shared/util.hpp"

/**
 * Convert char vec to string.
 */
std::string chvec2str(std::vector<unsigned char> data) {
  std::string s(data.begin(), data.end());
  return s;
}

/**
 * Convert string to char vec.
 */
std::vector<unsigned char> str2chvec(std::string s) {
  std::vector<unsigned char> v(s.begin(), s.end());
  return v;
}

/**
 * Convert char vec to string.
 */
std::string hex_encode(std::string s) {
  std::string res;
  CryptoPP::StringSource(
      s, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(res)));
  return res;
}

/**
 * Convert string to char vec.
 */
std::string hex_decode(std::string s) {
  std::string res;
  CryptoPP::StringSource(
      s, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(res)));
  return res;
}

/**
 * Converts a byte block into an integer.
 */
CryptoPP::Integer byteblock_to_integer(const CryptoPP::SecByteBlock &block) {
  return CryptoPP::Integer(block, block.size());
}

/**
 * Converts an integer into a byte block.
 */
CryptoPP::SecByteBlock integer_to_byteblock(const CryptoPP::Integer &x) {
  size_t encodedSize = x.MinEncodedSize(CryptoPP::Integer::UNSIGNED);
  CryptoPP::SecByteBlock bytes(encodedSize);
  x.Encode(bytes.BytePtr(), encodedSize, CryptoPP::Integer::UNSIGNED);
  return bytes;
}

/**
 * Converts a byte block into a string.
 */
std::string byteblock_to_string(const CryptoPP::SecByteBlock &block) {
  return std::string(block.begin(), block.end());
}
/**
 * Converts a string into a byte block.
 */
CryptoPP::SecByteBlock string_to_byteblock(const std::string &s) {
  CryptoPP::SecByteBlock block(reinterpret_cast<const byte *>(&s[0]), s.size());
  return block;
}

bool random_bit() {
  return (std::rand() % 2) == 0;
}

/**
 * Given a string, it prints its hex representation of the raw bytes it
 * contains. Used for debugging.
 */
void print_string_as_hex(std::string str) {
  for (int i = 0; i < str.length(); i++) {
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<int>(str[i]) << " ";
  }
  std::cout << std::endl;
}

/**
 * Prints contents as integer
 */
void print_key_as_int(const CryptoPP::SecByteBlock &block) {
  std::cout << byteblock_to_integer(block) << std::endl;
}

/**
 * Prints contents as hex.
 */
void print_key_as_hex(const CryptoPP::SecByteBlock &block) {
  std::string result;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));

  encoder.Put(block, block.size());
  encoder.MessageEnd();

  std::cout << result << std::endl;
}

/**
 * Split a string.
 */
std::vector<std::string> string_split(std::string str, char delimiter) {
  std::vector<std::string> result;
  // construct a stream from the string
  std::stringstream ss(str);
  std::string s;
  while (std::getline(ss, s, delimiter)) {
    result.push_back(s);
  }
  return result;
}

/**
 * Parse input to circuit
 */
std::vector<int> parse_input(std::string input_file) {
  std::string input_str;
  CryptoPP::FileSource(input_file.c_str(), true,
                       new CryptoPP::StringSink(input_str));

  std::vector<int> res;
  for (int i = 0; i < input_str.length(); i++) {
    switch (input_str[i]) {
    case '0':
      res.push_back(0);
      break;
    case '1':
      res.push_back(1);
      break;
    }
  }
  return res;
}

/*
 * Return the first byte of a SecByteBlock
 * */
byte first_byte(CryptoPP::SecBlock<byte> label) {
  return label.BytePtr()[0];
}
