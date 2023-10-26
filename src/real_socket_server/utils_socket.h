// @file utils-socket.h - utilities to be used with real_socket_server example
// @author: Ian Quah, David Cousins
// TPOC: contact@openfhe-crypto.org

// @copyright Copyright (c) 2020 2023, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef REAL_SERVER_UTILS_H
#define REAL_SERVER_UTILS_H

#include "openfhe.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"


#include <chrono>
#include <complex>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <string>
#include <tuple>
#include <unistd.h>
#include <vector>
#include <dirent.h>
#include <fstream>
#include <thread>
#include <cstring>
#include <boost/asio.hpp>

using namespace lbcrypto;

#define short versions of commonly used OpenFHE data types
using CC = CryptoContext<DCRTPoly>;
using CT = Ciphertext<DCRTPoly>;
using PubKey = PublicKey<DCRTPoly>;
using KPair = KeyPair<DCRTPoly>;
using CFactory = CryptoContextFactory<DCRTPoly>;
  
using boost::asio::ip::tcp;

using complexVector = std::vector<std::complex<double>>;
using complexMatrix = std::vector<complexVector>;
using ciphertextMatrix = std::vector<CT>;

const int VECTORSIZE = 4;
const int CRYPTOCONTEXT_INDEX = 0;
const int PUBLICKEY_INDEX = 1;


/**
 * validateData - test if two vectors (really, two indexable containers) are
 * equal element-wise to within some tolerance
 * @tparam T some iterable
 * @param v1 vector1
 * @param v2 vector2
 * @param tol float
 * @return
 */
template <typename T>
bool validateData(const T &v1, const T &v2, const float &tol = 0.0001) {
  if (v1.size() != v2.size()) {
    return false;
  }
  for (unsigned int i = 0; i < v1.size(); i++) {
    // do a scale check. Fails for numbers that are extremely close to 0.
    if (std::abs((v1[i] - v2[i]) / v1[i]) > tol) {
      // if the above fails, we assume it's close to 0 and we check that both
      // numbers are extremely small
      if (std::abs(v1[i] - v2[i]) > tol) {
        return false;
      }  // Pass ABSOLUTE CHECK: it's true and we continue
    }
  }
  return true;
}

/**
 * Take a powernap of 0.5 seconds
 */
void nap(const int &ms = 500) {
  std::chrono::duration<int, std::milli> timespan(ms);
  std::this_thread::sleep_for(timespan);
}


/**
 * sendBuffer over socket. sends a size_t size of buffer then the buffer itself 
 * @param b streambuf to be sent. 
 * @param s socket to send over
 */
void sendBuffer(boost::asio::streambuf &b, tcp::socket &s){
  size_t bSize = b.size();
  std::cout << "streamed to buffer " << bSize << " bytes" << std::endl;
  std::cout << "SERVER: send size to socket" << std::endl;  
  size_t nSent;
  nSent = s.send(boost::asio::buffer(&bSize, sizeof(bSize)));  
  std::cout << "SERVER: sent " << nSent << " bytes to socket" << std::endl;    
  std::cout << "SERVER: sending data to socket" << std::endl;  
  nSent = s.send(b.data());
  std::cout << "SERVER: sent " << nSent << " data bytes to socket" << std::endl;    
}

/**
 * recvLength returns length of next buffer to be received over socket s
 * @param s socket to use
 */
size_t recvLength(tcp::socket &s){
  
  //read length
  size_t inLength;
  std::cout << "CLIENT: reading length from socket" << std::endl;
  size_t nRead = boost::asio::read(s, boost::asio::buffer(&inLength, sizeof(inLength)));
  std::cout << "CLIENT: read "<< nRead << " bytes from socket" << std::endl;
  std::cout << "CLIENT: will read "<< inLength << " bytes from socket" << std::endl;
  return inLength;
}


/**
 * sendCT sends a CT over socket s
 * @param s socket to send over
 * @param CT to send
 */
 
void sendCT(tcp::socket &s, const CT &ct){
  boost::asio::streambuf b;
  std::ostream os(&b);
  std::cout << "SERVER: sending cryptotext" << std::endl;
  Serial::Serialize(ct, os, SerType::BINARY);
  sendBuffer(b, s);
}

/**
 * recvCT received a CT over socket s
 * @param s socket to receive from
 * @return CT received CT
 */
 
CT recvCT(tcp::socket &s){
  CT c1;
  {
	boost::asio::streambuf b(recvLength(s));
	std::istream is(&b);
	size_t nRead = boost::asio::read(s, b);
	std::cout << "CLIENT: read "<< nRead << " bytes from socket" << std::endl;
	Serial::Deserialize(c1, is, SerType::BINARY);
	std::cout << "CLIENT: ciphertext deserialized" << std::endl;
  }  
  return c1;
}

/**
 * sendCC sends a CC over socket s
 * @param s socket to send over
 * @param CC to send
 */
 
void sendCC(tcp::socket &s, const CC &cc){
  boost::asio::streambuf b;
  std::ostream os(&b);
  std::cout << "SERVER: sending cryptocontext" << std::endl;
  Serial::Serialize(cc, os, SerType::BINARY);
  sendBuffer(b, s);
}

/**
 * recvCC received a CC over socket s
 * @param s socket to receive from
 * @return CC received CC
 */
 
CC recvCC(tcp::socket &s){
  CC cc;
  {
	boost::asio::streambuf b(recvLength(s));
	std::istream is(&b);
	size_t nRead = boost::asio::read(s, b);
	std::cout << "CLIENT: read "<< nRead << " bytes CC from socket" << std::endl;
	Serial::Deserialize(cc, is, SerType::BINARY);
	std::cout << "CLIENT: CC deserialized" << std::endl;
  }  
  return cc;
}

/**
 * sendPublicKey sends a PublicKey over socket s
 * @param s socket to send over
 * @param PublicKey to send
 */
 
void sendPublicKey(tcp::socket &s, const PubKey &pk){
  boost::asio::streambuf b;
  std::ostream os(&b);
  std::cout << "SERVER: sending Public key" << std::endl;
  Serial::Serialize(pk, os, SerType::BINARY);
  sendBuffer(b, s);
}


/**
 * recvPublicKey received a PublicKey over socket s
 * @param s socket to receive from
 * @return PublicKey received PublicKey
 */
 
PubKey recvPublicKey(tcp::socket &s){
  PubKey pk;
  {
	boost::asio::streambuf b(recvLength(s));
	std::istream is(&b);
	size_t nRead = boost::asio::read(s, b);
	std::cout << "CLIENT: read "<< nRead << " bytes PublicKey from socket" << std::endl;
	Serial::Deserialize(pk, is, SerType::BINARY);
	std::cout << "CLIENT: PublicKey deserialized" << std::endl;
  }  
  return pk;
}

/**
 * sendEvalMultKey sends a EvalMultKey over socket s
 * @param s socket to send over
 * @param EvalMultKey to send
 */
 
void sendEvalMultKey(tcp::socket &s, const CC &cc){
  boost::asio::streambuf b;
  std::ostream os(&b);
  std::cout << "SERVER: sending EvalMult/reliniarization key" << std::endl;
  if (!cc->SerializeEvalMultKey(os, SerType::BINARY)) {
	std::cerr << "SERVER: Error writing eval mult keys" << std::endl;
	std::exit(1);
  }
  sendBuffer(b, s);
}

/**
 * recvEvalMultKey received a EvalMultKey over socket s
 * @param s socket to receive from
 * @return EvalMultKey received EvalMultKey
 */
 
void recvEvalMultKey(tcp::socket &s, CC &cc){
  boost::asio::streambuf b(recvLength(s));
  std::istream is(&b);
  size_t nRead = boost::asio::read(s, b);
  std::cout << "CLIENT: read "<< nRead << " bytes evalMult key from socket" << std::endl;
  if (!cc->DeserializeEvalMultKey(is, SerType::BINARY)) {
	std::cerr << "CLIENT: Could not deserialize eval mult key file"
			  << std::endl;
	std::exit(1);
  }
  std::cout << "CLIENT: Relinearization keys from server deserialized." << std::endl;
}


/**
 * sendEvalAutomorphismKey sends a EvalAutomorphismKey over socket s
 * @param s socket to send over
 * @param EvalAutomorphismKey to send
 */
 
void sendEvalAutomorphismKey(tcp::socket &s, const CC &cc){
  boost::asio::streambuf b;
  std::ostream os(&b);
  std::cout << "SERVER: sending Rotation keys" << std::endl;
  if (!cc->SerializeEvalAutomorphismKey(os, SerType::BINARY)) {
	std::cerr << "SERVER: Error writing rotation keys" << std::endl;
	std::exit(1);
  }
  sendBuffer(b, s);
}


/**
 * recvEvalAutomorphismKey received a EvalAutomorphismKey over socket s
 * @param s socket to receive from
 * @return EvalAutomorphismKey received EvalAutomorphismKey
 */
 
void recvEvalAutomorphismKey(tcp::socket &s, CC &cc){
  boost::asio::streambuf b(recvLength(s));
  std::istream is(&b);
  size_t nRead = boost::asio::read(s, b);
  std::cout << "CLIENT: read "<< nRead << " bytes eval automorphism key from socket" << std::endl;
  if (!cc->DeserializeEvalAutomorphismKey(is, SerType::BINARY)) {
	std::cerr << "CLIENT: Could not deserialize eval automorphism (rotation) key"
			  << std::endl;
	std::exit(1);
  }
  std::cout << "CLIENT: Relinearization keys from server deserialized." << std::endl;
}





#endif  // REAL_SERVER_UTILS_H
