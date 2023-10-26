// @file pre-utils.h - utilities to be used with
//    pre-client
//    pre-server
// @authors: David Cousins, Ian Quah
// TPOC: contact@openfhe-crypto.org

// @copyright Copyright (c) 2020, 2023 Duality Technologies Inc.
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

// remove explicit directory

#ifndef PRE_UTILS_H
#define PRE_UTILS_H

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <boost/interprocess/streams/bufferstream.hpp> // to convert between Serialize and msg
#include <fstream>
#include <iostream>
#include <olc_net.h>

using namespace lbcrypto;

// shortcuts for OpenFHE types to make the code more readable
using CC = CryptoContext<DCRTPoly>;   // crypto context
using CT = Ciphertext<DCRTPoly>;      // ciphertext
using PT = Plaintext;                 // plaintext
using KPair = KeyPair<DCRTPoly>;      // secret/public key par.
using EvKey = EvalKey<DCRTPoly>;      // evaluation key (reencryption key)
using PrivKey = PrivateKey<DCRTPoly>; // secret key of par.
using PubKey = PublicKey<DCRTPoly>;   // public key of par.
using vecInt = std::vector<int64_t>;  // vector of ints

struct Configs {
  std::string producer_aes_key = "demoData/keys/producer_aes_key.txt";
  std::string consumer_aes_key = "demoData/keys/consumer_aes_key";
};

Configs GConf;

enum class PreMsgTypes : uint32_t {
  ServerAccept,
  RequestCC,
  SendCC,
  SendPublicKey,
  AckPublicKey,
  SendPrivateKey,
  AckPrivateKey,
  RequestReEncryptionKey,
  SendReEncryptionKey,
  NackReEncryptionKey,
  SendCT,
  AckCT,
  RequestCT,
  NackCT,
  SendVecInt,
  AckVecInt,
  RequestVecInt,
  NackVecInt,
};

std::vector<std::string> PreMsgNames{
    "ServerAccept",
    "RequestCC",
    "SendCC",
    "SendPublicKey",
    "AckPublicKey",
    "SendPrivateKey",
    "AckPrivateKey",
    "RequestReEncryptionKey",
    "SendReEncryptionKey",
    "NackReEncryptionKey",
    "SendCT",
    "AckCT",
    "RequestCT",
    "NackCT",
    "SendVecInt",
    "AckVecInt",
    "RequestVecInt",
    "NackVecInt",
};

// Code to convert from enum class to underlying int for reference.
std::ostream &operator<<(std::ostream &os, const PreMsgTypes &obj) {
  os << static_cast<std::underlying_type<PreMsgTypes>::type>(obj);
  os << ": "
     << PreMsgNames[static_cast<std::underlying_type<PreMsgTypes>::type>(obj)];
  return os;
}

/**
 * Take a powernap of (DEFAULT) 0.5 seconds
 * @param ms - number of milisec to nap
 */
void nap(const int &ms = 500) {
  std::chrono::duration<int, std::milli> timespan(ms);
  std::this_thread::sleep_for(timespan);
}

void checkVecInt(std::string name, vecInt v) {
  size_t sz = v.size();
  std::cout << name << " First 8 points: ";
  for (size_t i = 0; i < 8; i++) { // print
    std::cout << v[i] << " ";
  }
  std::cout << std::endl;
  std::cout << "Last 8 points of (" << sz << "): ";
  for (size_t i = sz - 8; i < sz; i++) { // print
    std::cout << v[i] << " ";
  }
  std::cout << std::endl;
}

#endif // PRE_UTILS_H
