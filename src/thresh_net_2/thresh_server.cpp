// @file  threshold_server.cpp - Server to manage key exchanges for threshold
// example
//
// @author TPOC: contact@openfhe-crypto.org
//
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

// This will be as simpler server similar to pke_server.cpp

// it will handle two clients (ckks_a and ckks_b) and basically pass
//   key requests back and forth for shared key generation.

//   it will then pass Ciphertexts back and forth so the two clients can
//   demonstrate computation and decryption

// the goal is to demonstrate two clients engaging in a threshold key
// genration and then perform a joint computation and decryption,
// rather than a real-world practical server for such operations
#define PROFILE

#include <getopt.h>

#include "openfhe.h"
#include "thresh_server.h"
#include "thresh_utils.h"

using namespace lbcrypto;

/**
 * main program
 * requires inputs
 */

int main(int argc, char *argv[]) {
  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////
  int opt;
  uint32_t port(0);
  std::cout << "here debug";

  while ((opt = getopt(argc, argv, "p:h")) != -1) {
    switch (opt) {
    case 'p':
      port = atoi(optarg);
      std::cout << "host port " << port << std::endl;
      break;
    case 'h':
    default: /* '?' */
      std::cerr << "Usage: " << std::endl
                << "arguments:" << std::endl
                << "  -p port of the server" << std::endl
                << "  -h prints this message" << std::endl;
      std::exit(EXIT_FAILURE);
    }
  }

  // verify inputs
  if (port == 0) {
    std::cerr << "port must be specified " << std::endl;
    exit(EXIT_FAILURE);
  }

  PROFILELOG("SERVER: Initializing");

  ThreshServer server(port);
  server.Start();

  while (1) {
    server.Update(-1, true);
  }
  PROFILELOG("SERVER: Exiting");
  return (EXIT_SUCCESS);
}
