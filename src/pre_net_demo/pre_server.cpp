// @file pre-server.cpp - Example of a Proxy Re-Encryption server
// @author: Ian Quah, David Cousins
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

// @section DESCRIPTION
// Example software for multiparty proxy-reencryption of an integer buffer using
// BFV rns scheme. Server application.
// uses lightweight ASIO connection library Copyright 2018 - 2020
// OneLoneCoder.com

#define PROFILE

#include <getopt.h>

#include "openfhe.h"
#include "pre_utils.h"
#include "pre_server.h"

using namespace lbcrypto;

/**
 * main program
 * requires inputs
 */

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

  PreServer server(port);
  server.Start();

  while (1) {
    server.Update(-1, true);
  }
  PROFILELOG("SERVER: Exiting");
  return (EXIT_SUCCESS);
}
