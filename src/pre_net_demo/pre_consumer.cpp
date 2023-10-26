// @file pre-consumer.cpp - Example of Proxy Re-Encryption consumer client
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
//
// @section DESCRIPTION
// Example software for multiparty proxy-reencryption of an integer buffer using
// BFV rns scheme. Consumer Application
// uses lightweight ASIO connection library Copyright 2018 - 2020
// OneLoneCoder.com

// In this example we have two types of clients, producers and consumers.
// producers generate a CT and also send secret keys to the server.
// consumers send a public key to the server and get a recryption key back.
//
// to show correct operation, we allow producers to send a CT to the
// server and consumers to request this CT from the server to verify
// we allow consumers to send decrypted vecInt to server and consumers
// to request that from server for verification.  in a real system
// another service would provide that transfer mechanism.

#define PROFILE

#include <getopt.h>
//#include <chrono>

#include "openfhe.h"
#include "pre_utils.h"

#include "pre_client.h"

using namespace lbcrypto;
/**
 * main program
 * requires inputs
 */

enum class ConsumerStates : uint64_t {
  GetMessage,
  RequestCC,
  GenKeys,
  RequestReEncryptionKey,
  RequestCT,
  GenReencryption,
};

int main(int argc, char *argv[]) {
  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////
  int opt;
  std::string myName("");  // name of client to run
  uint32_t port(0);
  std::string hostName("");  // name of server host
  unsigned int id(0);

  while ((opt = getopt(argc, argv, "i:n:d:p:h")) != -1) {
    switch (opt) {
      case 'i':
        hostName = optarg;
        std::cout << "host name " << hostName << std::endl;
        break;
      case 'n':
        myName = optarg;
        std::cout << "starting consumer client named " << myName << std::endl;
        break;
      case 'd':
        id = atoi(optarg);
        std::cout << "consumer id " << id << std::endl;
        break;
      case 'p':
        port = atoi(optarg);
        std::cout << "host port " << port << std::endl;
        break;
      case 'h':
      default: /* '?' */
        std::cerr << "Usage: " << std::endl
                  << "arguments:" << std::endl
                  << "  -n name of the consumer client" << std::endl
                  << "  -d Identity of the consumer client" << std::endl
                  << "  -i IP or hostname of the server" << std::endl
                  << "  -p port of the server" << std::endl
                  << "  -h prints this message" << std::endl;
        std::exit(EXIT_FAILURE);
    }
  }
  PreConsumerClient c;
  // connect to the server
  PROFILELOG(myName << ": Connecing to server at " << hostName << ":" << port);
  c.Connect(hostName, port);
  if (c.IsConnected()) {
    PROFILELOG(myName << ": Connected to server");
    // if (c.Incoming().empty()) {
    //   PROFILELOG(myName << " Incomming empty");
    // }else {
    //   PROFILELOG(myName << " Incomming full");
    // }
  } else {
    PROFILELOG(myName << ": Not Connected to server. Exiting");
    exit(EXIT_FAILURE);
  }

  bool done = false;

  ConsumerStates state(ConsumerStates::GetMessage);  // simple state machine

  CC clientCC;
  KPair keyPair;
  PT pt;
  CT producerCT;  // CT recieved from server that we will reencrypt
  EvKey reencryptionKey;

  unsigned int ringsize(0U);
  unsigned int plaintextModulus(0U);
  vecInt vShorts;  // our vector of shorts (must be stored as int64_t)
  vecInt unpackedConsumer(0);
  TimeVar t;  // time benchmarking variable
  std::ofstream keyoutfile;

  OPENFHE_DEBUG_FLAG(false);  // turns on and off OPENFHE_DEBUG() statements
  while (!done) {
    if (c.IsConnected()) {
      // client executes a state
      switch (state) {  // sequence of states that producer executes
        case ConsumerStates::GetMessage:
          // client tests for a response from the server
          if (!c.Incoming().empty()) {
            auto msg = c.Incoming().pop_front().msg;

            switch (msg.header.id) {
              case PreMsgTypes::ServerAccept:
                // Server has responded to the Connect()
                OPENFHE_DEBUG("Server Accepted Connection");
                state = ConsumerStates::RequestCC;
                break;

              case PreMsgTypes::SendCC:
                PROFILELOG(myName << ": reading crypto context from server");
                TIC(t);
                clientCC = c.RecvCC(msg);
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ConsumerStates::GenKeys;
                break;

              case PreMsgTypes::SendReEncryptionKey:
                PROFILELOG(myName << ": reading reencryption key from server");
                TIC(t);
                reencryptionKey = c.RecvReencryptionKey(msg);
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ConsumerStates::RequestCT;
                break;

              case PreMsgTypes::NackReEncryptionKey:
                // Server has responded to a SendReEncryptionKey witg a NAC,
                // retry
                OPENFHE_DEBUG("Server NackReEncryptionKey");
                nap(1000);  // sleep for a second and retry.
                state = ConsumerStates::RequestReEncryptionKey;
                break;

              case PreMsgTypes::AckPublicKey:
                // Server has responded to a sendPublicKey
                OPENFHE_DEBUG("Server Accepted PublicKey");
                state = ConsumerStates::RequestReEncryptionKey;
                break;

              case PreMsgTypes::AckVecInt:
                // Server has responded to a sendVecInt
                OPENFHE_DEBUG("Server Accepted VecInt");
                state = ConsumerStates::GetMessage;
                break;

              case PreMsgTypes::SendCT:
                PROFILELOG(myName << ": reading CT from server");
                TIC(t);
                producerCT = c.RecvCT(msg);
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ConsumerStates::GenReencryption;
                break;

              case PreMsgTypes::NackCT:
                // Server has responded to a SendCT with a NAC, retry
                OPENFHE_DEBUG("Server NackCT");
                nap(1000);  // sleep for a second and retry.
                state = ConsumerStates::RequestCT;
                break;

              default:
                PROFILELOG(myName << ": received unhandled message from Server "
                                  << msg.header.id);
            }
          }  // end isEmpty -- could sleep here
          break;

        case ConsumerStates::RequestCC:  // first step
          TIC(t);
          PROFILELOG(myName << ": Requesting CC");
          c.RequestCC();  // request the CC from the server.
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          state = ConsumerStates::GetMessage;
          break;

        case ConsumerStates::GenKeys:
          // we have received the CC from the server
          // next step is to generate keys and send the private key to server
          PROFILELOG(myName << ": Generating keys");
          TIC(t);
          keyPair = clientCC->KeyGen();
          PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");

          if (!keyPair.good()) {
            std::cerr << myName << " Key generation failed!" << std::endl;
            std::exit(EXIT_FAILURE);
          }

          PROFILELOG(myName << ": Serializing and sending public key");
          TIC(t);
          c.SendPublicKey(keyPair);
          PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");

          ringsize = clientCC->GetRingDimension();
          plaintextModulus =
              clientCC->GetCryptoParameters()->GetPlaintextModulus();
          PROFILELOG(myName << ": plaintext modulus is :" << plaintextModulus);

          if (plaintextModulus < 256) {
            std::cerr << "error, code is designed for plaintextModulus>256, "
                         "modulus is "
                      << plaintextModulus << std::endl;
            std::exit(EXIT_FAILURE);
          }

          PROFILELOG(myName << ": can decrypt " << ringsize * 2
                            << " bytes of data");
          state = ConsumerStates::GetMessage;
          break;

        case ConsumerStates::RequestReEncryptionKey:
          TIC(t);
          PROFILELOG(myName << ": Requesting ReEncryptionKey");
          c.RequestReEncryptionKey(id);
          PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
          state = ConsumerStates::GetMessage;
          break;

        case ConsumerStates::RequestCT:
          TIC(t);
          PROFILELOG(myName << ": Requesting CT");
          c.RequestCT();  // request the CT from the server.
          PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
          state = ConsumerStates::GetMessage;
          break;
        case ConsumerStates::GenReencryption:
          PROFILELOG(myName << ": got CT");
          PROFILELOG(myName << ": reecrypt the data with reencryption key");
          TIC(t);

          PT consumerPT;
          if (reencryptionKey) {
            auto reencCT = clientCC->ReEncrypt(producerCT, reencryptionKey);
            PROFILELOG(myName
                       << ": decrypt the reencrypted result with my key");
            clientCC->Decrypt(keyPair.secretKey, reencCT, &consumerPT);
          } else {
            PROFILELOG(myName << ": decrypt the producer ct with my key");
            clientCC->Decrypt(keyPair.secretKey, producerCT, &consumerPT);
          }

          PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");

          // write the decrypted key to a file that will be used to decrypt an
          // encrypted image
          auto unpackedConsumer = consumerPT->GetStringValue();

          keyoutfile.open(GConf.consumer_aes_key + "_" + std::to_string(id) +
                          ".txt");
          if (!keyoutfile) {
            std::cout << "Unable to open key file";
            exit(1);  // terminate with error
          }
          keyoutfile << unpackedConsumer;
          keyoutfile.close();
          nap(1000);
          // consumer is done
          PROFILELOG(myName << ": Execution Completed.");
          done = true;
          break;
      }  // switch state

    }  // IsConnected()

  }  // while !done

  ////////////////////////////////////////////////////////////
  // Done
  ////////////////////////////////////////////////////////////

  PROFILELOG(myName << ": Execution Completed.");

  std::exit(EXIT_SUCCESS);  // successful return
}
