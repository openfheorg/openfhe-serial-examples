// @file thresh_client_a.cpp - Example of Threshold-fhe client Alice
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
// Example software for multiparty threshold fhe of an integer buffer using
// CKKS scheme. Client application.
// uses lightweight ASIO connection library Copyright 2018 - 2020
// OneLoneCoder.com

// In this example we have two clients, Alice and Bob.
// The clients interact via the server to generate the evaluation keys for
// multiplication and vector sum. After generating the evaluation keys, Bob
// sends ciphertexts to the server and Alice requests the ciphertexts from the
// server to compute on them. To show correct operation, we let the clients
// perform the final decryption and print the output. In a real system another
// service would provide that transfer mechanism.

#define PROFILE

#include <getopt.h>
//#include <chrono>

#include "openfhe.h"
#include "thresh_utils.h"

#include "thresh_client.h"

using namespace lbcrypto;
/**
 * main program
 * requires inputs
 */

enum class ClientAStates : uint64_t {
  GetMessage,
  RequestCC,
  GenPubKeys,
  SendRnd1evalMultKey,
  SendRnd1evalSumKeys,
  RequestRnd2SharedKey,
  RequestRnd2evalMultAB,
  RequestRnd2evalMultBAB,
  RequestRnd2evalSumKeysJoin,
  GenFinalSharedKeys,
  RequestCT1,
  RequestCT2,
  RequestCT3,
  DecryptLeadPartialAdd,
  DecryptLeadPartialMult,
  DecryptLeadPartialSum,
  RequestDecryptMainAdd,
  RequestDecryptMainMult,
  RequestDecryptMainSum,
  DecryptFusion,
};

int main(int argc, char *argv[]) {
  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////
  int opt;
  std::string myName(""); // name of client to run
  uint32_t port(0);
  std::string hostName(""); // name of server host

  while ((opt = getopt(argc, argv, "i:n:p:h")) != -1) {
    switch (opt) {
    case 'i':
      hostName = optarg;
      std::cout << "host name " << hostName << std::endl;
      break;
    case 'n':
      myName = optarg;
      std::cout << "starting client named " << myName << std::endl;
      break;
    case 'p':
      port = atoi(optarg);
      std::cout << "host port " << port << std::endl;
      break;
    case 'h':
    default: /* '?' */
      std::cerr << "Usage: " << std::endl
                << "arguments:" << std::endl
                << "  -n name of the client" << std::endl
                << "  -i IP or hostname of the server" << std::endl
                << "  -p port of the server" << std::endl
                << "  -h prints this message" << std::endl;
      std::exit(EXIT_FAILURE);
    }
  }
  ClientA c;
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

  // Client A (Alice) is a simple state machine, set initial state
  ClientAStates state(ClientAStates::GetMessage);

  usint batchSize = 16; // batch size for vector sum computation
  CC clientCC;          // cryptocontext of the client

  // Keys from Round1
  KPair keyPair; //(public, secret) keypair of the client
  EvKey evalMultKey;
  std::shared_ptr<std::map<usint, EvKey>> evalSumKeys;

  // Keys from Round 2
  PubKey Rnd2SharedKey;
  EvKey Rnd2EvalMultAB, Rnd2EvalMultBAB;
  std::shared_ptr<std::map<usint, EvKey>> Rnd2EvalSumKeysJoin;

  // Keys from Round 3
  EvKey evalMultAAB, evalMultFinal;

  // ciphertexts of plaintexts1,2,3 and evaluated ciphertexts of add, mult, sum
  // operations.
  CT ciphertext1, ciphertext2, ciphertext3;
  CT ciphertextAdd12, ciphertextAdd123;
  CT ciphertextMultTemp, ciphertextMult, ciphertextSum;

  // Partially decrypted ciphertexts from Client A (Alice)
  std::vector<CT> ciphertextPartialAdd1, ciphertextPartialMult1,
      ciphertextPartialSum1;

  // Partially decrypted ciphertexts from Client B (Bob)
  CT ciphertextPartialadd2, ciphertextPartialmult2, ciphertextPartialsum2;

  TimeVar t; // time benchmarking variable

  OPENFHE_DEBUG_FLAG(false); // Turns on and off OPENFHE_DEBUG() statements

  while (!done) {
    if (c.IsConnected()) {
      switch (state) { // sequence of states that the client executes
      case ClientAStates::GetMessage:
        // client tests for a response from the server
        if (!c.Incoming().empty()) {
          auto msg = c.Incoming().pop_front().msg;

          switch (msg.header.id) {
          case ThreshMsgTypes::ServerAccept:
            // Server has responded to the Connect()
            OPENFHE_DEBUG("Server Accepted Connection");
            state = ClientAStates::RequestCC;
            break;

          case ThreshMsgTypes::SendCC:
            PROFILELOG(myName << ": reading crypto context from server");
            TIC(t);
            clientCC = c.RecvCC(msg);
            PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
            state = ClientAStates::GenPubKeys;
            break;

          case ThreshMsgTypes::AckRnd1PubKey:
            PROFILELOG(myName << ": Acknowledged Round 1 Public key");
            state = ClientAStates::SendRnd1evalMultKey;
            break;

          case ThreshMsgTypes::AckRnd1evalMultKey:
            PROFILELOG(myName << ": Acknowledged Round 1 EvalMultKey");
            state = ClientAStates::SendRnd1evalSumKeys;
            break;
          case ThreshMsgTypes::AckRnd1evalSumKeys:
            PROFILELOG(myName << ": Acknowledged Round 1 EvalSumKeys");
            nap(100); // sleep until Round 2 key generation is done.
            state = ClientAStates::RequestRnd2SharedKey;
            break;

          case ThreshMsgTypes::SendRnd2SharedKey:
            PROFILELOG(myName << ": Reading Round 2 Shared key");
            TIC(t);
            Rnd2SharedKey = c.RecvRnd2SharedKey(msg);
            PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
            state = ClientAStates::RequestRnd2evalMultAB;
            break;

          case ThreshMsgTypes::SendRnd2EvalMultAB:
            PROFILELOG(myName << ": Reading Round 2 EvalMultAB");
            TIC(t);
            Rnd2EvalMultAB = c.RecvRnd2evalMultAB(msg);
            PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
            state = ClientAStates::RequestRnd2evalMultBAB;
            break;

          case ThreshMsgTypes::SendRnd2EvalMultBAB:
            PROFILELOG(myName << ": Reading Round 2 EvalMultBAB");
            TIC(t);
            Rnd2EvalMultBAB = c.RecvRnd2evalMultBAB(msg);
            PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
            state = ClientAStates::RequestRnd2evalSumKeysJoin;
            break;

          case ThreshMsgTypes::SendRnd2EvalSumKeysJoin:
            PROFILELOG(myName << ": Reading Round 2 EvalSumKeysJoin");
            TIC(t);
            Rnd2EvalSumKeysJoin = c.RecvRnd2evalSumKeysJoin(msg);
            PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
            state = ClientAStates::GenFinalSharedKeys;
            break;

          case ThreshMsgTypes::AckRnd3EvalMultFinal:
            PROFILELOG(myName << ": Acknowledged Round 3 EvalMultFinal");
            nap(1000);
            state = ClientAStates::RequestCT1;
            break;

          case ThreshMsgTypes::SendCT1:
            ciphertext1 = c.RecvCT(msg);
            PROFILELOG(myName << ": reading ciphertext1");
            nap(1000);
            state = ClientAStates::RequestCT2;
            break;
          case ThreshMsgTypes::SendCT2:
            PROFILELOG(myName << ": reading ciphertext2");
            ciphertext2 = c.RecvCT(msg);
            nap(1000);
            state = ClientAStates::RequestCT3;
            break;

          case ThreshMsgTypes::SendCT3:
            PROFILELOG(myName << ": reading ciphertext3");
            ciphertext3 = c.RecvCT(msg);
            state = ClientAStates::DecryptLeadPartialAdd;
            break;

          case ThreshMsgTypes::AckPartialLeadAdd:
            PROFILELOG(myName
                       << ": acknowledging Partially decrypted Lead add CT");
            state = ClientAStates::DecryptLeadPartialMult;
            break;

          case ThreshMsgTypes::AckPartialLeadMult:
            PROFILELOG(myName
                       << ": acknowledging Partially decrypted Lead mult CT");
            state = ClientAStates::DecryptLeadPartialSum;
            break;

          case ThreshMsgTypes::AckPartialLeadSum:
            PROFILELOG(myName
                       << ": acknowledging Partially decrypted Lead sum CT");
            state = ClientAStates::RequestDecryptMainAdd;
            break;

          case ThreshMsgTypes::SendDecryptMainAdd:
            PROFILELOG(myName << ": reading partial decrypted add "
                                 "ciphertext from client B");
            TIC(t);
            ciphertextPartialadd2 = c.RecvCT(msg);
            PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
            state = ClientAStates::RequestDecryptMainMult;
            break;

          case ThreshMsgTypes::SendDecryptMainMult:
            PROFILELOG(myName << ": reading partial decrypted mult "
                                 "ciphertext from client B");
            TIC(t);
            ciphertextPartialmult2 = c.RecvCT(msg);
            PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
            state = ClientAStates::RequestDecryptMainSum;
            break;

          case ThreshMsgTypes::SendDecryptMainSum:
            PROFILELOG(myName << ": reading partial decrypted sum "
                                 "ciphertext from client B");
            TIC(t);
            ciphertextPartialsum2 = c.RecvCT(msg);
            PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
            state = ClientAStates::DecryptFusion;
            break;

          case ThreshMsgTypes::NackRnd2SharedKey:
            // Server has responded to a SendRnd2PubKey with a NAC, retry
            OPENFHE_DEBUG("Server NackRnd2SharedKey");
            nap(1000); // sleep for a second and retry.
            state = ClientAStates::RequestRnd2SharedKey;
            break;

          case ThreshMsgTypes::NackRnd2EvalMultAB:
            // Server has responded to a SendRnd2EvalMultAB with a NAC,
            // retry
            OPENFHE_DEBUG("Server NackRnd2EvalMultAB");
            nap(1000); // sleep for a second and retry.
            state = ClientAStates::RequestRnd2evalMultAB;
            break;

          case ThreshMsgTypes::NackRnd2EvalMultBAB:
            // Server has responded to a SendRnd2EvalMultBAB with a NAC,
            // retry
            OPENFHE_DEBUG("Server NackRnd2EvalMultBAB");
            nap(1000); // sleep for a second and retry.
            state = ClientAStates::RequestRnd2evalMultBAB;
            break;

          case ThreshMsgTypes::NackRnd2EvalSumKeysJoin:
            // Server has responded to a SendRnd2EvalSumKeysJoin with a NAC,
            // retry
            OPENFHE_DEBUG("Server NackRnd2EvalSumKeysJoin");
            nap(1000); // sleep for a second and retry.
            state = ClientAStates::RequestRnd2evalSumKeysJoin;
            break;

          case ThreshMsgTypes::NackCT1:
            PROFILELOG("Server NackCT1");
            nap(1000);
            state = ClientAStates::RequestCT1;
            break;

          case ThreshMsgTypes::NackCT2:
            PROFILELOG("Server NackCT2");
            nap(1000);
            state = ClientAStates::RequestCT2;
            break;

          case ThreshMsgTypes::NackCT3:
            PROFILELOG("Server NackCT3");
            nap(1000);
            state = ClientAStates::RequestCT3;
            break;

          case ThreshMsgTypes::NackPartialLeadAdd:
            PROFILELOG("Server NackPartialLeadAdd");
            nap(1000);
            state = ClientAStates::DecryptLeadPartialAdd;
            break;

          case ThreshMsgTypes::NackPartialLeadMult:
            PROFILELOG("Server NackPartialLeadMult");
            nap(1000);
            state = ClientAStates::DecryptLeadPartialMult;
            break;

          case ThreshMsgTypes::NackPartialLeadSum:
            PROFILELOG("Server NackPartialLeadSum");
            nap(1000);
            state = ClientAStates::DecryptLeadPartialSum;
            break;

          case ThreshMsgTypes::NackPartialMainAdd:
            PROFILELOG("Server NackPartialMainAdd");
            nap(1000);
            state = ClientAStates::RequestDecryptMainAdd;
            break;

          case ThreshMsgTypes::NackPartialMainMult:
            PROFILELOG("Server NackPartialMainMult");
            nap(1000);
            state = ClientAStates::RequestDecryptMainMult;
            break;

          case ThreshMsgTypes::NackPartialMainSum:
            PROFILELOG("Server NackPartialMainSum");
            nap(1000);
            state = ClientAStates::RequestDecryptMainSum;
            break;

          default:
            PROFILELOG(myName << ": received unhandled message from Server "
                              << msg.header.id);
          }
        } // end isEmpty -- could sleep here
        break;

      case ClientAStates::RequestCC: // first step
        TIC(t);
        PROFILELOG(myName << ": Requesting CC");
        c.RequestCC(); // request the CC from the server.
        PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::GenPubKeys: // if have received the CC from the
                                      // server
        // then generate keys and send the round 1 keys to server
        PROFILELOG(myName << ": Generating Round 1 keys");
        TIC(t);
        keyPair = clientCC->KeyGen();

        // Generate evalmult key part for A
        evalMultKey =
            clientCC->KeySwitchGen(keyPair.secretKey, keyPair.secretKey);

        // Generate evalsum key part for A
        clientCC->EvalSumKeyGen(keyPair.secretKey);
        evalSumKeys = std::make_shared<std::map<usint, EvKey>>(
            clientCC->GetEvalSumKeyMap(keyPair.secretKey->GetKeyTag()));

        PROFILELOG(myName << ": Serializing and sending Round 1 Public key");
        c.SendRnd1PubKey(keyPair);
        PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;

        if (!keyPair.good()) {
          std::cerr << myName << "Round 1 Key generation failed!" << std::endl;
          std::exit(EXIT_FAILURE);
        }
        break;

      case ClientAStates::SendRnd1evalMultKey:
        PROFILELOG(myName << ": Serializing and sending Round 1 EvalMult key");
        TIC(t);
        c.SendRnd1evalMultKey(evalMultKey);
        PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::SendRnd1evalSumKeys:
        PROFILELOG(myName << ": Serializing and sending Round 1 EvalSumKeys");
        TIC(t);
        c.SendRnd1evalSumKeys(evalSumKeys);
        PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::RequestRnd2SharedKey:
        TIC(t);
        PROFILELOG(myName << ": Requesting Round 2 public key");
        c.RequestRnd2SharedKey(); // request the round 2 public key from Bob.
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::RequestRnd2evalMultAB:
        TIC(t);
        PROFILELOG(myName << ": Requesting Round 2 EvalMultAB");
        c.RequestRnd2evalMultAB(); // request the round 2 EvalMultAB from
                                   // Bob.
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::RequestRnd2evalMultBAB:
        TIC(t);
        PROFILELOG(myName << ": Requesting Round 2 EvalMultAB");
        c.RequestRnd2evalMultBAB(); // request the round 2 EvalMultBAB from
                                    // Bob.
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::RequestRnd2evalSumKeysJoin:
        TIC(t);
        PROFILELOG(myName << ": Requesting Round 2 EvalSumKeysJoin");
        c.RequestRnd2evalSumKeysJoin(); // request the round 2
                                        // EvalSumKeysJoin from Bob.
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::GenFinalSharedKeys: // if have received the Round 2
                                              // keys from the server
        // then generate keys and send the evalmultfinal key to server
        PROFILELOG(myName << ": Generating Round 3 keys");

        TIC(t);

        std::cout << "Round 3 (party A) started." << std::endl;

        evalMultAAB = clientCC->MultiMultEvalKey(
            keyPair.secretKey, Rnd2EvalMultAB, Rnd2SharedKey->GetKeyTag());

        evalMultFinal = clientCC->MultiAddEvalMultKeys(
            evalMultAAB, Rnd2EvalMultBAB, Rnd2EvalMultAB->GetKeyTag());

        clientCC->InsertEvalMultKey({evalMultFinal});

        std::cout << "Round 3 of key generation completed." << std::endl;

        PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");

        if (!evalMultFinal) {
          std::cerr << myName << "Round 3 Key generation failed!" << std::endl;
          std::exit(EXIT_FAILURE);
        }

        PROFILELOG(myName << ": Serializing and sending Round 3 keys");
        TIC(t);
        c.SendRnd3EvalMultFinal(evalMultFinal);
        PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;

        break;

      case ClientAStates::RequestCT1:
        TIC(t);
        PROFILELOG(myName << ": Requesting ciphertext1");
        c.RequestCT1(); // request ciphertext1 from Bob.
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::RequestCT2:
        TIC(t);
        PROFILELOG(myName << ": Requesting ciphertext2");
        c.RequestCT2(); // request ciphertext2 from Bob.
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::RequestCT3: // first step
        TIC(t);
        PROFILELOG(myName << ": Requesting ciphertext3");
        c.RequestCT3(); // request the ciphertext3 from Bob.
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::DecryptLeadPartialAdd:
        PROFILELOG(myName << ": Partial decryption of eval add ciphertext");
        TIC(t);

        ciphertextAdd12 = clientCC->EvalAdd(ciphertext1, ciphertext2);
        ciphertextAdd123 = clientCC->EvalAdd(ciphertextAdd12, ciphertext3);

        ciphertextPartialAdd1 = clientCC->MultipartyDecryptLead(
            {ciphertextAdd123}, keyPair.secretKey);
        c.SendCTPartialAdd(ciphertextPartialAdd1[0]);
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::DecryptLeadPartialMult:
        PROFILELOG(myName << ": Partial decryption of eval mult ciphertext");
        TIC(t);

        ciphertextMultTemp = clientCC->EvalMult(ciphertext1, ciphertext3);
        ciphertextMult = clientCC->ModReduce(ciphertextMultTemp);

        ciphertextPartialMult1 = clientCC->MultipartyDecryptLead(
            {ciphertextMult}, keyPair.secretKey);
        c.SendCTPartialMult(ciphertextPartialMult1[0]);
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::DecryptLeadPartialSum:
        PROFILELOG(myName << ": Partial decryption of eval sum ciphertext");
        TIC(t);
        clientCC->InsertEvalSumKey(Rnd2EvalSumKeysJoin);
        // compute ciphertextSum[0] =
        // ciphertext3[0]+...+ciphertext[batchsize-1] compute ciphertextSum[1]
        // = ciphertext3[1]+...+ciphertext3[batchsize] and so on.
        ciphertextSum = clientCC->EvalSum(ciphertext3, batchSize);

        ciphertextPartialSum1 =
            clientCC->MultipartyDecryptLead({ciphertextSum}, keyPair.secretKey);
        c.SendCTPartialSum(ciphertextPartialSum1[0]);
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::RequestDecryptMainAdd:
        PROFILELOG(myName << ": Request partial decryption main add");
        TIC(t);
        c.RequestDecryptMainAdd();
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::RequestDecryptMainMult:
        PROFILELOG(myName << ": Request partial decryption main mult");
        TIC(t);
        c.RequestDecryptMainMult();
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::RequestDecryptMainSum:
        PROFILELOG(myName << ": Request partial decryption main sum");
        TIC(t);
        c.RequestDecryptMainSum();
        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
        state = ClientAStates::GetMessage;
        break;

      case ClientAStates::DecryptFusion:
        PROFILELOG(myName << ": Final decryption fusion of add, mult, sum");

        PT plaintextMultipartyAdd, plaintextMultipartyMult,
            plaintextMultipartySum;

        std::vector<CT> Partial_Add;
        Partial_Add.push_back(ciphertextPartialAdd1[0]);
        Partial_Add.push_back(ciphertextPartialadd2);
        clientCC->MultipartyDecryptFusion(Partial_Add, &plaintextMultipartyAdd);

        plaintextMultipartyAdd->SetLength(12); // ptlength;

        std::cout << "\n Resulting Fused Plaintext Add: \n";
        std::cout << plaintextMultipartyAdd;

        std::cout << "\n";

        // final decryption for multiplication
        std::vector<Ciphertext<DCRTPoly>> Partial_Mult;
        Partial_Mult.push_back(ciphertextPartialMult1[0]);
        Partial_Mult.push_back(ciphertextPartialmult2);
        clientCC->MultipartyDecryptFusion(Partial_Mult,
                                          &plaintextMultipartyMult);

        plaintextMultipartyMult->SetLength(12); // ptlength;

        std::cout << "\n Resulting Fused Plaintext Mult: \n";
        std::cout << plaintextMultipartyMult;

        std::cout << "\n";

        // decrypt fusion for vector sum
        std::vector<CT> Partial_Sum;
        Partial_Sum.push_back(ciphertextPartialSum1[0]);
        Partial_Sum.push_back(ciphertextPartialsum2);
        clientCC->MultipartyDecryptFusion(Partial_Sum, &plaintextMultipartySum);

        plaintextMultipartySum->SetLength(12); // ptlength;

        std::cout << "\n Resulting Fused Plaintext Sum: \n";
        std::cout << plaintextMultipartySum;

        std::cout << "\n";

        PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");

        done = true;
        break;

      } // switch state

    } // IsConnected()

    nap(100); // take a 100 msec pause

  } // while !done

  ////////////////////////////////////////////////////////////
  // Done
  ////////////////////////////////////////////////////////////

  PROFILELOG(myName << ": Execution Completed.");
  c.DisconnectClient();
  nap(1000);
  std::exit(EXIT_SUCCESS); // successful return
}
