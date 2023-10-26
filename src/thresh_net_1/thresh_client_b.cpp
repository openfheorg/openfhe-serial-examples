// @file thresh_client_b.cpp - Example of threshold fhe client Bob
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
// CKKS scheme. Client Application
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

enum class ClientBStates : uint64_t {
  GetMessage,
  RequestCC,
  RequestRnd1PubKey,
  RequestRnd1evalMultKey,
  RequestRnd1evalSumKeys,
  GenRnd2Keys,
  SendRnd2evalMultAB,
  SendRnd2evalMultBAB,
  SendRnd2evalSumKeysJoin,
  RequestRnd3evalMultFinal,
  GenCT1,
  GenCT2,
  GenCT3,
  DecryptMainPartialAdd,
  DecryptMainPartialMult,
  DecryptMainPartialSum,
  RequestDecryptLeadAdd,
  RequestDecryptLeadMult,
  RequestDecryptLeadSum,
  DecryptFusion,
};

int main(int argc, char *argv[]) {
  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////
  int opt;
  std::string myName("");  // name of client to run
  uint32_t port(0);
  std::string hostName("");  // name of server host

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
  ClientB c;
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

  ClientBStates state(ClientBStates::GetMessage);  // simple state machine

  usint batchSize = 16;
  CC clientCC;

  // received keys from Round1
  PubKey Rnd1Pubkey;
  EvKey Rnd1evalMultKey;
  std::shared_ptr<std::map<usint, EvKey>> Rnd1evalSumKeys;

  // keys generated in Round2
  KPair keyPair;
  EvKey evalMultKey2, evalMultAB, evalMultBAB;
  std::shared_ptr<std::map<usint, EvKey>> evalSumKeysJoin, evalSumKeysB;

  // received keys from Round3
  EvKey Rnd3evalMultFinal;

  TimeVar t;  // time benchmarking variable

  // example plaintext vectors
  std::vector<double> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
  std::vector<double> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
  std::vector<double> vectorOfInts3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

  // plaintext variables for packing the vectorints
  Plaintext plaintext1, plaintext2, plaintext3;

  // ciphertexts of plaintexts1,2,3 and evaluated ciphertexts of add, mult, sum
  // operations.
  CT ciphertext1, ciphertext2, ciphertext3;
  // CT AddCT, MultCT;
  CT ciphertextAdd12, ciphertextAdd123;
  CT ciphertextMultTemp, ciphertextMult, ciphertextSum;

  // Partially decrypted ciphertexts from Client A (Alice)
  CT ciphertextPartialadd1, ciphertextPartialmult1, ciphertextPartialsum1;

  // Partially decrypted ciphertexts from Client B (Bob)
  std::vector<CT> ciphertextPartialAdd2, ciphertextPartialMult2,
      ciphertextPartialSum2;

  OPENFHE_DEBUG_FLAG(false);  // turns on and off OPENFHE_DEBUG() statements
  while (!done) {
    if (c.IsConnected()) {
      // client executes a state
      switch (state) {  // sequence of states that the client executes
        case ClientBStates::GetMessage:
          // client tests for a response from the server
          if (!c.Incoming().empty()) {
            auto msg = c.Incoming().pop_front().msg;

            switch (msg.header.id) {
              case ThreshMsgTypes::ServerAccept:
                // Server has responded to the Connect()
                OPENFHE_DEBUG("Server Accepted Connection");
                state = ClientBStates::RequestCC;
                break;

              case ThreshMsgTypes::SendCC:
                PROFILELOG(myName << ": reading crypto context from server");
                TIC(t);
                clientCC = c.RecvCC(msg);
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ClientBStates::RequestRnd1PubKey;
                break;

              case ThreshMsgTypes::SendRnd1PubKey:
                PROFILELOG(myName << ": reading Round 1 public key");
                TIC(t);
                Rnd1Pubkey = c.RecvRnd1PubKey(msg);
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ClientBStates::RequestRnd1evalMultKey;
                break;

              case ThreshMsgTypes::SendRnd1evalMultKey:
                PROFILELOG(myName << ": reading Round 1 eval mult key");
                TIC(t);
                Rnd1evalMultKey = c.RecvRnd1evalMultKey(msg);
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ClientBStates::RequestRnd1evalSumKeys;
                break;

              case ThreshMsgTypes::SendRnd1evalSumKeys:
                PROFILELOG(myName << ": reading Round 1 eval sum key");
                TIC(t);
                Rnd1evalSumKeys = c.RecvRnd1evalSumKeys(msg);
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ClientBStates::GenRnd2Keys;
                break;

              case ThreshMsgTypes::NackRnd1PubKey:
                // Server has responded to a SendRnd1PubKey with a NAC, retry
                OPENFHE_DEBUG("Server NackRnd1PubKey");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::RequestRnd1PubKey;
                break;

              case ThreshMsgTypes::NackRnd1evalMultKey:
                // Server has responded to a SendRnd1evalMultKey with a NAC,
                // retry
                OPENFHE_DEBUG("Server NackRnd1evalMultKey");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::RequestRnd1evalMultKey;
                break;

              case ThreshMsgTypes::NackRnd1evalSumKeys:
                // Server has responded to a SendRnd1evalSumKeys with a NAC,
                // retry
                OPENFHE_DEBUG("Server NackRnd1evalSumKeys");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::RequestRnd1evalSumKeys;
                break;

              case ThreshMsgTypes::AckRnd2SharedKey:
                PROFILELOG(myName << ": Acknowledged Round 2 Public key");
                state = ClientBStates::SendRnd2evalMultAB;
                break;

              case ThreshMsgTypes::AckRnd2EvalMultAB:
                PROFILELOG(myName << ": Acknowledged Round 2 EvalMultAB");
                state = ClientBStates::SendRnd2evalMultBAB;
                break;

              case ThreshMsgTypes::AckRnd2EvalMultBAB:
                PROFILELOG(myName << ": Acknowledged Round 2 EvalMultBAB");
                state = ClientBStates::SendRnd2evalSumKeysJoin;
                break;

              case ThreshMsgTypes::AckRnd2EvalSumKeysJoin:
                PROFILELOG(myName << ": Acknowledged Round 2 EvalSumKeysJoin");
                state = ClientBStates::RequestRnd3evalMultFinal;
                break;

              case ThreshMsgTypes::SendRnd3EvalMultFinal:
                PROFILELOG(myName << ": reading Round 3 eval mult final key");
                TIC(t);
                Rnd3evalMultFinal = c.RecvRnd3evalMultFinal(msg);
                clientCC->InsertEvalMultKey({Rnd3evalMultFinal});
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ClientBStates::GenCT1;
                break;

              case ThreshMsgTypes::AckCT1:
                PROFILELOG(myName << ": Acknowledged Ciphertext 1");
                state = ClientBStates::GenCT2;
                break;

              case ThreshMsgTypes::AckCT2:
                PROFILELOG(myName << ": Acknowledged Ciphertext 2");
                state = ClientBStates::GenCT3;
                break;

              case ThreshMsgTypes::AckCT3:
                PROFILELOG(myName << ": Acknowledged Ciphertext 3");
                nap(500);
                state = ClientBStates::DecryptMainPartialAdd;
                break;

              case ThreshMsgTypes::AckPartialMainAdd:
                PROFILELOG(
                    myName
                    << ": acknowledging partially decrypted main add CT");
                nap(200);
                state = ClientBStates::DecryptMainPartialMult;
                break;

              case ThreshMsgTypes::AckPartialMainMult:
                PROFILELOG(
                    myName
                    << ": acknowledging partially decrypted main mult CT");
                nap(200);
                state = ClientBStates::DecryptMainPartialSum;
                break;

              case ThreshMsgTypes::AckPartialMainSum:
                PROFILELOG(
                    myName
                    << ": acknowledging partially decrypted main sum CT");
                state = ClientBStates::RequestDecryptLeadAdd;
                break;

              case ThreshMsgTypes::SendDecryptLeadAdd:
                PROFILELOG(myName << ": reading partial decrypted ciphertext "
                                     "add from client A");
                TIC(t);
                ciphertextPartialadd1 = c.RecvCT(msg);
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ClientBStates::RequestDecryptLeadMult;
                break;

              case ThreshMsgTypes::SendDecryptLeadMult:
                PROFILELOG(myName << ": reading partial decrypted ciphertext "
                                     "mult from client B");
                TIC(t);
                ciphertextPartialmult1 = c.RecvCT(msg);
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ClientBStates::RequestDecryptLeadSum;
                break;

              case ThreshMsgTypes::SendDecryptLeadSum:
                PROFILELOG(myName << ": reading partial decrypted ciphertext "
                                     "sum from client A");
                TIC(t);
                ciphertextPartialsum1 = c.RecvCT(msg);
                PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
                state = ClientBStates::DecryptFusion;
                break;

              case ThreshMsgTypes::NackCT1:
                PROFILELOG("Server NackCT1");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::GenCT1;
                break;

              case ThreshMsgTypes::NackCT2:
                PROFILELOG("Server NackCT2");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::GenCT2;
                break;

              case ThreshMsgTypes::NackCT3:
                PROFILELOG("Server NackCT3");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::GenCT3;
                break;

              case ThreshMsgTypes::NackRnd3evalMultFinal:
                // Server has responded to a SendRnd3EvalMultFinal with a NAC,
                // retry
                OPENFHE_DEBUG("Server NackRnd3EvalMultFinal");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::RequestRnd3evalMultFinal;
                break;

              case ThreshMsgTypes::NackPartialLeadAdd:
                PROFILELOG("Server NackPartialLeadAdd");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::RequestDecryptLeadAdd;
                break;

              case ThreshMsgTypes::NackPartialLeadMult:
                PROFILELOG("Server NackPartialLeadMult");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::RequestDecryptLeadMult;
                break;

              case ThreshMsgTypes::NackPartialLeadSum:
                PROFILELOG("Server NackPartialLeadSum");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::RequestDecryptLeadSum;
                break;

              case ThreshMsgTypes::NackPartialMainAdd:
                PROFILELOG("Server NackPartialMainAdd");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::DecryptMainPartialAdd;
                break;

              case ThreshMsgTypes::NackPartialMainMult:
                PROFILELOG("Server NackPartialMainMult");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::DecryptMainPartialMult;
                break;

              case ThreshMsgTypes::NackPartialMainSum:
                PROFILELOG("Server NackPartialMainSum");
                nap(1000);  // sleep for a second and retry.
                state = ClientBStates::DecryptMainPartialSum;
                break;

              default:
                PROFILELOG(myName << ": received unhandled message from Server "
                                  << msg.header.id);
            }
          }  // end isEmpty -- could sleep here
          break;

        case ClientBStates::RequestCC:  // first step
          TIC(t);
          PROFILELOG(myName << ": Requesting CC");
          c.RequestCC();  // request the CC from the server.
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::RequestRnd1PubKey:
          TIC(t);
          PROFILELOG(myName << ": Requesting Round 1 public key");
          c.RequestRnd1PubKey();  // request the round 1 public key from Alice.
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::RequestRnd1evalMultKey:
          TIC(t);
          PROFILELOG(myName << ": Requesting Round 1 EvalMultKey");
          c.RequestRnd1evalMultKey();  // request the Round 1 EvalMultKey from
                                       // Alice.
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::RequestRnd1evalSumKeys:
          TIC(t);
          PROFILELOG(myName << ": Requesting Round 1 EvalSumKeys");
          c.RequestRnd1evalSumKeys();  // request the Round 1 EvalSumKeys from
                                       // Alice.
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::GenRnd2Keys:
          PROFILELOG("Round 2 " << myName << " started.");
          TIC(t);
          std::cout << "Joint public key for (s_a + s_b) is generated..."
                    << std::endl;
          keyPair = clientCC->MultipartyKeyGen(Rnd1Pubkey);

          evalMultKey2 = clientCC->MultiKeySwitchGen(
              keyPair.secretKey, keyPair.secretKey, Rnd1evalMultKey);

          evalMultAB = clientCC->MultiAddEvalKeys(
              Rnd1evalMultKey, evalMultKey2, keyPair.publicKey->GetKeyTag());

          evalMultBAB = clientCC->MultiMultEvalKey(
              keyPair.secretKey, evalMultAB, keyPair.publicKey->GetKeyTag());

          c.SendRnd2SharedKey(keyPair);

          evalSumKeysB =
              clientCC->MultiEvalSumKeyGen(keyPair.secretKey, Rnd1evalSumKeys,
                                           keyPair.publicKey->GetKeyTag());

          evalSumKeysJoin = clientCC->MultiAddEvalSumKeys(
              Rnd1evalSumKeys, evalSumKeysB, keyPair.publicKey->GetKeyTag());

          PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");

          state = ClientBStates::GetMessage;
          if (!keyPair.good()) {
            std::cerr << myName << "Round 2 Key generation failed!"
                      << std::endl;
            std::exit(EXIT_FAILURE);
          }
          break;

        case ClientBStates::SendRnd2evalMultAB:
          PROFILELOG(myName << ": Serializing and sending Round 2 EvalMultAB");
          TIC(t);
          c.SendRnd2EvalMultAB(evalMultAB);
          PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::SendRnd2evalMultBAB:
          PROFILELOG(myName << ": Serializing and sending Round 2 EvalMultBAB");
          TIC(t);
          c.SendRnd2EvalMultBAB(evalMultBAB);
          PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::SendRnd2evalSumKeysJoin:
          PROFILELOG(myName
                     << ": Serializing and sending Round 2 EvalSumKeysJoin");
          TIC(t);
          c.SendRnd2EvalSumKeysJoin(evalSumKeysJoin);
          PROFILELOG(myName << ": elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::RequestRnd3evalMultFinal:
          PROFILELOG(myName << ": Requesting Round 3 final shared Mult key");
          TIC(t);
          c.RequestRnd3evalMultFinal();  // request the Round 3 EvalMultFinal
                                         // from Alice.
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::GenCT1:
          PROFILELOG(myName << ": Generate ciphertext 1");
          plaintext1 = clientCC->MakeCKKSPackedPlaintext(vectorOfInts1);
          ciphertext1 = clientCC->Encrypt(keyPair.publicKey, plaintext1);

          c.SendCT1(ciphertext1, 0);
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::GenCT2:
          PROFILELOG(myName << ": Generate ciphertext 2");

          plaintext2 = clientCC->MakeCKKSPackedPlaintext(vectorOfInts2);
          ciphertext2 = clientCC->Encrypt(keyPair.publicKey, plaintext2);

          c.SendCT2(ciphertext2, 1);
          state = ClientBStates::GetMessage;

          break;

        case ClientBStates::GenCT3:
          PROFILELOG(myName << ": Generate ciphertext 3");

          plaintext3 = clientCC->MakeCKKSPackedPlaintext(vectorOfInts3);
          ciphertext3 = clientCC->Encrypt(keyPair.publicKey, plaintext3);

          c.SendCT3(ciphertext3, 2);
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::DecryptMainPartialAdd:
          PROFILELOG(myName << ": Partial decryption of eval add ciphertext");
          TIC(t);

          // compute ciphertext123 = ciphertext1+ciphertext2+ciphertext3
          ciphertextAdd12 = clientCC->EvalAdd(ciphertext1, ciphertext2);
          ciphertextAdd123 = clientCC->EvalAdd(ciphertextAdd12, ciphertext3);

          ciphertextPartialAdd2 = clientCC->MultipartyDecryptMain({ciphertextAdd123},
																  keyPair.secretKey);

          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          c.SendCTPartialAdd(ciphertextPartialAdd2[0]);
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::DecryptMainPartialMult:
          PROFILELOG(myName << ": Partial decryption of eval mult ciphertext");
          TIC(t);

          // compute ciphertextMult = ciphertext1*ciphertext3
          ciphertextMultTemp = clientCC->EvalMult(ciphertext1, ciphertext3);
          ciphertextMult = clientCC->ModReduce(ciphertextMultTemp);

          ciphertextPartialMult2 = clientCC->MultipartyDecryptMain({ciphertextMult},
																   keyPair.secretKey);
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          c.SendCTPartialMult(ciphertextPartialMult2[0]);
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::DecryptMainPartialSum:
          PROFILELOG(myName << ": Partial decryption of eval sum ciphertext");
          TIC(t);

          // compute ciphertextSum[0] =
          // ciphertext3[0]+...+ciphertext[batchsize-1] compute ciphertextSum[1]
          // = ciphertext3[1]+...+ciphertext3[batchsize] and so on.
          clientCC->InsertEvalSumKey(evalSumKeysJoin);
          ciphertextSum = clientCC->EvalSum(ciphertext3, batchSize);

          ciphertextPartialSum2
			= clientCC->MultipartyDecryptMain({ciphertextSum}, keyPair.secretKey);
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          c.SendCTPartialSum(ciphertextPartialSum2[0]);
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::RequestDecryptLeadAdd:
          PROFILELOG(myName
                     << ": Requesting partial decrypt lead add ciphertext");
          TIC(t);

          c.RequestDecryptLeadAdd();
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::RequestDecryptLeadMult:
          PROFILELOG(myName
                     << ": Requesting partial decrypt lead mult ciphertext");
          TIC(t);
          c.RequestDecryptLeadMult();
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::RequestDecryptLeadSum:
          PROFILELOG(myName
                     << ": Requesting partial decrypt lead sum ciphertext");
          TIC(t);
          c.RequestDecryptLeadSum();
          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          state = ClientBStates::GetMessage;
          break;

        case ClientBStates::DecryptFusion:
          PROFILELOG(myName << ": perform decrypt fusion");
          TIC(t);

          PT plaintextMultipartyAdd, plaintextMultipartyMult,
              plaintextMultipartySum;

          // final decryption for add
          std::vector<CT> Partial_Add;
          Partial_Add.push_back(ciphertextPartialadd1);
          Partial_Add.push_back(ciphertextPartialAdd2[0]);
          clientCC->MultipartyDecryptFusion(Partial_Add,
                                            &plaintextMultipartyAdd);

          plaintextMultipartyAdd->SetLength(
              plaintext1->GetLength());  // ptlength;

          std::cout << "\n Resulting Fused Plaintext Add: \n";
          std::cout << plaintextMultipartyAdd;

          std::cout << "\n";

          // final decryption for multiplication
          std::vector<Ciphertext<DCRTPoly>> Partial_Mult;
          Partial_Mult.push_back(ciphertextPartialmult1);
          Partial_Mult.push_back(ciphertextPartialMult2[0]);
          clientCC->MultipartyDecryptFusion(Partial_Mult,
                                            &plaintextMultipartyMult);

          plaintextMultipartyMult->SetLength(
              plaintext1->GetLength());  // ptlength;

          std::cout << "\n Resulting Fused Plaintext Mult: \n";
          std::cout << plaintextMultipartyMult;

          std::cout << "\n";

          // final decryption for sum
          std::vector<Ciphertext<DCRTPoly>> Partial_Sum;
          Partial_Sum.push_back(ciphertextPartialsum1);
          Partial_Sum.push_back(ciphertextPartialSum2[0]);
          clientCC->MultipartyDecryptFusion(Partial_Sum,
                                            &plaintextMultipartySum);

          plaintextMultipartySum->SetLength(
              plaintext1->GetLength());  // ptlength;

          std::cout << "\n Resulting Fused Plaintext Sum: \n";
          std::cout << plaintextMultipartySum;

          std::cout << "\n";

          PROFILELOG(myName << ":elapsed time " << TOC_MS(t) << "msec.");
          done = true;
          break;
      }  // switch state

    }  // IsConnected()

  }  // while !done

  ////////////////////////////////////////////////////////////
  // Done
  ////////////////////////////////////////////////////////////

  PROFILELOG(myName << ": Execution Completed.");
  c.DisconnectClient();
  nap(1000);
  std::exit(EXIT_SUCCESS);  // successful return
}
