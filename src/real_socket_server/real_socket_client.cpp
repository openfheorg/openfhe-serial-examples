// @file real-socket-client - code to simulate a client to show an example of encrypted
// server-client processing relationships.
//
//The server serializes contexts, public key and processing keys for
// the client to then load. It then generates and encrypts some data
// to send to the client. The client loads the crypto context and
// keys, then operates on the encrypted data, encrypts additional
// data, and sends the results back to the server.  Finally, the
// server decrypts the result and in this demo verifies that results
// are correct.
// 
// @author: Ian Quah, Dave Cousins
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

#include "utils_socket.h"
#include "openfhe.h"

using namespace lbcrypto;

std::tuple<CC, PubKey> recvCCAndKeys(tcp::socket &s) {
  /////////////////////////////////////////////////////////////////
  // NOTE: ReleaseAllContexts is imperative; it ensures that the environment
  // is cleared before loading anything. The function call ensures we are not
  // keeping any contexts in the process. Use it before creating a new CC
  /////////////////////////////////////////////////////////////////
  CFactory::ReleaseAllContexts();
  
  CC clientCC= recvCC(s);

  /////////////////////////////////////////////////////////////////
  // NOTE: the following 2 lines are essential
  // It is possible that the keys are carried over in the cryptocontext
  // serialization so clearing the keys is important
  /////////////////////////////////////////////////////////////////

  clientCC->ClearEvalMultKeys();
  clientCC->ClearEvalAutomorphismKeys();

  PubKey clientPublicKey = recvPublicKey(s);

  recvEvalMultKey(s, clientCC);
  recvEvalAutomorphismKey(s, clientCC);

  return std::make_tuple(clientCC, clientPublicKey);
}


void computeAndSendData(tcp::socket &s,
						CC &clientCC,
						CT &clientC1,
						CT &clientC2,
						PubKey &clientPublicKey) {
  
  std::cout << "CLIENT: Applying operations on data" << std::endl;
  auto clientCiphertextMult = clientCC->EvalMult(clientC1, clientC2);
  auto clientCiphertextAdd = clientCC->EvalAdd(clientC1, clientC2);
  auto clientCiphertextRot = clientCC->EvalAtIndex(clientC1, 1);
  auto clientCiphertextRotNeg = clientCC->EvalAtIndex(clientC1, -1);

  // Now, we want to simulate a client who is encrypting data for the server to
  // decrypt. E.g weights of a machine learning algorithm

  std::cout << "CLIENT: encrypting a vector" << std::endl;
  complexVector clientVector1 = {1.0, 2.0, 3.0, 4.0};
  if (clientVector1.size() != VECTORSIZE) {
    std::cerr << "clientVector1 size was modified. Must be of length 4"
	      << std::endl;
    exit(1);
  }
  auto clientPlaintext1 = clientCC->MakeCKKSPackedPlaintext(clientVector1);
  auto clientInitiatedEncryption =
    clientCC->Encrypt(clientPublicKey, clientPlaintext1);

  sendCT(s, clientCiphertextMult);
  sendCT(s, clientCiphertextAdd);
  sendCT(s, clientCiphertextRot);
  sendCT(s, clientCiphertextRotNeg);
  sendCT(s, clientInitiatedEncryption);
}
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[]) {

  // note GConf is a global structure defined in utils.h
   try
  {
    if (argc != 3)
    {
      std::cerr << "Usage: real-socket-client <host> <port>\n";
      return 1;
    }

    boost::asio::io_context io_context;

    tcp::socket s(io_context);
    tcp::resolver resolver(io_context);
	std::cout << "CLIENT: connecting to " << argv[1] << ":" << argv[2] << std::endl;
	bool connected(false);
	while (!connected) {
	  try { 
		boost::asio::connect(s, resolver.resolve(argv[1], argv[2]));
		connected = true;
	  } catch (std::exception& e) {
	    if (e.what() == std::string("connect: Connection refused")) {
		  std::cout << "waiting for socket " << argv[1] << ":" << argv[2]
					<< " to be created" << std::endl;
		} else {
		  std::cerr<<"Error in socket connect " << e.what() << std::endl;
		  exit(EXIT_FAILURE);
		}
		nap(1000);
	  }
	}
	  
	std::cout << "CLIENT: connected" << std::endl;
  
	/////////////////////////////////////////////////////////////////
	// Actual client work
	/////////////////////////////////////////////////////////////////

	auto ccAndPubKeyAsTuple = recvCCAndKeys(s);
	auto clientCC = std::get<CRYPTOCONTEXT_INDEX>(ccAndPubKeyAsTuple);
	auto clientPublicKey = std::get<PUBLICKEY_INDEX>(ccAndPubKeyAsTuple);
  
	std::cout << "CLIENT: Getting ciphertexts" << std::endl;
	CT clientC1 = recvCT(s);
	CT clientC2 = recvCT(s);

	std::cout << "CLIENT: Computing and Serializing results" << std::endl;
	computeAndSendData(s, clientCC, clientC1, clientC2, clientPublicKey);


  } catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return EXIT_SUCCESS;

}
