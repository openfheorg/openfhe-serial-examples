// @file utils.h - utilities to be used with real_server example
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

#ifndef REAL_SERVER_UTILS_H
#define REAL_SERVER_UTILS_H
#include "openfhe.h"

// header files needed for serialization of CKKS
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
#include <boost/interprocess/sync/named_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

using namespace lbcrypto;
using namespace boost::interprocess; //named mutexes for locks

using complexVector = std::vector<std::complex<double>>;
using complexMatrix = std::vector<complexVector>;
using ciphertextMatrix = std::vector<Ciphertext<DCRTPoly>>;

const int VECTORSIZE = 4;
const int CRYPTOCONTEXT_INDEX = 0;
const int PUBLICKEY_INDEX = 1;



/**
 * Config container. stores locations of I/O files for IPC
 */
struct Configs {
  /////////////////////////////////////////////////////////////////
  // NOTE:
  // If running locally, you may want to replace the "hardcoded" DATAFOLDER with
  // the DATAFOLDER location below which gets the current working directory
  /////////////////////////////////////////////////////////////////
  //  char buff[1024];
  //  std::string DATAFOLDER = std::string(getcwd(buff, 1024)) + "/demoData";

  // Save-Load locations for keys
  const std::string DATAFOLDER = "demoData";
  std::string ccLocation = DATAFOLDER + "/cryptocontext.txt";
  std::string pubKeyLocation = DATAFOLDER + "/key_pub.txt";    // Pub key
  std::string multKeyLocation = DATAFOLDER + "/key_mult.txt";  // relinearization key
  std::string rotKeyLocation = DATAFOLDER + "/key_rot.txt";    // automorphism / rotation key
  
  // Save-load locations for RAW ciphertexts
  std::string cipherOneLocation = DATAFOLDER + "/ciphertext1.txt";
  std::string cipherTwoLocation = DATAFOLDER + "/ciphertext2.txt";

  // Save-load locations for evaluated ciphertexts
  std::string cipherMultLocation = DATAFOLDER + "/ciphertextMult.txt";
  std::string cipherAddLocation = DATAFOLDER + "/ciphertextAdd.txt";
  std::string cipherRotLocation = DATAFOLDER + "/ciphertextRot.txt";
  std::string cipherRotNegLocation = DATAFOLDER + "/ciphertextRotNegLocation.txt";
  std::string clientVectorLocation = DATAFOLDER + "/ciphertextVectorFromClient.txt";
  
  const std::string SERVER_LOCK = "s_lock";
  const std::string CLIENT_LOCK = "c_lock";

  //contain the lock mutex 
  named_mutex *serverLock;
  named_mutex *clientLock;
  
};

// global configuration structure that contains all locations for IPC
Configs GConf;  

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
 * displayVectors - "zip" the two indexable containers and display them as pairs
 * of values
 * @tparam T - an indexable container
 * @param v1 - container 1
 * @param v2 - container 2
 */
template <typename T>
void displayVectors(T v1, T v2) {
  for (unsigned int i = 0; i < v1.size(); i++) {
    std::cout << v1[i] << "," << v2[i] << '\n';
  }
}

/////////////////////////////////////////////////////////////////
// Synchronization material
//  - uses mutex "locks" to coordinate the two processes
/////////////////////////////////////////////////////////////////

/** fExists: check if the file already exists
 * @param filename
 * @return
 *  bool: if true then the file already exists so the current query-er should
 * sleep if false then feel free to grab it
 */
bool fExists(const std::string &filename) {
  if (FILE *file = fopen(filename.c_str(), "r")) {
    fclose(file);
    return true;
  } else {
    return false;
  }
}

/** fRemove: Remove the file if it already exists
 * @param filename
 * @return
 *  bool: if true then the file already exists and we delete it
 */
bool fRemove(const std::string &filename) {

  if (FILE *file = fopen(filename.c_str(), "r")) {
    fclose(file);
    std::remove(filename.c_str());
    return true;
  } else {
    return false;
  }
}

/**
 * Take a powernap of 0.5 seconds
 */
void nap(const int &ms = 500) {
  std::chrono::duration<int, std::milli> timespan(ms);
  std::this_thread::sleep_for(timespan);
}

/**
 * createAndAcquireLock
 * create the lock and immediately "get" the lock.
 */
named_mutex* createAndAcquireLock(const std::string &lockName) {
  try {
    auto mtx = new named_mutex(create_only, lockName.c_str());
    mtx->lock();
    return mtx;
  } catch (interprocess_exception &ex){
    named_mutex::remove(lockName.c_str());
    std::cerr<<"Error in createAndAquireLock create "<<lockName
	     << " "<< ex.what() << std::endl;
    exit(EXIT_FAILURE);
  }
  return NULL;
}

/**
 * OpenLock
 * open an existing lock
 */
named_mutex* openLock(const std::string &lockName) {
  bool done(false);
  while (!done) {
    try {
      auto mtx = new named_mutex(open_only, lockName.c_str());
      done = true;
	  
      return mtx;
    } catch (interprocess_exception &ex){
      if (ex.what() == std::string("No such file or directory")) {
		std::cout << "waiting for " << lockName << " to be created" << std::endl;
      } else {
		std::cerr<<"Error in openLock create "<<lockName
				 << " "<< ex.what() << std::endl;
		exit(EXIT_FAILURE);
      }
      nap(1000);
    }
  }
  
  return NULL;
}

/**
 * acquireLock
 *  - "get" the lock. sleeps until successful
 */
void acquireLock(named_mutex* mtx, const std::string &lockName) { 
  try {
    mtx->lock();
  } catch (interprocess_exception &ex){
    std::cerr<<"Error in aquireLock lock "<<lockName 
	     << " "<< ex.what() << std::endl;
  }


}

/**
 * releaseLock
 *  - "release" the lock
 */
void releaseLock(named_mutex* mtx, const std::string &lockName){
  try {
    mtx->unlock();
  } catch (interprocess_exception &ex){
    std::cerr<<"Error in releaseLock lock "<<lockName 
	     << " "<< ex.what() << std::endl;
  }
}

/**
 * removeLock
 *  - "remove" the lock by deleting it from the system
 */
void removeLock(named_mutex* mtx, const std::string &lockName){
  try {
    named_mutex::remove(lockName.c_str());
  } catch (interprocess_exception &ex){
    std::cerr<<"Error in removeLock lock "<<lockName 
	     << " "<< ex.what() << std::endl;
  }
}

#endif  // REAL_SERVER_UTILS_H
