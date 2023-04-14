/*
Copyright (©) 2023 Kashif Mushtaq

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sub-license, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#pragma once
#ifndef _DEBUG
#pragma comment(lib, "./cryptopp870/x64/Output/Release/cryptlib.lib")
#else
#pragma comment(lib, "./cryptopp870/x64/Output/Debug/cryptlib.lib")
#endif // !_DEBUG




#include "pch.h"

// Crypto++ Include
#include "./cryptopp870/pch.h"
#include "./cryptopp870/files.h"
#include "./cryptopp870/default.h"
#include "./cryptopp870/base64.h"
#include "./cryptopp870/osrng.h"

//AES
#include "./cryptopp870/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "./cryptopp870/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "./cryptopp870/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "./cryptopp870/aes.h"
using CryptoPP::AES;

#include "./cryptopp870/gcm.h"
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include <WinBase.h>

#include <iostream>
#include <time.h>
#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <stdarg.h>
#include<string.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>



USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)



static std::string m_ErrorMessage;


static inline RandomNumberGenerator& PSRNG(void);

static inline RandomNumberGenerator& PSRNG(void) {
    static AutoSeededRandomPool rng;
    rng.Reseed();
    return rng;
}

static void LogToEventViewer(WORD err, const char *format, ...);
HANDLE hHandle = RegisterEventSource(NULL, L"AesGcm");

/**
Exported for dynamic loading and calling
 */
//#ifdef __cplusplus
//extern "C" {
//#endif

    bool WINAPI _base64Encode(/*[in]*/ const char *inPlainText, /*[out]*/ char **outBase64Encoded, /*[in, out]*/ int &dataLength);
    bool WINAPI _base64Decode(/*[in]*/ const char *inBase64Text, /*[out]*/ char **outPlainText, /*[in, out]*/ int &dataLength);
    bool WINAPI _hexDecode(/*[in]*/ const char *inHexEncodedText, /*[out]*/char **outHexDecoded);
    bool WINAPI _hexEncode(/*[in]*/ const char *inData, /*[out]*/char **outHexEncoded);

    bool WINAPI _encrypt_GcmAes256(/*[in]*/ const char *inHexKey, /*[in]*/ const char *inHexIv, /*[in]*/ const char *inPlainText, /*[out]*/ char **outEncryptedBase64, /*[in, out]*/ int &dataLength);
    bool WINAPI _decrypt_GcmAes256(/*[in]*/ const char *inHexKey, /*[in]*/ const char *inHexIv, /*[in]*/ const char *inBase64Text, /*[out]*/ char **outDecrypted, /*[in, out]*/ int &dataLength);

    bool WINAPI _getNewAESKeyAndIv(/*[out]*/ char **outHexKey, /*[out]*/ char **outHexIv, /*[out]*/ int &outKeyLength, /*[out]*/ int &outIvLength);

    

//#ifdef __cplusplus
//}
//#endif

void Base64Decode(const std::string& inString, std::string& outString);

void hexDecode(std::string &hexString);
bool _encrypt_local(/*[in]*/const char *aesKey, /*[in]*/const char *aesIV, /*[in]*/const char *inPlainText, /*[out]*/ char **outEncryptedBase64, /*[in, out]*/int &dataLength);
bool _decrypt_local(/*[in]*/const char *aesKey, /*[in]*/const char *aesIV, /*[in]*/const char *inBase64Text, /*[out]*/ char **outDecrypted, /*[in, out]*/int &dataLength);
