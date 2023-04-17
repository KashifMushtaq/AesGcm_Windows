// AesGcmTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <iostream>

typedef bool (WINAPI* _base64Encode)(/*[in]*/ const std::string inPlainText, /*[out]*/ std::string &outBase64Encoded, /*[in, out]*/ int& dataLength);
typedef bool (WINAPI* _base64Decode)(/*[in]*/ const std::string inBase64Text, /*[out]*/ std::string &outPlainText, /*[in, out]*/ int& dataLength);

/// <summary>
/// Note:
/// It's Users responsibility to clear memory buffers allocated by the called DLL functions using delete[] out<Variable>. 
/// E.g. for char** outHexDecoded: if(outHexDecoded) delete[] outHexDecoded; must be called after calling _hexDecode function
/// </summary>
typedef bool (WINAPI* _hexDecode)(/*[in]*/ const char* inHexEncodedText, /*[out]*/char** outHexDecoded);
typedef bool (WINAPI* _hexEncode)(/*[in]*/ const char* inData, /*[out]*/char** outHexEncoded);

typedef bool (WINAPI* _encrypt_GcmAes256)(/*[in]*/ const char* inHexKey, /*[in]*/ const char* inHexIv, /*[in]*/ const char* inPlainText, /*[out]*/ char** outEncryptedBase64, /*[in, out]*/ int& dataLength);
typedef bool (WINAPI* _decrypt_GcmAes256)(/*[in]*/ const char* inHexKey, /*[in]*/ const char* inHexIv, /*[in]*/ const char* inBase64Text, /*[out]*/ char** outDecrypted, /*[in, out]*/ int& dataLength);

typedef bool (WINAPI* _getNewAESKeyAndIv)(/*[out]*/ char** outHexKey, /*[out]*/ char** outHexIv, /*[out]*/ int& outKeyLength, /*[out]*/ int& outIvLength);


LPSTR WideCharToAscii(const LPCWSTR w);
WCHAR* AsciiToWideChar(const LPCSTR p);

int main(int argc, TCHAR* argv[], TCHAR* envp[])
{
	bool result = false;


    std::string inHexKey = "";
    std::string inHexIV = "";
	char* outHexKey = nullptr;
	char* outHexIv = nullptr;
	std::string plainText = "Test encryption and decryption";
    HINSTANCE hLibEntry = NULL;

#ifndef _DEBUG
    hLibEntry = LoadLibrary(L"../../../GcmAes/x64/Release/AesGcm.dll");
#else
    hLibEntry = LoadLibrary(L"../../../GcmAes/x64/Debug/AesGcm.dll");
#endif // !_DEBUG

	



	/* ----------------------- Key Generation Test ----------------------- */

    if (hLibEntry)
    {

        _getNewAESKeyAndIv getNewAESKeyAndIv;
        getNewAESKeyAndIv = (_getNewAESKeyAndIv)GetProcAddress(hLibEntry, "_getNewAESKeyAndIv");
        if (getNewAESKeyAndIv)
        {


            int outKeyLength = 0;
            int outIvLength = 0;

            result = (getNewAESKeyAndIv)(&outHexKey, &outHexIv, outKeyLength, outIvLength);

            if (result)
            {
                printf("Key=%s\nLen=%i\n\nIV=%s\nLen=%i\n", outHexKey, outKeyLength, outHexIv, outIvLength);
                printf("Key and IV Test OK\n\n");
            }
            else
            {
                printf("%s", "Key and IV generation failed. Please check syslog for errors");
                return 1;
            }

        }


        /* ----------------------- Key Generation Test ----------------------- */






        /* ----------------------- Encryption Decryption Test ----------------------- */
        //Save key and IV to call encryption and decryption functions
        if(outHexKey) inHexKey = outHexKey;
        if(outHexIv) inHexIV = outHexIv;

        char* outTestEncrypted = nullptr;
        int outTestEncryptedLen = 0;

        _encrypt_GcmAes256 encrypt_GcmAes256;
        encrypt_GcmAes256 = (_encrypt_GcmAes256)GetProcAddress(hLibEntry, "_encrypt_GcmAes256");
        
        if (encrypt_GcmAes256)
        {
            //encrypt - result base64 encoded
            result = (encrypt_GcmAes256)(inHexKey.c_str(), inHexIV.c_str(), plainText.c_str(), &outTestEncrypted, outTestEncryptedLen);
            if (result)
            {
                printf("Test 1 -> Encrypted base64 encoded: %s\n", outTestEncrypted);
            }
            else
            {
                printf("%s", "Test 1 -> Encryption failed. Please check event viewer for errors");
                return 1;
            }
        }

        char* outTestDecrypted = nullptr;
        int outTestDecryptedLen = 0;

        _decrypt_GcmAes256 decrypt_GcmAes256;
        decrypt_GcmAes256 = (_decrypt_GcmAes256)GetProcAddress(hLibEntry, "_decrypt_GcmAes256");

        if (decrypt_GcmAes256)
        {
            //decrypt - result plain text
            result = (decrypt_GcmAes256)(inHexKey.c_str(), inHexIV.c_str(), outTestEncrypted, &outTestDecrypted, outTestDecryptedLen);
            if (result && strcmp(plainText.c_str(), outTestDecrypted) == 0)
            {
                printf("Test 1 -> Decrypted: %s\n", outTestDecrypted);
                printf("Test 1 -> Encryption / Decryption OK\n\n");
            }
            else
            {
                printf("%s", "Test 1 -> Decryption failed. Please check event viewer for errors");
                return 1;
            }
        }

        inHexKey.clear();
        inHexIV.clear();

        if (outHexKey)
        {
            delete[] outHexKey;
            outHexKey = nullptr;
        }
        if (outHexIv)
        {
            delete[] outHexIv;
            outHexIv = nullptr;
        }
        if (outTestEncrypted)
        {
            delete[] outTestEncrypted;
            outTestEncrypted = nullptr;
        }

        /* ----------------------- Encryption Decryption Test ----------------------- */





        /* ----------------------- C++ Encryption and C++ Decryption Test ----------------------- */
        std::string hexKey = "2192B39425BBD08B6E8E61C5D1F1BC9F428FC569FBC6F78C0BC48FCCDB0F42AE";
        std::string hexIV = "E1E592E87225847C11D948684F3B070D";

        printf("Plain Text: %s\n", plainText.c_str());

        char* outEncrypted = nullptr;
        int outEncryptedLen = 0;

        encrypt_GcmAes256 = (_encrypt_GcmAes256)GetProcAddress(hLibEntry, "_encrypt_GcmAes256");

        if (encrypt_GcmAes256)
        {
            //encrypt - result base64 encoded
            result = (encrypt_GcmAes256)(hexKey.c_str(), hexIV.c_str(), plainText.c_str(), &outEncrypted, outEncryptedLen);
            if (result)
            {
                printf("Test 2 -> Encrypted base64 encoded: %s\n", outEncrypted);
            }
            else
            {
                printf("%s", "Test 2 -> Encryption failed. Please check syslog for errors");
                return 1;
            }
        }

        char* outDecrypted = nullptr;
        int outDecryptedLen = 0;

        decrypt_GcmAes256 = (_decrypt_GcmAes256)GetProcAddress(hLibEntry, "_decrypt_GcmAes256");

        if (decrypt_GcmAes256)
        {
            //decrypt - result plain text
            result = (decrypt_GcmAes256)(hexKey.c_str(), hexIV.c_str(), outEncrypted, &outDecrypted, outDecryptedLen);
            if (result && strcmp(plainText.c_str(), outDecrypted) == 0)
            {
                printf("Test 2 -> Decrypted: %s\n", outDecrypted);
                printf("Test 2 -> Encryption / Decryption OK\n\n");
            }
            else
            {
                printf("%s", "Test 2 -> Decryption failed. Please check syslog for errors");
                return 1;
            }
        }

        // Clear buffers
        if (outEncrypted)
        {
            delete[] outEncrypted;
            outEncrypted = nullptr;
        }
        if (outDecrypted)
        {
            delete[] outDecrypted;
            outDecrypted = nullptr;
        }
        /* ----------------------- C++ Encryption and C++ Decryption Test ----------------------- */




        /* ----------------------- Java based Encryption and C++ Decryption Test ----------------------- */
        //Java Encrypted with same Key and IV as above
        // A/boAixWJKflKviHp2cfDl6l/xn1qw2MsHcKFkrOfm2XOVmawIFct4fS1w7wKw==

        std::string javaEncrypted = "A/boAixWJKflKviHp2cfDl6l/xn1qw2MsHcKFkrOfm2XOVmawIFct4fS1w7wKw==";
        char* outCDecrypted = nullptr;
        int outCDecryptedLen = 0;

        decrypt_GcmAes256 = (_decrypt_GcmAes256)GetProcAddress(hLibEntry, "_decrypt_GcmAes256");

        if (decrypt_GcmAes256)
        {
            //decrypt - result plain text
            result = (decrypt_GcmAes256)(hexKey.c_str(), hexIV.c_str(), javaEncrypted.c_str(), &outCDecrypted, outCDecryptedLen);
            if (result && strcmp(plainText.c_str(), outCDecrypted) == 0)
            {
                printf("Test 3 -> Decrypted: %s\n", outCDecrypted);
                printf("Test 3 -> Java Encrypted / C++ Decryption OK\n\n");
            }
            else
            {
                printf("%s", "Test 3 -> Java Decryption failed. Please check syslog for errors");
                return 1;
            }
        }

        // Clear buffers
        if (outCDecrypted)
        {
            delete[] outCDecrypted;
            outCDecrypted = nullptr;
        }
        /* ----------------------- Java based Encryption and C++ Decryption Test ----------------------- */




        /* ----------------------- Hex Encoding / Decoding Test ----------------------- */

         std::wstring pszPlainText = L"syllabic kana – hiragana (平仮名) and katakana (片仮名)";
        char* hexEncoded = nullptr;
        char* hexDecoded = nullptr;

        _hexEncode hexEncode;
        hexEncode = (_hexEncode)GetProcAddress(hLibEntry, "_hexEncode");

        if (hexEncode)
        {
            result = (hexEncode)(WideCharToAscii(pszPlainText.c_str()), &hexEncoded);

            if (result)
            {
                _tprintf(L"Test 4 -> Multi-byte Text: %s\n", pszPlainText.c_str());
                printf("Test 4 -> Hex Encoded: %s\n", hexEncoded);
                printf("Test 4 -> Hex Encoding OK\n\n");
            }
            else
            {
                printf("%s", "Test 4 -> Encoding failed.");
                return 1;
            }
        }

        _hexDecode hexDecode;
        hexDecode = (_hexDecode)GetProcAddress(hLibEntry, "_hexDecode");

        if (hexDecode)
        {
            result = (hexDecode)(hexEncoded, &hexDecoded);

            if (result && strcmp(WideCharToAscii(pszPlainText.c_str()), hexDecoded) == 0)
            {
                _tprintf(L"Test 5 -> Multi-byte Text: %s\n", pszPlainText.c_str());
                _tprintf(L"Test 5 -> Hex Decoded: %s\n", AsciiToWideChar(hexDecoded));
                printf("Test 5 -> Hex Decoding OK\n\n");
            }
            else
            {
                printf("%s", "Test 4 -> Decoding failed.");
                return 1;
            }
        }

        if (hexEncoded)
        {
            delete[] hexEncoded;
            hexEncoded = nullptr;
        }
        if (hexDecoded)
        {
            delete[] hexDecoded;
            hexDecoded = nullptr;
        }
        /* ----------------------- Hex Encoding / Decoding Test ----------------------- */


        /* ----------------------- Base64 Encoding / Decoding Test ----------------------- */

        std::string base64Encoded = "";
        std::string base64Decoded = "";
        int base64Len = (int)pszPlainText.length();

        _base64Encode base64Encode;
        base64Encode = (_base64Encode)GetProcAddress(hLibEntry, "_base64Encode");

        if (base64Encode)
        {
            result = (base64Encode)(WideCharToAscii(pszPlainText.c_str()), base64Encoded, base64Len);

            if (result)
            {
                _tprintf(L"Test 6 -> Multi-byte Text: %s\n", pszPlainText.c_str());
                printf("Test 6 -> Base64 Encoded: %s\n", base64Encoded.c_str());
                printf("Test 6 -> Base64 Encoding OK\n\n");
            }
            else
            {
                printf("%s", "Test 6 -> Encoding failed.");
                return 1;
            }
        }

        _base64Decode base64Decode;
        base64Decode = (_base64Decode)GetProcAddress(hLibEntry, "_base64Decode");

        if (base64Decode)
        {
            base64Len = (int)base64Encoded.length();
            result = (base64Decode)(base64Encoded, base64Decoded, base64Len);

            if (result && strcmp(WideCharToAscii(pszPlainText.c_str()), base64Decoded.c_str()) == 0)
            {
                _tprintf(L"Test 7 -> Multi-byte Text: %s\n", pszPlainText.c_str());
                _tprintf(L"Test 7 -> Base64 Decoded: %s\n", AsciiToWideChar(base64Decoded.c_str()));
                printf("Test 7 -> Base64 Decoding OK\n\n");
            }
            else
            {
                printf("%s", "Test 7 -> Decoding failed.");
                return 1;
            }
        }

        /* ----------------------- Base64 Encoding / Decoding Test ----------------------- */


    }

	if (hLibEntry)FreeModule(hLibEntry);

    return 0;
}


LPSTR WideCharToAscii(const LPCWSTR w)
{
    int len2 = lstrlenW(w);
    char* s = (char*)malloc(len2 + 1);

    ZeroMemory(s, len2 + 1);
    if (0 == WideCharToMultiByte(CP_ACP, 0, w, len2, s, len2, NULL, NULL))
    {
        // FAIL
        free(s);
        s = NULL;
    }
    else
    {
        s[len2] = '\0';
    }
    return s;
}


WCHAR* AsciiToWideChar(const LPCSTR p)
{
    DWORD len = (DWORD)strlen(p);
    LPWSTR p2 = (WCHAR*)malloc(sizeof(WCHAR) * (len + 1));
    ZeroMemory(p2, sizeof(WCHAR) * (len + 1));
    if (0 == MultiByteToWideChar(CP_ACP, 0, p, len, p2, len * 2))
    {
        // FAIL
        free(p2);
        p2 = NULL;
    }
    else
    {
        p2[len] = L'\0';
    }
    return p2;
}