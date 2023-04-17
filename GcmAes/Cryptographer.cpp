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

#include "Cryptographer.h"

bool WINAPI
_base64Encode(const std::string inPlainText, std::string &outBase64Encoded, int& dataLength)
{
    bool bR = false;

    CryptoPP::Base64Encoder* base64Encoder = new CryptoPP::Base64Encoder(new StringSink(outBase64Encoded), false);
    base64Encoder->PutMessageEnd(reinterpret_cast<const unsigned char*> (inPlainText.c_str()), inPlainText.length());
    delete base64Encoder;
    dataLength = (int)outBase64Encoded.length();
    if (dataLength > 0)
    {
        bR = true;
    }
    return bR;
}

bool WINAPI
_base64Decode(/*[in]*/const std::string inBase64Text, /*[out]*/ std::string &outPlainText, /*[in, out]*/int &dataLength)
{
    bool bR = false;

    Base64Decode(inBase64Text, outPlainText);

    if (outPlainText.length() > 0)
    {
        bR = true;
    }
    return bR;
}

void
Base64Decode(const std::string &inString, std::string &outString)
{
    StringSource(inString, true, new Base64Decoder(new StringSink(outString)));
}

bool WINAPI
_encrypt_GcmAes256(/*[in]*/const char *inHexKey, /*[in]*/const char *inHexIv, /*[in]*/const char *inPlainText, /*[out]*/ char **outEncryptedBase64, /*[in, out]*/int &dataLength)
{
    bool bR = false;

    std::string aesKey(inHexKey);
    std::string aesIv(inHexIv);
    
    if (aesKey.length() != 64 && aesIv.length() != 32)
    {
        LogToEventViewer(1, "%s", "AES Session Key must be 64 character hex string and IV must be 32 character hex string");
        return false;
    }
    
    //Hex decode incoming Key and IV
    hexDecode(aesKey);
    hexDecode(aesIv);
    
    std::string outText;
    std::string outBase64;

    if (aesKey.length() > 0 && aesIv.length() > 0)
    {
        bR = _encrypt_local(aesKey.c_str(), aesIv.c_str(), inPlainText, outEncryptedBase64, dataLength);
    }
    else
    {
        m_ErrorMessage.append("_encrypt_GcmAes256 -> AES Session Key or IV cannot be empty");
    }

    if(m_ErrorMessage.length()>0)
    {
        LogToEventViewer(EVENTLOG_ERROR_TYPE, "%s", m_ErrorMessage.c_str());
        m_ErrorMessage.clear();
    }
    
    outText.clear();
    outBase64.clear();

    return bR;
}

bool WINAPI
_decrypt_GcmAes256(/*[in]*/const char *inHexKey, /*[in]*/const char *inHexIv, /*[in]*/const char *inBase64Text, /*[out]*/ char **outDecrypted, /*[in, out]*/int &dataLength)
{
    bool bR = false;

    std::string aesKey(inHexKey);
    std::string aesIv(inHexIv);

    if (aesKey.length() != 64 && aesIv.length() != 32)
    {
        LogToEventViewer(1, "%s", "AES Session Key must be 64 character hex string and IV must be 32 character hex string");
        return false;
    }
    
    //Hex decode incoming Key and IV
    hexDecode(aesKey);
    hexDecode(aesIv);
    
    if (aesKey.length() > 0 && aesIv.length() > 0)
    {
        bR = _decrypt_local(aesKey.c_str(), aesIv.c_str(), inBase64Text, outDecrypted, dataLength);
    }
    else
    {
        m_ErrorMessage.append("_decrypt_GcmAes256 -> AES Session Key or IV cannot be empty");
    }

    if(m_ErrorMessage.length()>0)
    {
        LogToEventViewer(EVENTLOG_ERROR_TYPE, "%s", m_ErrorMessage.c_str());
        m_ErrorMessage.clear();
    }
    
    return bR;
}

bool WINAPI
_getNewAESKeyAndIv(/*[out]*/ char **outHexKey, /*[out]*/ char **outHexIv, /*[out]*/int &outKeyLength, /*[out]*/int &outIvLength)
{
    bool bR = false;

    try
    {
        std::string outAESKey;
        std::string outAESIV;

        byte *bKey = new byte[AES::MAX_KEYLENGTH + 1];
        memset(bKey, '\0', AES::MAX_KEYLENGTH + 1);
        PSRNG().GenerateBlock(bKey, AES::MAX_KEYLENGTH + 1);

        byte *bIV = new byte[AES::BLOCKSIZE + 1];
        memset(bIV, '\0', AES::BLOCKSIZE + 1);
        PSRNG().GenerateBlock(bIV, AES::BLOCKSIZE + 1);



        HexEncoder *hexEncoder = new HexEncoder(new StringSink(outAESKey));
        hexEncoder->Put(bKey, AES::MAX_KEYLENGTH);
        hexEncoder->MessageEnd();
        delete hexEncoder;

        hexEncoder = new HexEncoder(new StringSink(outAESIV));
        hexEncoder->Put(bIV, AES::BLOCKSIZE);
        hexEncoder->MessageEnd();

        delete [] bKey;
        delete [] bIV;
        delete hexEncoder;

        hexEncoder = NULL;

        outKeyLength = (int)outAESKey.length();
        outIvLength = (int)outAESIV.length();

        if (outKeyLength > 0 && outIvLength > 0)
        {
            if (*outHexKey) delete[] *outHexKey;
            if (*outHexIv) delete[] *outHexIv;

            *outHexKey = new char[outKeyLength + 1];
            *outHexIv = new char[outIvLength + 1];

            memset(*outHexKey, '\0', outKeyLength + 1);
            memset(*outHexIv, '\0', outIvLength + 1);

            memcpy(*outHexKey, outAESKey.c_str(), outKeyLength);
            memcpy(*outHexIv, outAESIV.c_str(), outIvLength);

            bR = true;
        }
        else
        {
            m_ErrorMessage.append("_getNewAESKey -> Failed");
        }

        outAESKey.clear();
        outAESIV.clear();
    }
    catch (CryptoPP::Exception *e)
    {
        m_ErrorMessage.append(e->GetWhat());
    }

    if(m_ErrorMessage.length()>0)
    {
        LogToEventViewer(EVENTLOG_ERROR_TYPE, "%s", m_ErrorMessage.c_str());
        m_ErrorMessage.clear();
    }
    
    return bR;
}

bool
_encrypt_local(/*[in]*/const char *aesKey, /*[in]*/const char *aesIV, /*[in]*/const char *inPlainText, /*[out]*/ char **outEncryptedBase64, /*[in, out]*/int &dataLength)
{
    bool bR = false;
    std::string outText;
    std::string outBase64;

    if (strlen(aesKey) > 0 && strlen(aesIV) > 0)
    {
        try
        {
            GCM< AES >::Encryption aesEncryption;
            aesEncryption.SetKeyWithIV(reinterpret_cast<const byte*> (aesKey), AES::MAX_KEYLENGTH, reinterpret_cast<const byte*> (aesIV), AES::BLOCKSIZE);

            StringSource(inPlainText, true, new AuthenticatedEncryptionFilter(aesEncryption, new StringSink(outText)
                                                                              ) // AuthenticatedEncryptionFilter
                         ); // StringSource

            CryptoPP::Base64Encoder *base64Encoder = new CryptoPP::Base64Encoder(new StringSink(outBase64), false);
            base64Encoder->PutMessageEnd(reinterpret_cast<const unsigned char *> (outText.data()), outText.length());
            delete base64Encoder;

            dataLength = (int)outBase64.length();
            if (outBase64.length() > 0)
            {
                if (*outEncryptedBase64) delete *outEncryptedBase64;
                *outEncryptedBase64 = new char[dataLength + 1];
                memset(*outEncryptedBase64, '\0', dataLength + 1);
                memcpy(*outEncryptedBase64, outBase64.c_str(), dataLength);

                bR = true;
            }
            else
            {
                m_ErrorMessage.append("_encrypt_local -> Encryption Failed");
            }

        }
        catch (CryptoPP::InvalidArgument& e)
        {
            m_ErrorMessage.append(e.what());
        }
        catch (CryptoPP::Exception& e)
        {
            m_ErrorMessage.append(e.what());
        }
    }
    else
    {
        m_ErrorMessage.append("_encrypt_local -> AES Key and IV must be 64 and 32 hex characters");
    }

    outText.clear();
    outBase64.clear();

    return bR;
}

bool
_decrypt_local(/*[in]*/const char *aesKey, /*[in]*/const char *aesIV, /*[in]*/const char *inBase64Text, /*[out]*/ char **outDecrypted, /*[in, out]*/int &dataLength)
{
    bool bR = false;
    std::string outText;

    std::string pszDecodedText;
    Base64Decode(inBase64Text, pszDecodedText);

    if (strlen(aesKey) > 0 && strlen(aesIV) > 0)
    {
        try
        {
            GCM< AES >::Decryption aesDecryption;
            aesDecryption.SetKeyWithIV(reinterpret_cast<const byte*> (aesKey), AES::MAX_KEYLENGTH, reinterpret_cast<const byte*> (aesIV), AES::BLOCKSIZE);

            AuthenticatedDecryptionFilter df(aesDecryption, new StringSink(outText));

            // The StringSource dtor will be called immediately
            //  after construction below. This will cause the
            //  destruction of objects it owns. To stop the
            //  behavior so we can get the decoding result from
            //  the DecryptionFilter, we must use a redirector
            //  or manually Put(...) into the filter without
            //  using a StringSource.
            StringSource(pszDecodedText, true,
                         new Redirector(df /*, PASS_EVERYTHING */)
                         ); // StringSource

            // If the object does not throw, here's the only
            //  opportunity to check the data's integrity
            bR = df.GetLastResult();


            dataLength = (int)outText.length();
            if (outText.length() > 0)
            {
                if (*outDecrypted) delete[] *outDecrypted;
                *outDecrypted = new char[dataLength + 1];
                memset(*outDecrypted, '\0', dataLength + 1);
                memcpy(*outDecrypted, outText.c_str(), dataLength);

                bR = true;
            }
            else
            {
                m_ErrorMessage.append("_decrypt_local -> Decryption Failed");
            }
        }
        catch (CryptoPP::HashVerificationFilter::HashVerificationFailed& e)
        {
            m_ErrorMessage.append(e.what());
        }
        catch (CryptoPP::InvalidArgument& e)
        {
            m_ErrorMessage.append(e.what());
        }
        catch (CryptoPP::Exception& e)
        {
            m_ErrorMessage.append(e.what());
        }
    }
    else
    {
        m_ErrorMessage.append("_decrypt_local -> AES Key and IV must be 64 and 32 hex characters");
    }

    return bR;
}


bool _hexDecode(/*[in]*/ const char *inHexEncodedText, /*[out]*/char **outHexDecoded)
{
    std::string hexString = inHexEncodedText;
    
    if (!hexString.c_str()) return false;
    if (hexString.length() == 0) return false;

    hexDecode(hexString);

    int dataLength = (int)hexString.length();
    if (hexString.length() > 0)
    {
        if (*outHexDecoded) delete *outHexDecoded;
        *outHexDecoded = new char[dataLength + 1];
        memset(*outHexDecoded, '\0', dataLength + 1);
        memcpy(*outHexDecoded, hexString.c_str(), dataLength);

        return true;
    }
    
    return false;
}


bool _hexEncode(/*[in]*/ const char *inData, /*[out]*/char **outHexEncoded)
{
    bool bR = false;
    int len = (int)strlen(inData);
    
    byte *bData = new byte[len + 1];
    memset(bData, '\0', len + 1);
    memcpy(bData, inData, len);
        
    std::string outHex = "";
    HexEncoder *hexEncoder = new HexEncoder(new StringSink(outHex));
    hexEncoder->Put(bData, len);
    hexEncoder->MessageEnd();
    delete hexEncoder;
    
    delete[] bData;

    int dataLength = (int)outHex.length();
    if (outHex.length() > 0)
    {
        if (*outHexEncoded) delete *outHexEncoded;
        *outHexEncoded = new char[dataLength + 1];
        memset(*outHexEncoded, '\0', dataLength + 1);
        memcpy(*outHexEncoded, outHex.c_str(), dataLength);
        bR = true;
    }

    return bR;
}
    
void
hexDecode(std::string &hexString)
{
    if (!hexString.c_str()) return;
    if (hexString.length() == 0) return;

    std::string binValue;
    HexDecoder decoder;
    decoder.Attach(new StringSink(binValue));
    decoder.Put((byte*) hexString.data(), hexString.size());
    decoder.MessageEnd();

    hexString.clear();
    hexString.append(binValue);
    binValue.clear();

}

/* some event logging */
static void
LogToEventViewer(WORD err, const char *format, ...)
{

    char buffer[256];
    memset(buffer, '\0', 256);

    va_list args;
    va_start(args, format);
    
    vsnprintf(buffer, 256, format, args);
    perror(buffer);

    va_end(args);

    if (NULL != hHandle)
    {
        ReportEventA(hHandle, err, 0, 0, NULL, 1, 0, (LPCSTR*) &buffer[0], NULL);
    }

}

