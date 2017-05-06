#include "gpsoauthclient.hpp"

//#define CRYPTOPP
#ifdef CRYPTOPP
#include "cryptopp\base64.h"
#endif

#include "cryptopp\rsa.h"
#include "cryptopp\osrng.h"
#undef byte

#include "tomcrypt.h"

#include <memory>
#include <algorithm>
#include <sstream>
#include <functional>

#define CURL_STATICLIB
#include "curl\curl.h"

using namespace CryptoPP;
#pragma comment (lib, "cryptlib.lib")

gpsoauthclient::gpsoauthclient(const std::string & email, const std::string & password)
{
	this->email = email;
	this->password = password;

	this->base64_key =
		"AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3"
		"iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK"
		"RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/"
		"6rmf5AAAAAwEAAQ==";

	this->android_key = this->google__key_from_b64(this->base64_key);
	this->version = "1.0.0";
	this->authurl = "https://android.clients.google.com/auth";
	this->useragent = "gspoauthclient/" + this->version;
}

gpsoauthclient::~gpsoauthclient() noexcept
{
}

std::unordered_map<std::string, std::string> gpsoauthclient::perform_master_login(const std::string &service, const std::string &device_country, const std::string &operator_country, const std::string &lang, int32_t sdk_version)
{
	return perform_auth_request(std::unordered_map<std::string, std::string>({
		{ "accountType", "HOSTED_OR_GOOGLE" },
		{ "Email", this->email },
		{ "has_permission", "1" },
		{ "add_account", "1" },
		{ "EncryptedPasswd",  google__create_signature(email, password, android_key) },
		{ "service", service },
		{ "source", "android" },
		{ "device_country", device_country },
		{ "operatorCountry", operator_country },
		{ "lang", lang },
		{ "sdk_version", std::to_string(sdk_version) }
	}));
}

std::unordered_map<std::string, std::string> gpsoauthclient::perform_oauth(const std::string &master_token, const std::string &service, const std::string &app, const std::string &client_signature, const std::string &device_country, const std::string &operator_country, const std::string &lang, int32_t sdk_version)
{
	return perform_auth_request(std::unordered_map<std::string, std::string>({
		{ "accountType", "HOSTED_OR_GOOGLE" },
		{ "Email", this->email },
		{ "has_permission", "1" },
		{ "EncryptedPasswd",  master_token },
		{ "service", service },
		{ "source", "android" },
		{ "app", app },
		{ "client_sig", client_signature },
		{ "device_country", device_country },
		{ "operatorCountry", operator_country },
		{ "lang", lang },
		{ "sdk_version", std::to_string(sdk_version) }
	}));
}


rsaparameter gpsoauthclient::google__key_from_b64(const std::string &base64_key)
{
	std::vector<uint8_t> decoded;
#ifdef CRYPTOPP
	Base64Decoder base64decoder;
	base64decoder.Put(reinterpret_cast<const uint8_t*>(base64_key.data()), base64_key.size());
	base64decoder.MessageEnd();

	if (base64decoder.MaxRetrievable() && base64decoder.MaxRetrievable() <= 0xffffffff)
	{
		decoded.resize(static_cast<size_t>(base64decoder.MaxRetrievable()));
		base64decoder.Get(decoded.data(), decoded.size());
	}

#else
	uint32_t size = base64_key.size();
	decoded.resize(size);

	if (base64_decode(reinterpret_cast<const byte*>(base64_key.c_str()), base64_key.size(), decoded.data(), reinterpret_cast<unsigned long*>(&size)) != CRYPT_OK)
	{
		throw "google__key_from_b64: base64_decode error";
	}
	
	decoded.resize(size);
#endif

	std::function<int32_t(const std::vector<uint8_t> &, int32_t)> byte_to_int = [](const std::vector<uint8_t> &b, int32_t i)
	{
		return (b.at(i) << 24) | (b.at(i + 1) << 16) | (b.at(i + 2) << 8) | b.at(i + 3);
	};

	int32_t i = byte_to_int(decoded, 0);
	std::vector<uint8_t> modulus(decoded.begin() + 4, decoded.begin() + 4 + i);

	int32_t j = byte_to_int(decoded, 4 + i);
	std::vector<uint8_t> exponent(decoded.begin() + i + 8, decoded.begin() + i + 8 + j);

	return std::make_pair(modulus, exponent);
}

std::string gpsoauthclient::google__create_signature(const std::string &email, const std::string &password, const rsaparameter &key)
{
	std::function<std::vector<uint8_t>(const rsaparameter &)> key_to_struct = [](const rsaparameter &key) -> std::vector<uint8_t>
	{
		std::vector<uint8_t> b;
		
		b.push_back(0x00);
		b.push_back(0x00);
		b.push_back(0x00);
		b.push_back(0x80);

		b.insert(b.end(), key.first.begin(), key.first.end());

		b.push_back(0x00);
		b.push_back(0x00);
		b.push_back(0x00);
		b.push_back(0x03);

		b.insert(b.end(), key.second.begin(), key.second.end());

		return b;
	};

	std::function<std::vector<uint8_t>(std::vector<uint8_t> &)> compute_sha1_hash = [](const std::vector<uint8_t> &structure) -> std::vector<uint8_t>
	{
		std::unique_ptr<uint8_t[]> sha1_hash = std::make_unique<uint8_t[]>(sha1_desc.hashsize);

		hash_state hs_sha1;
		sha1_init(&hs_sha1);
		sha1_process(&hs_sha1, structure.data(), structure.size());
		sha1_done(&hs_sha1, sha1_hash.get());

		return std::vector<uint8_t>(sha1_hash.get(), sha1_hash.get() + sha1_desc.hashsize);
	};

	std::vector<uint8_t> signature({ 0x00 });
	std::vector<uint8_t> sha1_hash = compute_sha1_hash(key_to_struct(key));

	std::string credentials = this->email + '\x00' + this->password;

	auto pkcs1_rsa_oaep_encrypt = [key](const std::string &b)
	{
		Integer modulus(key.first.data(), key.first.size(), Integer::UNSIGNED);
		Integer exponent(key.second.data(), key.second.size(), Integer::UNSIGNED);

		RSA::PublicKey publickey;
		publickey.Initialize(modulus, exponent);

		std::string encoded;

		/*
		crypto++ readme
		1.	If a constructor for A takes a pointer to an object B (except primitive
			types such as int and char), then A owns B and will delete B at A's
			destruction.  If a constructor for A takes a reference to an object B,
			then the caller retains ownership of B and should not destroy it until
			A no longer needs it. 
		*/

		StringSource(b, true, new PK_EncryptorFilter(AutoSeededRandomPool(), RSAES_OAEP_SHA_Encryptor(publickey), new StringSink(encoded)));
		
		return std::vector<uint8_t>(encoded.begin(), encoded.end());
	};

	//the return encrypted crentials should be a vector of 128 bytes
	//the mod public keysize itself should be 1024
	//the public exponent should be 3 in this case
	std::vector<uint8_t> encrypted_credentials = pkcs1_rsa_oaep_encrypt(credentials);

	//appends the 4 uint8_t hash to the end of 'signature'
	signature.insert(signature.end(), sha1_hash.begin(), sha1_hash.begin() + 4);

	//appends the encrypted email/pass to the end of 'signature'
	signature.insert(signature.end(), encrypted_credentials.begin(), encrypted_credentials.end());

	return urlsafe_b64_encode(signature);
}

std::string gpsoauthclient::urlsafe_b64_encode(const std::vector<uint8_t>& signature)
{
	std::vector<uint8_t> encoded;

#ifdef CRYPTOPP
	Base64Encoder base64encoder;
	base64encoder.Put(reinterpret_cast<const byte*>(signature.data()), signature.size());
	base64encoder.MessageEnd();

	if (base64encoder.MaxRetrievable() && base64encoder.MaxRetrievable() <= 0xffffffff)
	{
		encoded.resize(static_cast<size_t>(base64encoder.MaxRetrievable()));
		base64encoder.Get(encoded.data(), encoded.size());
	}

	for (size_t n = 0; n < encoded.size(); ++n)
	{
		if (encoded.at(n) == '+')
		{
			encoded.at(n) = '-';
		}
		else if (encoded.at(n) == '/')
		{
			encoded.at(n) = '_';
		}
	}

	std::string encoded_string(encoded.begin(), encoded.end());

	encoded_string.erase(std::remove(encoded_string.begin(), encoded_string.end(), '\n'), encoded_string.end());

	return encoded_string;

#else
	uint32_t size = 2048;
	encoded.resize(size);

	if (base64_encode(signature.data(), signature.size(), encoded.data(), reinterpret_cast<unsigned long *>(&size)) != CRYPT_OK)
	{
		throw "urlsafe_b64_encode: base64_encode error";
	}

	encoded.resize(size);

	for (size_t n = 0; n < encoded.size(); ++n)
	{
		if (encoded.at(n) == '+')
		{
			encoded.at(n) = '-';
		}
		else if (encoded.at(n) == '/')
		{
			encoded.at(n) = '_';
		}
	}


	return std::string(encoded.begin(), encoded.end());

#endif
}

size_t curl_writefunction(void * pointer, size_t size, size_t n, std::string * str)
{
	size_t new_size = size * n;
	size_t old_size = str->size();

	str->resize(new_size + old_size);

	std::copy(reinterpret_cast<char*>(pointer), reinterpret_cast<char*>(pointer) + new_size, str->begin() + old_size);
	return new_size;
}

std::unordered_map<std::string, std::string> gpsoauthclient::perform_auth_request(std::unordered_map<std::string, std::string> &data)
{
	curl_global_init(CURL_GLOBAL_ALL);
	
	CURL *curl = curl_easy_init();
	if (!curl)
	{
		curl_global_cleanup();
		return std::unordered_map<std::string, std::string>();
	}

	curl_easy_setopt(curl, CURLOPT_VERBOSE, true);
	curl_easy_setopt(curl, CURLOPT_URL, this->authurl.c_str());
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
	curl_easy_setopt(curl, CURLOPT_POST, 1);

	std::string post_argument = "";
	for (const std::pair<std::string, std::string> &p : data)
	{
		post_argument += "&" + p.first + "=" + p.second;
	}

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_argument.c_str());
	curl_easy_setopt(curl, CURLOPT_USERAGENT, this->useragent.c_str());

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); //only for https
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); //only for https

	std::string response;
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefunction);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

	if (curl_easy_perform(curl) != CURLE_OK) 
	{
		
		curl_easy_cleanup(curl);
		curl_global_cleanup();

		return std::unordered_map<std::string, std::string>();
	}


	curl_easy_cleanup(curl);
	curl_global_cleanup();

	auto parse_auth_request = [](const std::string &request)
	{
		std::unordered_map<std::string, std::string> auth_request;
		
		std::istringstream ss(request);
		std::string line;
		while (std::getline(ss, line))
		{
			size_t n = line.find_first_of('=');

			std::string key = line.substr(0, n);
			std::string value = line.substr(n + 1);

			auth_request[key] = value;
			
		}

		return auth_request;
	};

	return parse_auth_request(response);
}
