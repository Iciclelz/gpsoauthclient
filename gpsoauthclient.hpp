#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

typedef std::pair<std::vector<uint8_t>, std::vector<uint8_t>> rsaparameter;

class gpsoauthclient
{
public:
	gpsoauthclient(const std::string &email, const std::string &password);
	~gpsoauthclient() noexcept;

	std::unordered_map<std::string, std::string> perform_master_login(
		const std::string &service = "ac2dm",
		const std::string &device_country = "us",
		const std::string &operator_country = "us",
		const std::string &lang = "en",
		int32_t sdk_version = 21);

	std::unordered_map<std::string, std::string> perform_oauth(
		const std::string &master_token,
		const std::string &service,
		const std::string &app,
		const std::string &client_signature,
		const std::string &device_country = "us",
		const std::string &operator_country = "us",
		const std::string &lang = "en",
		int32_t sdk_version = 21);

private:
	std::string base64_key;
	rsaparameter android_key;
	std::string version;
	std::string authurl;
	std::string useragent;

	std::string email;
	std::string password;

	rsaparameter google__key_from_b64(const std::string &base64_key);
	std::string google__create_signature(const std::string &email, const std::string &password, const rsaparameter &key);

	std::string urlsafe_b64_encode(const std::vector<uint8_t> &signature);

	std::unordered_map<std::string, std::string> perform_auth_request(const std::unordered_map<std::string, std::string> &data);
	
};

