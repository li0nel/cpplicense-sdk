/**
*	Useful functions for connecting to licensing API
*
*	@author	Lionel Martin
*	@date	1/04/2014
*/
#include <string>

namespace CPPL
{
	namespace RestApi
	{
		enum ApiResult 
		{
			CPPL_API_LOGINCANCEL,
			CPPL_API_200,
			CPPL_API_401,
			CPPL_API_403,
			CPPL_API_SERVERUNREACHABLE
		};

		/**
		* Structure for Wininet HTTP request
		*/
		struct SWinHttpSampleGet
		{
			std::wstring szServer;
			std::wstring szPath;
			BOOL bUseSSL;
			std::wstring szVerb;
			std::wstring szServerUsername;
			std::wstring szServerPassword;
			std::wstring szProxyUsername;
			std::wstring szProxyPassword;
			std::wstring szOAuthHeader;
			std::wstring szLicense64;
		};

		/**
		* Connects to the online licensing API to retrieve a fresh license
		* in a serialized and encoded format
		*/
		ApiResult GetOnlineLicense(const std::wstring& wszOAuthToken, std::wstring& wszEncLicense, const std::wstring& wszAppID);

		/**
		* Show user a login dialog box
		* Returns true if user has successfully logged in, false otherwise
		*/
		bool UserLogin(std::wstring& wszOAuthToken, const std::wstring& wszVolumeInfo);
	}
}


std::string to_mbstring(const std::wstring& input);

std::wstring to_wstring(const std::string& input);

