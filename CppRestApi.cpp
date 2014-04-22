#include <windows.h>
#include <winhttp.h>
#include "CppRestApi.h"
#include "../CheckLicenseValidTester/resource.h"

#include <sha.h>
#include <filters.h>
#include <rsa.h>
#include <osrng.h>
#include <gzip.h>
#include <base64.h>
#include <files.h>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>


#pragma comment(lib, "winhttp.lib")

/**
* Functions to give MultiByte strings to CryptoPP
*/
std::string to_mbstring(const std::wstring& input)
{
	return std::string(input.begin(), input.end());
}

std::wstring to_wstring(const std::string& input)
{
	return std::wstring(input.begin(), input.end());
}

CppLicensing::RestApi::ApiResult WinHttpAuthSample(CppLicensing::RestApi::SWinHttpSampleGet *pGetRequest, std::string& response)
{
	DWORD dwStatusCode = 0;
	DWORD dwSupportedSchemes;
	DWORD dwFirstScheme;
	DWORD dwTarget;
	DWORD dwLastStatus = 0;
	DWORD dwSize = sizeof(DWORD);
	BOOL  bResults = FALSE;
	BOOL  bDone = FALSE;

	CppLicensing::RestApi::ApiResult result = CppLicensing::RestApi::ApiResult::CPPL_API_SERVERUNREACHABLE;

	DWORD dwProxyAuthScheme = 0;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	LPSTR pszOutBuffer;
	DWORD dwDownloaded = 0;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"Software",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	INTERNET_PORT nPort = (pGetRequest->bUseSSL) ?
	INTERNET_DEFAULT_HTTPS_PORT :
								INTERNET_DEFAULT_HTTP_PORT;

	// Specify an HTTP server.
	if (hSession)
		hConnect = WinHttpConnect(hSession,
		pGetRequest->szServer.c_str(),
		nPort, 0);

	// Create an HTTP request handle.
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect,
		pGetRequest->szVerb.c_str(),
		pGetRequest->szPath.c_str(),
		NULL,
		WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		(pGetRequest->bUseSSL) ?
	WINHTTP_FLAG_SECURE : 0);

	// if already logged in with a token
	// Add a request header.
	if (hRequest && pGetRequest->szOAuthHeader.length() != 0)
	{
		std::wstring wszHeaders;
		wszHeaders.assign(pGetRequest->szOAuthHeader);
		wszHeaders.append(L"\r\n");
		wszHeaders.append(pGetRequest->szLicense64);

		bResults = WinHttpAddRequestHeaders(hRequest,
			wszHeaders.c_str(),
			(ULONG)-1L,
			WINHTTP_ADDREQ_FLAG_ADD);
	}
	else if (pGetRequest->szServerUsername.length() != 0)
	{
		std::string szBasicAuth64("");
		std::wstring wszBasicAuth(L"");
		wszBasicAuth.append(pGetRequest->szServerUsername);
		wszBasicAuth.append(L":");
		wszBasicAuth.append(pGetRequest->szServerPassword);

		std::string szBasicAuth("");
		szBasicAuth.assign(wszBasicAuth.begin(),wszBasicAuth.end());
		//Deactivate line breaks in base64 output!
		CryptoPP::StringSource(szBasicAuth, true, new CryptoPP::Base64Encoder(new
			CryptoPP::StringSink(szBasicAuth64), false));

		std::wstring wszHeaders(L"Authorization: Basic ");
		wszHeaders.append(szBasicAuth64.begin(),szBasicAuth64.end());

		bResults = WinHttpAddRequestHeaders(hRequest,
			wszHeaders.c_str(),
			(ULONG)-1L,
			WINHTTP_ADDREQ_FLAG_ADD);
	}
	
	// Continue to send a request until status code 
	// is not 401 or 407.
	if (hRequest == NULL)
		bDone = TRUE;

	while (!bDone)
	{
		//  If a proxy authentication challenge was responded to, reset
		//  those credentials before each SendRequest, because the proxy  
		//  may require re-authentication after responding to a 401 or  
		//  to a redirect. If you don't, you can get into a 
		//  407-401-407-401- loop.
		/*if (dwProxyAuthScheme != 0)
			bResults = WinHttpSetCredentials(hRequest,
			WINHTTP_AUTH_TARGET_SERVER,
			WINHTTP_AUTH_SCHEME_BASIC,
			pGetRequest->szServerUsername.c_str(),
			pGetRequest->szServerPassword.c_str(),
			NULL);*/
		// Send a request.
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS,
			0,
			WINHTTP_NO_REQUEST_DATA,
			0,
			0,
			0);

		// End the request.
		if (bResults)
			bResults = WinHttpReceiveResponse(hRequest, NULL);

		// Resend the request in case of 
		// ERROR_WINHTTP_RESEND_REQUEST error.
		if (!bResults && GetLastError() == ERROR_WINHTTP_RESEND_REQUEST)
			continue;

		// Continue to verify data until there is nothing left.
		if (bResults)
		do
		{
			// Verify available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				printf("Error %u in WinHttpQueryDataAvailable.\n",
				GetLastError());

			// Allocate space for the buffer.
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				printf("Out of memory\n");
				dwSize = 0;
			}
			else
			{
				// Read the Data.
				ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
					dwSize, &dwDownloaded))
					;// printf("Error %u in WinHttpReadData.\n", GetLastError());
				else
				{
					std::string szTemp(pszOutBuffer, dwDownloaded);
					response.append(szTemp);
					// printf("%s\n", pszOutBuffer);
				}

				// Free the memory allocated to the buffer.
				delete[] pszOutBuffer;
			}

		} while (dwSize > 0);


		// Check the status code.
		if (bResults)
		{
			dwSize = sizeof(dwStatusCode);
			bResults = WinHttpQueryHeaders(hRequest,
				WINHTTP_QUERY_STATUS_CODE |
				WINHTTP_QUERY_FLAG_NUMBER,
				NULL,
				&dwStatusCode,
				&dwSize,
				NULL);
		}

		if (bResults)
		{
			switch (dwStatusCode)
			{
			case 200:
				// The resource was successfully retrieved.
				// You can use WinHttpReadData to read the 
				// contents of the server's response.
				//printf("The resource was successfully retrieved.\n");
				bDone = TRUE;
				result = CppLicensing::RestApi::ApiResult::CPPL_API_200;
				break;
			case 401:
				// The server requires authentication.			
				bDone = TRUE;
				result = CppLicensing::RestApi::ApiResult::CPPL_API_401;
				break;
			case 403:
				result = CppLicensing::RestApi::ApiResult::CPPL_API_403;
				bDone = TRUE;
				break;
			case 407:
				// The proxy requires authentication.
				//printf("The proxy requires authentication.  Sending credentials...\n");

				// Obtain the supported and preferred schemes.
				bResults = WinHttpQueryAuthSchemes(hRequest,
					&dwSupportedSchemes,
					&dwFirstScheme,
					&dwTarget);

				// Set the credentials before resending the request.
				if (bResults)
					dwProxyAuthScheme = WINHTTP_AUTH_SCHEME_BASIC;

				// If the same credentials are requested twice, abort the
				// request.  For simplicity, this sample does not check 
				// for a repeated sequence of status codes.
				if (dwLastStatus == 407)
					bDone = TRUE;
				break;

			default:
				// The status code does not indicate success.
				//printf("Error. Status code %d returned.\n", dwStatusCode);
				bDone = TRUE;
			}
		}

		// Keep track of the last status code.
		dwLastStatus = dwStatusCode;

		// If there are any errors, break out of the loop.
		if (!bResults)
			bDone = TRUE;
	}

	// Report any errors.
	if (!bResults)
	{
		DWORD dwLastError = GetLastError();
		//printf("Error %d has occurred.\n", dwLastError);

		result = CppLicensing::RestApi::ApiResult::CPPL_API_SERVERUNREACHABLE;
	}

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return result;
}


/**
* Connects to the online licensing API to retrieve a fresh OAuth Token
*/
CppLicensing::RestApi::ApiResult GetOAuthToken(const std::wstring& wszEmail, const std::wstring& wszPassword, std::wstring& wszOAuthToken)
{
	std::string response("");

	//TODO
	//POST / token HTTP / 1.1
	//Host: server.example.com
	//Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
	//Content-Type: application/x-www-form-urlencoded
	
	//grant_type = client_credentials

	/*if (szEmail == "li0nel@github.com")
	{
		szOAuthToken.assign("a756334e3f491cec71eea4cc54730f706b53097c1511aa112e");
		return CppLicensing::RestApi::ApiResult::CPPL_API_200;
	}*/

	CppLicensing::RestApi::SWinHttpSampleGet oAuthRequest;
	oAuthRequest.bUseSSL = false;
	oAuthRequest.szServer = std::wstring(L"localhost");
	oAuthRequest.szPath = std::wstring(L"/oauthtoken");
	oAuthRequest.szOAuthHeader = std::wstring(L"");
	oAuthRequest.szLicense64 = std::wstring(L"");
	oAuthRequest.szVerb = std::wstring(L"POST");
	oAuthRequest.szServerPassword.assign(wszPassword);
	oAuthRequest.szProxyPassword.assign(wszPassword);
	oAuthRequest.szServerUsername.assign(wszEmail);
	oAuthRequest.szProxyUsername.assign(wszEmail);

	CppLicensing::RestApi::ApiResult result = WinHttpAuthSample(&oAuthRequest, response);

	//Extract OAuthToken from response
	boost::property_tree::ptree pt;
	std::istringstream isDecLicense(response);
	try {
		read_json(isDecLicense, pt);
		std::string sztoken(pt.get<std::string>("access_token"));
		wszOAuthToken.assign(sztoken.begin(),sztoken.end());

		std::string szError(pt.get<std::string>("error"));
		std::wstring wszError(szError.begin(), szError.end());
		if (!wszError.empty())
			MessageBox(NULL, wszError.c_str(), L"Error", 0); // not modal, not good, need to use cpprest design
	}
	catch (...)
	{
	}

	return result;
}

/**
* Connects to the online licensing API to retrieve a fresh license
* in a serialized and encoded format
*/
CppLicensing::RestApi::ApiResult CppLicensing::RestApi::GetOnlineLicense(const std::wstring& wszOAuthToken, std::wstring& wszEncLicense, const std::wstring& wszAppID)
{
	std::string szEncLicense64("");
	//Deactivate line breaks in base64 output!
	CryptoPP::StringSource(to_mbstring(wszEncLicense), true, new CryptoPP::Base64Encoder(new
		CryptoPP::StringSink(szEncLicense64), false));

	std::wstring wszEncLicense64;
	wszEncLicense64.assign(szEncLicense64.begin(), szEncLicense64.end());

	std::string response("");

	CppLicensing::RestApi::SWinHttpSampleGet oAuthRequest;
	oAuthRequest.bUseSSL = false;
	oAuthRequest.szServer = std::wstring(L"localhost");
	oAuthRequest.szPath = std::wstring(L"/licenses/").append(wszAppID);
	oAuthRequest.szOAuthHeader = std::wstring(L"Authorization: Bearer ").append(wszOAuthToken);
	oAuthRequest.szLicense64 = std::wstring(L"X-License: ").append(wszEncLicense64);
	oAuthRequest.szServerPassword = std::wstring(L"");
	oAuthRequest.szVerb = std::wstring(L"GET");
	oAuthRequest.szProxyPassword = std::wstring(L"");
	oAuthRequest.szServerUsername = std::wstring(L"");
	oAuthRequest.szProxyUsername = std::wstring(L"");

	CppLicensing::RestApi::ApiResult result = WinHttpAuthSample(&oAuthRequest, response);

	//Extract license from response
	boost::property_tree::ptree pt;
	std::istringstream isDecLicense(response);
	try {
		read_json(isDecLicense, pt);
		std::string szEncNewLicense64(pt.get<std::string>("License"));
		std::string szDecoded64;
		CryptoPP::StringSource(szEncNewLicense64, true, new CryptoPP::Base64Decoder(new
			CryptoPP::StringSink(szDecoded64)));

		wszEncLicense.assign(szDecoded64.begin(),szDecoded64.end());

		std::string szError(pt.get<std::string>("error"));
		std::wstring wszError(szError.begin(), szError.end());
		//if (!wszError.empty())
			//MessageBox(NULL, wszError.c_str(), L"Error", 0); // not modal, not good, need to use cpprest design
	}
	catch (...)
	{
	}

	return result;
}

void GetUserInput(HWND hWnd, int idInput, std::wstring& wszInputString)
{
	TCHAR lpszInput[256] = { 0 };
	WORD cchInput;

	// Get number of characters. 
	cchInput = (WORD)SendDlgItemMessage(hWnd,
		idInput,
		EM_LINELENGTH,
		(WPARAM)0,
		(LPARAM)0);

	// Put the number of characters into first word of buffer. 
	*((LPWORD)lpszInput) = cchInput; //Warning with unicode

	// Get the characters. 
	SendDlgItemMessage(hWnd,
		idInput,
		EM_GETLINE,
		(WPARAM)0,       // line 0 
		(LPARAM)lpszInput);

	// Null-terminate the string. 
	lpszInput[cchInput] = 0;
	wszInputString.assign(lpszInput);
}

INT_PTR CALLBACK LoginProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	static std::pair<std::wstring, std::wstring>* pwsz_TokenVolume;

	std::wstring wszPassword(L"");
	std::wstring wszEmail(L"");

	CppLicensing::RestApi::ApiResult result = CppLicensing::RestApi::ApiResult::CPPL_API_SERVERUNREACHABLE;

	switch (message)
	{
	case WM_INITDIALOG:
		pwsz_TokenVolume = reinterpret_cast<std::pair<std::wstring, std::wstring>*>(lParam);
		SetWindowText(GetDlgItem(hDlg, IDC_VOLUMEINFO), ((*pwsz_TokenVolume).second).c_str());
		return 1;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			SetWindowText(hDlg, L"Connecting...");
			ShowWindow(GetDlgItem(hDlg, IDC_ERROREMAIL), SW_HIDE);
			ShowWindow(GetDlgItem(hDlg, IDC_ERRORPASSWORD), SW_HIDE);

			GetUserInput(hDlg, IDC_PASSWORD, wszPassword);

			GetUserInput(hDlg, IDC_EMAIL, wszEmail);

			result = GetOAuthToken(wszEmail, wszPassword, ((*pwsz_TokenVolume).first));

			SetWindowText(hDlg, L"Login");

			switch (result)
			{
			case CppLicensing::RestApi::ApiResult::CPPL_API_SERVERUNREACHABLE:
				MessageBox(hDlg,L"Can not reach licensing server.\n\nPlease check your internet connection and retry.", L"Error",MB_OK);
				// Can not connect to the internet
				// User can connect to internet and retry
				// Or user must cancel to get out of login form
				return 0;
			case CppLicensing::RestApi::ApiResult::CPPL_API_401:
				ShowWindow(GetDlgItem(hDlg, IDC_ERRORPASSWORD), SW_SHOW);
				//Show error login here
				//Wrong email
				//Wrong password
				return 0;
			case CppLicensing::RestApi::ApiResult::CPPL_API_403:
				ShowWindow(GetDlgItem(hDlg, IDC_ERROREMAIL), SW_SHOW);
				//Show error login here
				//Forbidden access for user
				//EndDialog(hDlg, TRUE); //User banned ; but API should return OK and update with dummy license!
				return 0;
			case CppLicensing::RestApi::ApiResult::CPPL_API_200:
				//(*pwsz_TokenVolume).first.assign(wszOAuthToken);
				EndDialog(hDlg, TRUE);
				return 0;
			default:
				EndDialog(hDlg, FALSE);
				return 0;
			}
		case IDCANCEL:
			EndDialog(hDlg, FALSE);
			return 0;
		}
		return 0;
	}
	return FALSE;

	UNREFERENCED_PARAMETER(lParam);
}


/**
* Displays a form to gather user credentials
* Displays instructions to update the license manually
* returns OAuthToken
* returns true if login has been successful (200), false otherwise (cancel)
*/
bool CppLicensing::RestApi::UserLogin(std::wstring& wszOAuthToken, const std::wstring& wszVolumeInfo)
{
	std::pair<std::wstring, std::wstring> wsz_TokenVolume = std::make_pair(wszOAuthToken, wszVolumeInfo);

	int result = DialogBoxParam(GetModuleHandle(NULL),
		MAKEINTRESOURCE(IDD_DIALOG1),
		NULL,
		LoginProc,
		reinterpret_cast<LPARAM>(&wsz_TokenVolume)
		);

	wszOAuthToken.assign(wsz_TokenVolume.first);

	return result <= 0 ? false : true; //-1 means DialogBox failed to display the form
}