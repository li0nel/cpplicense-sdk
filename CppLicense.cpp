#include <windows.h>
#include <system_error>
#include <tchar.h>
#include <utility>      // std::pair, std::make_pair

#include "CppLicense.h"
#include "CppRestApi.h"

#include <sha.h>
#include <filters.h>
#include <rsa.h>
#include <osrng.h>
#include <gzip.h>
#include <base64.h>
#include <files.h>
#include <modes.h>

#include <sstream>
#include <fstream> 
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#pragma comment (lib,"cryptlibD.lib")
#pragma comment (lib,"boost_date_time-vc120-mt-1_55.lib")


CppLicense::Licensing::ApplicationID CppLicense::Licensing::ApplicationInfo::m_nApplicationID = CppLicense::Licensing::ApplicationID::CPPL_APP_OLD;
bool CppLicense::Licensing::ApplicationInfo::m_bExpiryWarningRaised = false;
bool CppLicense::Licensing::ApplicationInfo::m_bSilentLicenseUpdateTried = false;

HANDLE argumentCopied = NULL;


/**
* Encrypt string
*/
std::wstring CppLicense::Encryption::Encrypt(const std::wstring& input)
{
	if (input.length() == 0)
		return std::wstring(L"");

	std::string output("");

	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH + 1];
	memset(key, 0, sizeof(key));
	strcpy((char*)key, szAESKey.c_str());// "testlmatestlmate");

	byte iv[CryptoPP::AES::BLOCKSIZE + 1];
	memset(iv, 0, sizeof(iv));
	strcpy((char*)iv, szAESInitv.c_str());// "iviviviviviviviv");

	CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(output));

	std::string szInput(input.begin(), input.end());
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(szInput.c_str()), szInput.length() + 1);
	stfEncryptor.MessageEnd();

	return to_wstring(output);

	
	/*CryptoPP::StringSource privStr(m_szPrivateKey, true, new CryptoPP::Base64Decoder);
	CryptoPP::RSAES_OAEP_SHA_Decryptor priv(privStr);
	CryptoPP::RSAES_OAEP_SHA_Encryptor pub(priv);
	CryptoPP::AutoSeededRandomPool rand_pool;
	
	// Encrypt
	std::string szEncInfo;
	int nIndex = 0, nSectionSize(64), nLength(input.length());
	bool bAbort(false);
	while (!bAbort)
	{
		if (nIndex + nSectionSize > nLength)
		{
			nSectionSize = nLength - nIndex;
			bAbort = true;
		}

		std::string szEncCurrentDateSection("");

		try {

			CryptoPP::StringSource(input.substr(nIndex, nSectionSize), true,
				new CryptoPP::PK_EncryptorFilter(rand_pool, pub,
				new CryptoPP::StringSink(szEncCurrentDateSection)));
		}
		catch (const std::exception & ex)
		{
			MessageBox(NULL, ex.what(), "debug", MB_OK);
		}

		output.append(szEncCurrentDateSection);

		nIndex += nSectionSize;
	}

	nIndex = output.length();*/
}

/**
* Decrypt string
*/
std::wstring CppLicense::Encryption::Decrypt(const std::wstring& input)
{
	if (input.length() == 0)
		return std::wstring(L"");

	std::string output;
	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH + 1];
	memset(key, 0, sizeof(key));
	strcpy((char*)key, szAESKey.c_str());// "testlmatestlmate");

	byte iv[CryptoPP::AES::BLOCKSIZE + 1];
	memset(iv, 0, sizeof(iv));
	strcpy((char*)iv, szAESInitv.c_str());// "iviviviviviviviv");

	CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(output));

	std::string szInput(input.begin(), input.end());
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(szInput.c_str()), szInput.size());
	stfDecryptor.MessageEnd();

	return to_wstring(output.substr(0, output.find('}')+1));

	/*
	std::string output("");

	// Create a decryptor
	CryptoPP::StringSource privStr(CppLicense::Encryption::m_szPrivateKey, true, new CryptoPP::Base64Decoder);
	CryptoPP::RSAES_OAEP_SHA_Decryptor priv(privStr);

	CryptoPP::AutoSeededRandomPool rand_pool1;
	int nIndex = 0, nSectionSize(128), nLength(input.length());
	bool bAbort(false);
	while (!bAbort)
	{
		if (nIndex + nSectionSize >= nLength)
		{
			nSectionSize = nLength - nIndex;
			bAbort = true;
		}

		std::string szLicenseSection;
		CryptoPP::StringSource(input.substr(nIndex, nSectionSize), true,
			new CryptoPP::PK_DecryptorFilter(rand_pool1, priv,
			new CryptoPP::StringSink(szLicenseSection)));

		output.append(szLicenseSection);

		nIndex += nSectionSize;
	}

	return output;*/
}

std::wstring CppLicense::Licensing::License::GetEncLicenseAsString()
{
	//License
	boost::property_tree::ptree pt;
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_APPLICATIONID, int(m_nApplicationID));
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_VOLUMEINFO, to_mbstring(m_wszVolumeInfo));
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_STARTDATE, m_StartDate);
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_ENDDATE, m_EndDate);

	std::ostringstream serializedLicense;
	write_json(serializedLicense, pt, false);
	std::wstring wszDecLicense = to_wstring(serializedLicense.str());
	wszDecLicense.assign(wszDecLicense.substr(0, wszDecLicense.find('}') + 1));
	std::wstring wszEncLicense = CppLicense::Encryption::Encrypt(wszDecLicense);

	return wszEncLicense;
}

bool CppLicense::Licensing::License::WriteLicense() //to be modified ; lib should only be able to READ License (RSA) and READ/WRITE info (AES)
{
	SetLastUsageDate(boost::posix_time::second_clock::local_time());

	//License
	boost::property_tree::ptree pt;
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_APPLICATIONID, int(m_nApplicationID));
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_VOLUMEINFO, to_mbstring(m_wszVolumeInfo));
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_STARTDATE, m_StartDate);
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_ENDDATE, m_EndDate);

	std::ostringstream serializedLicense;
	write_json(serializedLicense, pt, false);
	std::wstring wszDecLicense = to_wstring(serializedLicense.str());
	std::wstring wszEncLicense = CppLicense::Encryption::Encrypt(wszDecLicense);

	//Info
	boost::property_tree::ptree pt2;
	pt2.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_LASTUSAGEDATE, m_LastUsageDate);
	pt2.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_OAUTHTOKEN, to_mbstring(m_wszOAuthToken));

	std::ostringstream serializedInfo;
	write_json(serializedInfo, pt2, false);
	std::wstring wszDecInfo = to_wstring(serializedInfo.str());
	std::wstring wszEncInfo = CppLicense::Encryption::Encrypt(wszDecInfo);

	//Install
	HKEY hKey;
	LONG returnStatus, returnStatus1, returnStatus2;
	DWORD dwType = REG_SZ;
	DWORD dwSize2 = 255;

	std::wstring wszAppRegKey = CppLicense::Licensing::ApplicationInfo::GetApplicationRegKeyLabel(GetApplicationID());

	returnStatus = RegCreateKeyEx(
		HKEY_CURRENT_USER,
		wszAppRegKey.c_str(),
		0,
		NULL,
		0,
		KEY_WRITE,
		NULL,
		&hKey,
		NULL);

	if (returnStatus == ERROR_SUCCESS)
	{
		returnStatus1 = RegSetValueExA(
			hKey,
			("License"),
			NULL,
			REG_BINARY,
			(LPBYTE)to_mbstring(wszEncLicense).c_str(),
			to_mbstring(wszEncLicense).length());

		returnStatus2 = RegSetValueExA(
			hKey,
			("Info"),
			NULL,
			REG_BINARY,
			(LPBYTE)to_mbstring(wszEncInfo).c_str(),
			to_mbstring(wszEncInfo).length());


		RegCloseKey(hKey);

		if (returnStatus1 == ERROR_SUCCESS && returnStatus2 == ERROR_SUCCESS)
		{
			return true;
		}

		return false;
	}

	RegCloseKey(hKey);
	return false;
}

/**
* Init for constructors
*/
void CppLicense::Licensing::License::Init(const std::wstring& wszEncLicense, const std::wstring& wszEncInfo)
{
	std::wstring wszDecLicense(CppLicense::Encryption::Decrypt(wszEncLicense));
	std::wstring wszDecInfo(CppLicense::Encryption::Decrypt(wszEncInfo));

	if (wszDecLicense.length() != 0)
	{
		//License
		boost::property_tree::ptree pt;
		std::istringstream isDecLicense(to_mbstring(wszDecLicense)); //todo TRY CATCH HERE
		read_json(isDecLicense, pt);

		m_nApplicationID = static_cast<CppLicense::Licensing::ApplicationID>(pt.get<int>(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_APPLICATIONID));
		m_wszVolumeInfo = to_wstring(pt.get<std::string>(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_VOLUMEINFO));
		m_StartDate = pt.get<boost::posix_time::ptime>(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_STARTDATE);
		m_EndDate = pt.get<boost::posix_time::ptime>(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_ENDDATE);
	}

	if (wszDecInfo.length() != 0)
	{
		//Info
		boost::property_tree::ptree pt2;
		std::istringstream isDecInfo(to_mbstring(wszDecInfo));
		read_json(isDecInfo, pt2);

		m_LastUsageDate = pt2.get<boost::posix_time::ptime>(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_LASTUSAGEDATE);
		m_wszOAuthToken = to_wstring(pt2.get<std::string>(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_OAUTHTOKEN));
	}
}

/**
* Constructor
*/
CppLicense::Licensing::License::License() :
	m_nApplicationID(CPPL_APP_OLD),
	m_wszVolumeInfo(L""),
	m_StartDate(),
	m_EndDate(),
	m_LastUsageDate(),
	m_wszOAuthToken(L"")
{
	// Load the license
	HKEY hKey;
	LONG returnStatus, returnStatus1, returnStatus2;
	DWORD dwType = REG_SZ;
	DWORD dwSize1 = 512, dwSize2 = 512; //WARNING, error 234

	std::wstring wszEncLicense(L"");
	std::wstring wszEncInfo(L"");

	CppLicense::Licensing::ApplicationID n_ApplicationID = CppLicense::Licensing::ApplicationInfo::GetApplicationID();
	std::wstring wszAppRegKey = CppLicense::Licensing::ApplicationInfo::GetApplicationRegKeyLabel(n_ApplicationID);

	returnStatus = RegOpenKey(
		HKEY_CURRENT_USER,
		wszAppRegKey.c_str(),
		&hKey);

	if (returnStatus == ERROR_SUCCESS)
	{
		char pszReturnVal1[512], pszReturnVal2[512];
		memset(pszReturnVal1,0,sizeof(pszReturnVal1));
		memset(pszReturnVal2, 0, sizeof(pszReturnVal2));

		returnStatus1 = RegQueryValueExA(
			hKey,
			"License",
			NULL,
			&dwType,
			(LPBYTE)&pszReturnVal1,
			&dwSize1);

		returnStatus2 = RegQueryValueExA(
			hKey,
			"Info",
			NULL,
			&dwType,
			(LPBYTE)&pszReturnVal2,
			&dwSize2);

		RegCloseKey(hKey);

		if (returnStatus1 == ERROR_SUCCESS && returnStatus2 == ERROR_SUCCESS)
		{
			wszEncLicense = to_wstring(std::string(pszReturnVal1, dwSize1));
			wszEncInfo = to_wstring(std::string(pszReturnVal2, dwSize2));
		}
		else if (returnStatus1 == ERROR_FILE_NOT_FOUND && returnStatus2 == ERROR_FILE_NOT_FOUND)
			throw "license not found"; //first launch or license removed ; exception will force login
		else
			throw "error";
	}
	else
	{
		RegCloseKey(hKey);
		throw "license not found";
	}

	Init(wszEncLicense, wszEncInfo);
}


/**
* Silently tries to update the client-side license with the server-side license
* Asynchronous. Does not block neither the main thread nor the user software
*/
void WINAPI SilentLicenseUpdateThread(LPVOID param)
{
	std::pair<std::wstring, std::wstring>* ppwsz_TokenLicense(static_cast<std::pair<std::wstring, std::wstring>*>(param));
	std::pair<std::wstring, std::wstring> pwsz_TokenLicense(*ppwsz_TokenLicense);
	std::wstring wszOAuthToken(pwsz_TokenLicense.first);
	std::wstring wszEncLicense(pwsz_TokenLicense.second);
	SetEvent(argumentCopied); //Release main thread, eventually updates the license asynchronously

	std::wostringstream ws;
	ws << CppLicense::Licensing::ApplicationInfo::GetApplicationID();
	const std::wstring wszAppID(ws.str());
	if (CppLicense::RestApi::GetOnlineLicense(wszOAuthToken, wszEncLicense, wszAppID))
	{
		try {
			CppLicense::Licensing::License * newLicense = new CppLicense::Licensing::License(wszEncLicense);

			if (newLicense != NULL)
			{
				newLicense->SetOAuthToken(wszOAuthToken);
				newLicense->WriteLicense();
			}
		}
		catch (...) {}
	}
}

bool CreateDummyLicense()
{
	//License
	boost::property_tree::ptree pt;
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_APPLICATIONID, int(CppLicense::Licensing::ApplicationInfo::GetApplicationID()));
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_VOLUMEINFO, to_mbstring(CppLicense::Licensing::ApplicationInfo::GetVolumeInfo()));
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_STARTDATE, boost::posix_time::second_clock::local_time() - boost::gregorian::days(5));
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_ENDDATE, boost::posix_time::second_clock::local_time() - boost::gregorian::days(5));

	std::ostringstream serializedLicense;
	write_json(serializedLicense, pt, false);
	std::wstring wszDecLicense = to_wstring(serializedLicense.str());
	std::wstring wszEncLicense = CppLicense::Encryption::Encrypt(wszDecLicense);
	//std::string szDecLicense = to_mbstring(CppLicense::Encryption::Decrypt(wszEncLicense));

	//Info
	boost::property_tree::ptree pt2;
	pt2.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_LASTUSAGEDATE, boost::posix_time::second_clock::local_time());
	pt2.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_OAUTHTOKEN, std::string("dummy license token :-)"));

	std::ostringstream serializedInfo;
	write_json(serializedInfo, pt2, false);
	std::wstring wszDecInfo = to_wstring(serializedInfo.str());
	std::wstring wszEncInfo = CppLicense::Encryption::Encrypt(wszDecInfo);

	//Install
	HKEY hKey;
	LONG returnStatus, returnStatus1, returnStatus2;
	DWORD dwType = REG_SZ;
	DWORD dwSize2 = 255;

	std::wstring wszAppRegKey = CppLicense::Licensing::ApplicationInfo::GetApplicationRegKeyLabel(CppLicense::Licensing::ApplicationInfo::GetApplicationID());

	returnStatus = RegCreateKeyEx(
		HKEY_CURRENT_USER,
		wszAppRegKey.c_str(),
		0,
		NULL,
		0,
		KEY_WRITE,
		NULL,
		&hKey,
		NULL);

	if (returnStatus == ERROR_SUCCESS)
	{
		returnStatus1 = RegSetValueExA(
			hKey,
			("License"),
			NULL,
			REG_BINARY,
			(LPBYTE)to_mbstring(wszEncLicense).c_str(),
			to_mbstring(wszEncLicense).length());

		returnStatus2 = RegSetValueExA(
			hKey,
			("Info"),
			NULL,
			REG_BINARY,
			(LPBYTE)to_mbstring(wszEncInfo).c_str(),
			to_mbstring(wszEncInfo).length());

		RegCloseKey(hKey);

		if (returnStatus1 == ERROR_SUCCESS && returnStatus2 == ERROR_SUCCESS)
			return true;
		else
			return false;
	}

	RegCloseKey(hKey);
	return false;
}

/**
* Check whether a license is valid
* @param bDisplayError true to display an error, false to exit
* @param bExitIfInvalid true to exit if license invalid, false to return valid flag (true or false)
* @return true if license is valid, false otherwise
*/
bool CppLicense::Licensing::CheckLicenseValid(bool bDisplayError, bool bExitIfInvalid)
{
	try
	{
		CppLicense::Licensing::License * license = NULL;
		try
		{
			license = new CppLicense::Licensing::License();
		}
		catch (char const* exceptStr)
		{
			if (exceptStr == "license not found")
			{
				//Just install dummy license to have proper VolumeInfo sent
				if (!CreateDummyLicense())
					throw;
				else
					return CheckLicenseValid(bDisplayError, bExitIfInvalid);
			}
			else
				throw;
		}
		
		if ( license == NULL )
		{
			if (bDisplayError)
			{
				MessageBox(NULL, L"The license can not be read.", L"Error", MB_OK);
				return false;
			}
			else
			{
				if (bExitIfInvalid) exit(0); // abort application
				return false;
			}
		}

		// Check the current application ID
		if (license->GetApplicationID() != CppLicense::Licensing::ApplicationInfo::GetApplicationID())
		{
			if (bDisplayError)
			{
				MessageBox(NULL, L"The installed license is not valid for this application.", L"Error", MB_OK);
				return false;
			}
			else
			{
				if (bExitIfInvalid) exit(0); // abort application
				return false;
			}
		}

		// Check Volume Info
		if (license->GetVolumeInfo() != CppLicense::Licensing::ApplicationInfo::GetVolumeInfo())
		{
			if (bDisplayError)
			{
				MessageBox(NULL, L"The license is not valid for this machine. Please contact vendor for a valid license.", L"Error", MB_OK);
				return false;
			}
			else
			{
				if (bExitIfInvalid) exit(0); // abort application
				return false;
			}
		}

		// Compare dates
		boost::posix_time::ptime today(boost::posix_time::second_clock::local_time());
		if (today < license->GetStartDate() || today > license->GetEndDate() || today < license->GetLastUsageDate())
		{
			if (bDisplayError)
			{
				std::wstring wszTempToken(L"");

				//license->ExportLicenseAsFile();
				if (CppLicense::RestApi::UserLogin(wszTempToken, license->GetVolumeInfo())) //force login / maual update to renew license
				{
					std::wstring wszEncLicense(license->GetEncLicenseAsString());
					license->SetOAuthToken(wszTempToken); // could write here the license with updated OAuthToken
					std::wostringstream ws;
					ws << CppLicense::Licensing::ApplicationInfo::GetApplicationID();
					const std::wstring wszAppID(ws.str());
					if (CppLicense::RestApi::GetOnlineLicense(wszTempToken, wszEncLicense, wszAppID))
					{
						CppLicense::Licensing::License * newLicense = new CppLicense::Licensing::License(wszEncLicense);
						if ( newLicense != NULL )
						{
							newLicense->SetOAuthToken(wszTempToken);
							newLicense->WriteLicense();
							return CheckLicenseValid(true, true);
						}
						else
							return false;
					}
					else
						return false;
				}
				else
					return false;
			}
			else
			{
				if (bExitIfInvalid) exit(0); // abort application
				return false;
			}
		}

		license->WriteLicense(); //Update last usage date
		
		boost::gregorian::days fiveDays(5);
		boost::gregorian::days tenDays(10);
		if ((license->GetEndDate() - fiveDays) < today && bDisplayError && CppLicense::Licensing::ApplicationInfo::RaiseExpiryWarning())
		{
			std::wstring wszTempToken(L"");

			//license->ExportLicenseAsFile();
			if (CppLicense::RestApi::UserLogin(wszTempToken, license->GetVolumeInfo())) // propose login / maual update to renew license
			{
				license->SetOAuthToken(wszTempToken);
				std::wstring wszEncLicense(license->GetEncLicenseAsString());
				std::wostringstream ws;
				ws << CppLicense::Licensing::ApplicationInfo::GetApplicationID();
				const std::wstring wszAppID(ws.str());
				if (CppLicense::RestApi::GetOnlineLicense(wszTempToken, wszEncLicense, wszAppID))
				{
					CppLicense::Licensing::License * newLicense = new CppLicense::Licensing::License(wszEncLicense);
					if (newLicense != NULL)
					{
						newLicense->SetOAuthToken(wszTempToken);
						newLicense->WriteLicense();
						return CheckLicenseValid(true, true);
					}
				}
			}
		}
		else if ((license->GetEndDate() - tenDays) < today && CppLicense::Licensing::ApplicationInfo::DoSilentLicenseUpdate())
		// if OAuth token is empty, just wait for the 5 days limit to show login form
		// just try this once for every app launch, no need to retry if it failed the first time (no internet connection)
		{
			std::pair<std::wstring, std::wstring> pwsz_TokenLicense = std::make_pair(license->GetOAuthToken(),license->GetEncLicenseAsString());
			// Creates a silent license update thread
			DWORD dwThread = 0;

			argumentCopied = CreateEvent(
				NULL,               // default security attributes
				TRUE,               // manual-reset event
				FALSE,              // initial state is nonsignaled
				TEXT("argumentCopied")  // object name
				);

			if (argumentCopied != NULL)
			{
				CreateThread(NULL,
					0L,
					(LPTHREAD_START_ROUTINE)SilentLicenseUpdateThread,
					(LPVOID)&pwsz_TokenLicense,
					0L,
					&dwThread);

				WaitForSingleObject(argumentCopied, INFINITE);
				CloseHandle(argumentCopied);
			}
		}

		return true;
	}
	catch ( const std::exception & ex )
	{
		if (bDisplayError)
		{
#ifdef _DEBUG
			MessageBoxA(NULL, ex.what(), "debug", 0);
#else
			MessageBox(NULL, L"License cannot be validated.", L"Error", MB_OK);
#endif

			//clean if corrupted ; that will force login
			CppLicense::Licensing::ApplicationInfo::RemoveLicense();
			return false;
		}
		else
		{
			if (bExitIfInvalid) exit(0); // abort application
			return false;
		}
	}
}

std::wstring CppLicense::Licensing::ApplicationInfo::GetApplicationRegKeyLabel(const CppLicense::Licensing::ApplicationID& appID)
{
	std::wstring wszAppRegKey(L"");

	// License is valid so update info on server
	switch (appID)
	{
	default:
		wszAppRegKey = L"Software\\VendorXXX\\SoftwareXXX";
		break;
	}

	return wszAppRegKey;
}

bool CppLicense::Licensing::ApplicationInfo::DoSilentLicenseUpdate()
{
	// Only try to do a silent online license update once

	if (!m_bSilentLicenseUpdateTried)
	{
		m_bSilentLicenseUpdateTried = true;

		return true;
	}
	else
		return false;
}

bool CppLicense::Licensing::ApplicationInfo::RaiseExpiryWarning()
{
	// Raise the expiry warning once only

	if (!m_bExpiryWarningRaised)
	{
		m_bExpiryWarningRaised = true;

		return true;
	}
	else
		return false;
}

std::wstring CppLicense::Licensing::ApplicationInfo::GetVolumeInfo()
{
	std::wstring wszVolumeInfo;

	TCHAR volumeName[MAX_PATH + 1] = { 0 };
	TCHAR fileSystemName[MAX_PATH + 1] = { 0 };
	DWORD serialNumber = 0;
	DWORD maxComponentLen = 0;
	DWORD fileSystemFlags = 0;

	if (GetVolumeInformation(
		TEXT("C:\\"),
		volumeName,
		ARRAYSIZE(volumeName),
		&serialNumber,
		&maxComponentLen,
		&fileSystemFlags,
		fileSystemName,
		ARRAYSIZE(fileSystemName)))
	{
		std::wostringstream oss;
		oss << serialNumber << fileSystemName << maxComponentLen;
		wszVolumeInfo = oss.str();
	}

	return wszVolumeInfo;
}

/**
* Extract the current license from the registry in a .reg file for manual update
* Calls GetSaveFileName for user to select where to save the .reg file
*/
bool CppLicense::Licensing::License::ExportLicenseAsFile()
{
	//Do not use RegSaveKey, need administrator privileges
	
	//License
	boost::property_tree::ptree pt;
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_APPLICATIONID, int(m_nApplicationID));
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_VOLUMEINFO, to_mbstring(m_wszVolumeInfo));
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_STARTDATE, m_StartDate);
	pt.put(CppLicense::Licensing::LicenseSerializedField::CPPL_LICENSE_ENDDATE, m_EndDate);

	std::ostringstream serializedLicense;
	write_json(serializedLicense, pt, false);
	std::wstring wszDecLicense = to_wstring(serializedLicense.str());
	std::wstring wszEncLicense = CppLicense::Encryption::Encrypt(wszDecLicense);

	CppLicense::Licensing::License* newLicense = new CppLicense::Licensing::License(wszEncLicense);
	//newLicense->WriteLicense();

	std::ostringstream ossFilename;
	ossFilename << "License_" << m_nApplicationID << ".reg";

	std::fstream fsReg;
	fsReg.open(ossFilename.str().c_str(), std::fstream::out | std::fstream::binary | std::fstream::trunc);
	fsReg << "Windows Registry Editor Version 5.00";
	fsReg << std::endl;
	fsReg << "[HKEY_CURRENT_USER\\" << to_mbstring(CppLicense::Licensing::ApplicationInfo::GetApplicationRegKeyLabel(GetApplicationID())) << "]";
	fsReg << std::endl;
	fsReg << "\"License\"=hex:";
	
	std::string szEncLicense(wszEncLicense.begin(), wszEncLicense.end());
	std::vector<unsigned char> bytes(szEncLicense.begin(), szEncLicense.end());

	for (std::vector<unsigned char>::iterator it = bytes.begin(); it != bytes.end(); ++it)
	{
		fsReg << std::hex << std::setw(2) << std::setfill('0') << int(*it);
		if (it+1 != bytes.end())
			fsReg << ",";
	}

	fsReg.close();

	return true;
}

bool CppLicense::Licensing::ApplicationInfo::RemoveLicense()
{
	bool bRemoved(false);

	HKEY hKey;
	LONG returnStatus, returnStatus1, returnStatus2;

	std::wstring wszAppRegKey = CppLicense::Licensing::ApplicationInfo::GetApplicationRegKeyLabel(CppLicense::Licensing::ApplicationInfo::GetApplicationID());

	returnStatus = RegOpenKeyEx(
		HKEY_CURRENT_USER,
		wszAppRegKey.c_str(),
		NULL,
		KEY_WRITE,
		&hKey);

	if (returnStatus == ERROR_SUCCESS)
	{
		returnStatus1 = RegDeleteValue(
			hKey,
			_T("License"));

		returnStatus2 = RegDeleteValue(
			hKey,
			_T("Info"));

		if (returnStatus1 == ERROR_SUCCESS && returnStatus2 == ERROR_SUCCESS)
		{
			bRemoved = true;
		}
	}

	RegCloseKey(hKey);

	return bRemoved;
}