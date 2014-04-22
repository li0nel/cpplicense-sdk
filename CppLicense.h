/**
*	Useful functions for licensing
*
*	@author	Lionel Martin
*	@date	25/03/2014
*/

#include <string>
#include "boost/date_time/posix_time/posix_time.hpp" //include all types plus i/o
#include "boost/date_time/gregorian/gregorian.hpp" //include all types plus i/o

namespace CppLicense
{
	namespace Licensing
	{
		/**
		* Check whether a license is valid
		* @param bDisplayError true to display an error, false to exit
		* @param bExitIfInvalid true to exit if license invalid, false to return valid flag (true or false)
		* @return true if license is valid, false otherwise
		*/
		bool CheckLicenseValid(bool bDisplayError = true, bool bExitIfInvalid = true);

		/**
		* Application IDs
		*/
		enum ApplicationID
		{
			CPPL_APP_OLD
		};

		/**
		* Reg fields
		*/
		namespace LicenseSerializedField
		{
			static std::string CPPL_LICENSE_APPLICATIONID ( "ApplicationID" );
			static std::string CPPL_LICENSE_VOLUMEINFO ( "VolumeInfo" );
			static std::string CPPL_LICENSE_STARTDATE ( "StartDate" );
			static std::string CPPL_LICENSE_ENDDATE ( "EndDate" );
			static std::string CPPL_LICENSE_LASTUSAGEDATE ( "LastUsageDate" );
			static std::string CPPL_LICENSE_OAUTHTOKEN ( "OAuthToken" );
		}

		class License {
		public:
			/**
			* Constructor
			*/
			License();

			/**
			* Constructor
			*/
			License( const std::wstring& wszEncLicense, const std::wstring& wszEncInfo = std::wstring() ) :
				m_nApplicationID(CPPL_APP_OLD),
				m_wszVolumeInfo(L""),
				m_StartDate(boost::posix_time::second_clock::local_time()),
				m_EndDate(boost::posix_time::second_clock::local_time()),
				m_LastUsageDate(boost::posix_time::second_clock::local_time()),
				m_wszOAuthToken(L"")
			{
				Init(wszEncLicense, wszEncInfo);
			}

			/**
			* Destructor
			*/
			~License(){}

			/**
			* Get the application ID
			* @param id The application id
			*/
			ApplicationID GetApplicationID() { return m_nApplicationID; }

			/**
			* Get the VolumeInfo string
			*/
			std::wstring GetVolumeInfo() { return m_wszVolumeInfo; }
			void SetVolumeInfo(const std::wstring wszVolumeInfo) { m_wszVolumeInfo.assign(wszVolumeInfo); }

			/**
			* Get the StartDate
			*/
			boost::posix_time::ptime GetStartDate() { return m_StartDate; }

			/**
			* Get the EndDate
			*/
			boost::posix_time::ptime GetEndDate()  { return m_EndDate; }

			/**
			* Get the LastUsageDate
			*/
			boost::posix_time::ptime GetLastUsageDate()  { return m_LastUsageDate; }

			/**
			* Set the LastUsageDate
			*/
			void SetLastUsageDate(const boost::posix_time::ptime& date) { m_StartDate = date; }

			/**
			* Get the OAuth Token
			*/
			std::wstring GetOAuthToken() { return m_wszOAuthToken; }

			/**
			* Set the OAuth Token
			*/
			void SetOAuthToken(const std::wstring& wszOAuthToken) { m_wszOAuthToken.assign(wszOAuthToken); }

			/**
			* Write the current license in registry
			*/
			bool WriteLicense();
			
			std::wstring GetEncLicenseAsString();

			/**
			* Extract the current license from the registry in a .reg file for manual update
			* Calls GetSaveFileName for user to select where to save the .reg file
			*/
			bool ExportLicenseAsFile();

		private:
			/**
			* Init for constructors
			*/
			void Init(const std::wstring& wszEncLicense, const std::wstring& wszEncInfo);

			/**
			* The application ID
			*/
			ApplicationID m_nApplicationID;

			/**
			* Volume Info, decoded
			*/
			std::wstring m_wszVolumeInfo;

			/**
			* Start Date
			*/
			boost::posix_time::ptime m_StartDate;

			/**
			* End Date
			*/
			boost::posix_time::ptime m_EndDate;

			/**
			* Last Usage Date
			*/
			boost::posix_time::ptime m_LastUsageDate;

			/**
			* OAuth Token
			*/
			std::wstring m_wszOAuthToken;
		};

		/**
		* The application info
		*/
		class ApplicationInfo
		{
		public:
			/**
			* Destructor
			*/
			~ApplicationInfo();

			static void SetApplicationID(ApplicationID id) { m_nApplicationID = id;	}

			/**
			* Get the application ID
			* @return The application id
			*/
			static ApplicationID GetApplicationID() { return m_nApplicationID; };

			/**
			* Determine whether to raise an expiry warning
			* @return true to raise, false otherwise
			*/
			static bool RaiseExpiryWarning();

			/**
			* Determine whether to try a silent online license update
			* @return true to try, false otherwise
			*/
			static bool DoSilentLicenseUpdate();

			/**
			* Get the application name
			* @param appID The application ID
			* @return The application name
			*/
			static std::wstring GetApplicationName(const CppLicensing::Licensing::ApplicationID& appID);

			/**
			* Get the application registry key label
			* @param appID The application ID
			* @return The application registry key label
			*/
			static std::wstring GetApplicationRegKeyLabel(const CppLicensing::Licensing::ApplicationID& appID);

			/**
			* Get the application license file name
			* @param appID The application ID
			* @return The application license file name
			*/
			static std::wstring GetApplicationLicenseRequestFileName(const CppLicensing::Licensing::ApplicationID& appID);

			/**
			* Get VolumeInfo string for Windows
			*/
			static std::wstring GetVolumeInfo();

			static bool RemoveLicense();

		private:
			/**
			* Private Constructor
			*/
			ApplicationInfo();

			/**
			* The application ID
			*/
			static ApplicationID m_nApplicationID;

			/**
			* A flag indicating whether an expiry warning has been raised
			*/
			static bool m_bExpiryWarningRaised;

			/**
			* A flag indicating whether a silent online licensing update has been tried
			*/
			static bool m_bSilentLicenseUpdateTried;
		};

	}

	namespace Encryption
	{
		static std::string szAESKey("IdzPaIeJX1U1TO2v");
		static std::string szAESInitv("2iiub88whiYSBdj0");

		/**
		* Encrypt string
		*/
		std::wstring Encrypt(const std::wstring&);

		/**
		* Decrypt string
		*/
		std::wstring Decrypt(const std::wstring&);
	}
}