using System;
using MonoTouch.Foundation;
using MonoTouch.Security;
using System.IO;
using MonoTouch.UIKit;

namespace iOSPasswordStorage
{
	public static class KeychainHelpers
	{
		/// <summary>
		/// Deletes a username/password record.
		/// </summary>
		/// <param name="sUsername">the username to query. May not be NULL.</param>
		/// <param name="sService">the service description to query. May not be NULL.</param>
		/// <returns>SecStatusCode.Success if everything went fine, otherwise some other status</returns>
		public static SecStatusCode DeletePasswordForUsername ( string sUsername, string sService )
		{
			if ( sUsername == null )
			{
				throw new ArgumentNullException ( "sUserName" );
			}
			
			if ( sService == null )
			{
				throw new ArgumentNullException ( "sService" );
			}
			
			// Querying is case sesitive - we don't want that.
			sUsername = sUsername.ToLower (  );
			sService = sService.ToLower (  );
			
			// Query and remove.
			SecRecord oQueryRec = new SecRecord ( SecKind.GenericPassword ) { Service = sService, Label = sService, Account = sUsername };
			SecStatusCode eCode = SecKeyChain.Remove ( oQueryRec );
			
			return eCode;
		}

		/// <summary>
		/// Sets a password for a specific username.
		/// </summary>
		/// <param name="sUsername">the username to add the password for. May not be NULL.</param>
		/// <param name="sPassword">the password to associate with the record. May not be NULL.</param>
		/// <param name="sService">the service description to use. May not be NULL.</param>
		/// <param name="eSecAccessible">defines how the keychain record is protected</param>
		/// <returns>SecStatusCode.Success if everything went fine, otherwise some other status</returns>
		public static SecStatusCode SetPasswordForUsername ( string sUsername, string sPassword, string sService, SecAccessible eSecAccessible )
		{
			if ( sUsername == null ) {
				throw new ArgumentNullException ( "sUserName" );
			}
			
			if ( sService == null ) {
				throw new ArgumentNullException ( "sService" );
			}
			
			if ( sPassword == null ) {
				throw new ArgumentNullException ( "sPassword" );
			}
			
			// Querying is case sesitive - we don't want that.
			sUsername = sUsername.ToLower (  );
			sService = sService.ToLower (  );
			
			// Don't bother updating. Delete existing record and create a new one.
			DeletePasswordForUsername ( sUsername, sService );
			
			// Create a new record.
			// Store password UTF8 encoded.
			SecStatusCode eCode = SecKeyChain.Add ( new SecRecord ( SecKind.GenericPassword ) {
				Service = sService,
				Label = sService,
				Account = sUsername,
				Generic = NSData.FromString ( sPassword, NSStringEncoding.UTF8 ),
				Accessible = eSecAccessible
			} );
			
			return eCode;
		}

		/// <summary>
		/// Gets a password for a specific username.
		/// </summary>
		/// <param name="sUsername">the username to query. May not be NULL.</param>
		/// <param name="sService">the service description to use. May not be NULL.</param>
		/// <returns>
		/// The password or NULL if no matching record was found.
		/// </returns>
		public static string GetPasswordForUsername ( string sUsername, string sService )
		{
			if ( sUsername == null )
			{
				throw new ArgumentNullException ( "sUserName" );
			}
			
			if ( sService == null )
			{
				throw new ArgumentNullException ( "sService" );
			}
			
			// Querying is case sesitive - we don't want that.
			sUsername = sUsername.ToLower (  );
			sService = sService.ToLower (  );
			
			SecStatusCode eCode;
			// Query the record.
			SecRecord oQueryRec = new SecRecord ( SecKind.GenericPassword ) { Service = sService, Label = sService, Account = sUsername };
			oQueryRec = SecKeyChain.QueryAsRecord ( oQueryRec, out eCode );
			
			// If found, try to get password.
			if ( eCode == SecStatusCode.Success && oQueryRec != null && oQueryRec.Generic != null )
			{
				// Decode from UTF8.
				return NSString.FromData ( oQueryRec.Generic, NSStringEncoding.UTF8 );
			}
			
			// Something went wrong.
			return null;
		}
	}
}

