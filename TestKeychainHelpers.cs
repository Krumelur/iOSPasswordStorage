using System;
using NUnit.Framework;
using MonoTouch.Security;

namespace iOSPasswordStorage
{
	[TestFixture]
	public class TestKeychainHelpers
	{
		/// <summary>
		/// Tests setting a password.
		/// </summary>
		[Test]
		public void Test_10_SetPasswordForUsernameNotSyncable ()
		{
			var result = KeychainHelpers.SetPasswordForUsername ( "hallo@example.com", "my password", "myService", SecAccessible.Always, false );
			Assert.That(result == MonoTouch.Security.SecStatusCode.Success);
		}

		/// <summary>
		/// Tests getting a password.
		/// </summary>
		[Test]
		public void Test_20_GetPasswordForUsernameNotSyncable ()
		{
			var result = KeychainHelpers.GetPasswordForUsername ("hallo@example.com", "myService", false);
			Assert.That (result == "my password");
		}

		/// <summary>
		/// Tests deleting a password.
		/// </summary>
		[Test]
		public void Test_30_DeletePasswordForUsernameNotSyncable()
		{
			var result = KeychainHelpers.DeletePasswordForUsername ("hallo@example.com", "myService", false);
			Assert.That (result == SecStatusCode.Success);
		}

		/// <summary>
		/// Tests setting a password.
		/// </summary>
		[Test]
		public void Test_40_SetPasswordForUsernameSyncable ()
		{
			var result = KeychainHelpers.SetPasswordForUsername ( "hallo@example.com", "my password", "myService", SecAccessible.Always, true );
			Assert.That(result == MonoTouch.Security.SecStatusCode.Success);
		}

		/// <summary>
		/// Tests getting a password.
		/// </summary>
		[Test]
		public void Test_50_GetPasswordForUsernameSyncable ()
		{
			var result = KeychainHelpers.GetPasswordForUsername ("hallo@example.com", "myService", true);
			Assert.That (result == "my password");
		}

		/// <summary>
		/// Tests deleting a password.
		/// </summary>
		[Test]
		public void Test_60_DeletePasswordForUsernameSyncable()
		{
			var result = KeychainHelpers.DeletePasswordForUsername ("hallo@example.com", "myService", true);
			Assert.That (result == SecStatusCode.Success);
		}
	}
}
