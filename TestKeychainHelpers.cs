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
		public void Test_10_SetPasswordForUsername ()
		{
			var result = KeychainHelpers.SetPasswordForUsername ( "hallo@test.com", "my password", "myService", SecAccessible.Always );
			Assert.That(result == MonoTouch.Security.SecStatusCode.Success);
		}

		/// <summary>
		/// Tests getting a password.
		/// </summary>
		[Test]
		public void Test_20_GetPasswordForUsername ()
		{
			var result = KeychainHelpers.GetPasswordForUsername ("hallo@test.com", "myService");
			Assert.That (result == "my password");
		}

		/// <summary>
		/// Tests deleting a password.
		/// </summary>
		[Test]
		public void Test_30_DeletePasswordForUsername()
		{
			var result = KeychainHelpers.DeletePasswordForUsername ("hallo@test.com", "myService");
			Assert.That(result == MonoTouch.Security.SecStatusCode.Success);
		}
	}
}
