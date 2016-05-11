<?php

class FetchApiTest extends PHPUnit_Framework_TestCase
{
  /**
   *      fetchFromApi
   */
  public function testCheckTokenAccess()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->checkTokenAccess('username');
  }

  public function testGetPublicAddresses()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->getPublicAddresses('username');
  }

  public function testGetAddresses()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->getAddresses('username');
  }

  public function testCheckAddressTokenAccess()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->checkAddressTokenAccess('address', 'sig');
  }

  public function testUpdateAccount()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->updateAccount('user_id', 'token', 'password');
  }

  public function testRegisterAccount()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->registerAccount('username', 'password', 'email');
  }

  public function testVerifyLoginCredentials()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->verifyLoginCredentials('username', 'password');
  }

  public function testGetOAuthAuthorizationCodeWithCredentials()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->getOAuthAuthorizationCodeWithCredentials('username', 'password', 'scopes');
  }

  public function testGetAddressDetails()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->getAddressDetails('username', 'address');
  }

  public function testRegisterAddress()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->registerAddress('address', 'oauth_token');
  }

  public function testVerifyAddress()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->verifyAddress('username', 'address', 'oauth_token', 'signature');
  }

  public function testUpdateAddressDetails()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->updateAddressDetails('username', 'address', 'oauth_token');
  }

  public function testDeleteAddress()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->deleteAddress('username', 'address', 'oauth_token');
  }

  public function testLookupUserByAddress()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->lookupUserByAddress('address');
  }

  public function testLookupAddressByUser()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromAPI')
      ->once();

    $mock->lookupAddressByUser('username');
  }
  /**
  *      fetchFromOAuth
  */

  public function testGetOAuthAccessToken()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromOAuth')
    ->once();

    $mock->getOAuthAccessToken('code');
  }

  public function testGetOAuthUserFromAccessToken()
  {
    $mock = Mockery::mock('Tokenly\TokenpassClient\TokenpassAPI')->shouldAllowMockingProtectedMethods();
    $mock->shouldReceive('fetchFromOAuth')
    ->once();

    $mock->getOAuthUserFromAccessToken('access_token');
  }

  /**
   *      TEARDOWN
   */
  public function tearDown()
  {
    Mockery::close();
  }
}
