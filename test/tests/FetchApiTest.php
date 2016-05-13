<?php

use Mockery as m;

class FetchApiTest extends PHPUnit_Framework_TestCase
{

  /**
   *      fetchFromApi
   */

  public function testCheckTokenAccess()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $user = new User($mock);

    $user->checkTokenAccess('username');
  }

  public function testGetPublicAddresses()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->getPublicAddresses('username');
  }

  public function testGetAddresses()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->getAddresses('username');
  }

  public function testCheckAddressTokenAccess()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->checkAddressTokenAccess('address', 'sig');
  }

  public function testUpdateAccount()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'success'));

    $user = new User($mock);

    $user->updateAccount('username', 'token', 'password');
  }

  public function testRegisterAccount()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->registerAccount('username', 'password', 'email');
  }

  public function testVerifyLoginCredentials()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('id' => 'true'));

    $mock->verifyLoginCredentials('username', 'password');
  }

  public function testGetOAuthAuthorizationCodeWithCredentials()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('code' => 'true'));

    $mock->getOAuthAuthorizationCodeWithCredentials('username', 'password', array());
  }

  public function testGetAddressDetails()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->getAddressDetails('username', 'address');
  }

  public function testRegisterAddress()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->registerAddress('address', 'oauth_token');
  }

  public function testVerifyAddress()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->verifyAddress('username', 'address', 'oauth_token', 'signature');
  }

  public function testUpdateAddressDetails()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->updateAddressDetails('username', 'address', 'oauth_token');
  }

  public function testDeleteAddress()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->deleteAddress('username', 'address', 'oauth_token');
  }

  public function testLookupUserByAddress()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->lookupUserByAddress('address');
  }

  public function testLookupAddressByUser()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromAPI]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromAPI')
      ->once()
      ->andReturn(array('result' => 'true'));

    $mock->lookupAddressByUser('username');
  }
  
  /**
  *      fetchFromOAuth
  */

  public function testGetOAuthAccessToken()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromOAuth]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromOAuth')
    ->once()
    ->andReturn(array('access_token' => 'true'));

    $mock->getOAuthAccessToken('code');
  }

  public function testGetOAuthUserFromAccessToken()
  {
    $mock = m::mock('Tokenly\TokenpassClient\TokenpassAPI[fetchFromOAuth]')
      ->shouldAllowMockingProtectedMethods();

    $mock->shouldReceive('fetchFromOAuth')
    ->once()
    ->andReturn(array('id' => 'true'));

    $mock->getOAuthUserFromAccessToken('access_token');
  }

  /**
   *      TEARDOWN
   */
  public function tearDown()
  {
    m::close();
  }
}
