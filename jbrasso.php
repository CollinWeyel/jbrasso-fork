<?php

/**
 * @package     jbraSso.Plugins
 * @author      Giannis Brailas <jbrailas@rns-systems.eu>, Collin Weyel <collin@weyel.dev>
 * @version		1.6
 * @copyright   Copyright (C) 2025 Giannis Brailas, Collin Weyel. All rights reserved.
 * @license     GNU Lesser General Public License v3.0 (LGPL-3.0); see LICENSE.md
 */

// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die();

use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Authentication\AuthenticationResponse;
use Joomla\CMS\Event\User\AuthenticationEvent;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\User\User;
use Joomla\Event\SubscriberInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\Input\Input;
use Joomla\CMS\Router\Route;
use Joomla\Http\HttpFactory;
use Joomla\CMS\User\UserHelper;
use Joomla\Utilities\ArrayHelper;
use Joomla\CMS\Log\Log;

/**
 * A oauth v2.0 user adapter authentication plugin.
 *
 * @package     jbraSso.Plugins
 * @subpackage  Authentication
 * @since       1.0
 */
class PlgSystemJbraSso extends CMSPlugin
{
	private $app_name;
	private $app_scope;
	private $auth_url;
	private $token_url;
	private $api_url;
	private $client_id;
	private $client_secret;
	private $logout_url;
	private $acceptable_domains;
	private $frontend_sso;
	private $admin_sso;
	private $create_user;
	private $debug;

	private $redirect_uri;

	public function __construct(&$subject, $config)
	{
		parent::__construct($subject, $config);

		// Load plugin parameters
		$this->app_name = $this->params->get('app_name', '');
		$this->app_scope = $this->params->get('app_scope', 'openid');
		$this->auth_url = $this->params->get('auth_url', '');
		$this->token_url = $this->params->get('token_url', '');
		$this->api_url = $this->params->get('api_url', '');
		$this->client_id = $this->params->get('client_id', '');
		$this->client_secret = $this->params->get('client_secret', '');
		$this->logout_url = $this->params->get('logout_url', '');
		$this->acceptable_domains = $this->params->get('acceptable_domains', '');
		$this->frontend_sso = $this->params->get('frontend_sso', false);
		$this->admin_sso = $this->params->get('admin_sso', false);
		$this->create_user = $this->params->get('create_user', false);
		$this->debug = $this->params->get('debug', false);

		if (Factory::getApplication()->isClient('administrator')) {
			// Redirect URI for the administrator context
			$this->redirect_uri = Uri::root() . 'administrator/index.php?plugin=jbrasso&app_name=' . $this->app_name . '&task=oauthcallback';
		} else {
			// Redirect URI for the site context
			$this->redirect_uri = Uri::root() . 'index.php?plugin=jbrasso&app_name=' . $this->app_name . '&task=oauthcallback';
		}

		$this->ensureTablesExist();
	}

	public function onAfterRoute()
	{
		// Check if the request is for your plugin
		$app = Factory::getApplication();
		$client_key = $app->isClient('administrator') ? 'admin' : 'site';
		$input = $app->input;
		$plugin = $input->getCmd('plugin');
		$app_name = $input->getCmd('app_name');
		$task = $input->getCmd('task');

		// Only trigger on public pages and if the user is not logged in
		$user = Factory::getUser();
		if (!$user->guest) {
			//if the user has selected to logout
			if ($plugin === 'jbrasso' && $task === 'logout') {
				if ($this->debug) {
					error_log('Logout requested.');
					Log::add(
						'jbrasso: logout requested',
						Log::DEBUG,
						'jbrasso_log'
					);
				}
				$this->logout();
			}
			return;
		}

		// Handle oauth callback
		if ($plugin === 'jbrasso' && $app_name === $this->app_name && $task === 'oauthcallback') {
			$this->handleOAuthCallback();
			return;
		}

		// Save current URL to return to after login
		$uri = Uri::getInstance();
		$current_url = base64_encode($uri->toString());
		$app->setUserState("oauth2.return_url", $current_url);


		// Start the login flow manually
		if ($plugin === 'jbrasso' && $app_name === 'azure' && $task === 'start') {
			$this->redirectForAuthorization(Factory::getSession()->get("oauth2.state.$client_key"));
			return;
		}

		// Check for a remember me cookie
		$rememberMeCookieName = 'joomla_remember_me_' . UserHelper::getShortHashedUserAgent();
		$cookieValue = isset($_COOKIE[$rememberMeCookieName]) ? $_COOKIE[$rememberMeCookieName] : null;

		if ($this->debug) {
			error_log('jbrasso: cookieValue of remember_me is: ' . $cookieValue);
			Log::add(
				'jbrasso: cookieValue of remember_me is: ' . $cookieValue,
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		// initialise the login authentication process if a cookie is present
		if ($cookieValue && $app->isClient('site') && $this->frontend_sso) {

			if ($this->debug) {
				error_log('jbrasso: cookieValue of remember_me is found.');
				Log::add(
					'jbrasso: cookieValue of remember_me is found.',
					Log::DEBUG,
					'jbrasso_log'
				);
			}

			$decodedValue = base64_decode($cookieValue, true);
			if ($this->debug) {
				error_log('jbrasso: decodedValue is: ' . $decodedValue);
				Log::add(
					'jbrasso: decodedValue is: ' . $decodedValue,
					Log::DEBUG,
					'jbrasso_log'
				);
			}

			if ($decodedValue && strpos($decodedValue, ':') !== false) {

				// Parse the cookie value
				list($series, $token) = explode(':', $decodedValue, 2);

				// Fetch the stored token from the database
				$result = $this->validateRememberMeToken($series, $token);

				if ($this->debug) {
					error_log('jbrasso: validateRememberMeToken result is: ' . print_r($result, true));
					Log::add(
						'jbrasso: validateRememberMeToken result is: ' . print_r($result, true),
						Log::DEBUG,
						'jbrasso_log'
					);
				}

				if ($result && isset($result->user_id)) {

					$user = Factory::getUser($result->user_id);
					$user = $this->updateUser($user, null);
					$this->autoLoginUser($user);

					if ($this->debug) {
						error_log('jbrasso: User Login ' . $result->user_id . ' succeeded using remember_me cookie.');
						Log::add(
							'jbrasso: User Login ' . $result->user_id . ' succeeded using remember_me cookie.',
							Log::DEBUG,
							'jbrasso_log'
						);
					}
					return;
				} else {
					// Invalid cookie, clear it
					$input->cookie->set($rememberMeCookieName, '', time() - 3600, '/');
					if ($this->debug) {
						error_log('jbrasso: Invalid remember_me cookie.');
						Log::add(
							'jbrasso: Invalid remember_me cookie.',
							Log::DEBUG,
							'jbrasso_log'
						);
					}
				}
			}
			$input->cookie->set($rememberMeCookieName, '', time() - 3600, '/');
		}

		//in frontend always and in backend only if the checkbox admin_sso is clicked
		if (($app->isClient('site') && $this->frontend_sso) || ($app->isClient('administrator') && $this->admin_sso)) {
			// Check if we have valid tokens
			$tokens = $this->loadTokens();
			if ($tokens) {
				if ($this->isAccessTokenValid($tokens)) {

					// Access token is valid; proceed with user login
					$this->processUserSession($tokens);
					return;
				}

				// Access token expired; attempt to refresh
				if (!empty($tokens['refresh_token'])) {
					$this->handleTokenRefresh($tokens['refresh_token']);
					return;
				}
			}

			// No valid tokens; Redirect to the OAuth 2.0 authorization server
			//in frontend always and in backend only if the checkbox admin_sso is clicked
			if ($app->isClient('site') || ($app->isClient('administrator') && $this->admin_sso))
				$this->redirectForAuthorization(Factory::getSession()->get("oauth2.state.$client_key"));
		}
	}

	private function isAccessTokenValid($tokens)
	{
		if (empty($tokens['access_token']) || empty($tokens['expires_in']) || empty($tokens['created_at'])) {
			// Token data is incomplete
			if ($this->debug) {
				error_log('jbrasso: Token data is incomplete.');
				Log::add(
					'jbrasso: Token data is incomplete.',
					Log::DEBUG,
					'jbrasso_log'
				);
			}
			return false;
		}

		// Ensure 'created_at' and 'expires_in' are integers
		$created_at = strtotime($tokens['created_at']);
		$expires_in = (int) $tokens['expires_in'];

		if ($this->debug) {
			error_log('jbrasso: Token details: created_at=' . $created_at . ', expires_in=' . $expires_in);
			Log::add(
				'jbrasso: Token details: created_at=' . $created_at . ', expires_in=' . $expires_in,
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		// Validate 'updated_at' and 'expires_in'
		if ($created_at <= 0 || $expires_in <= 0) {
			if ($this->debug) {
				error_log('jbrasso: Invalid token timestamps: updated_at=' . $created_at . ', expires_in=' . $expires_in);
				Log::add(
					'jbrasso: Invalid token timestamps: updated_at=' . $created_at . ', expires_in=' . $expires_in,
					Log::DEBUG,
					'jbrasso_log'
				);
			}
			return false;
		}

		// Calculate expiration time
		$currentTime = time(); // Current time in seconds
		$expirationTime = $created_at + $expires_in; // When the token expires

		// Token has expired
		if ($currentTime >= $expirationTime) {
			if ($this->debug) {
				error_log('jbrasso: Access token has expired or is about to expire.');
				error_log('jbrasso: Current time: ' . $currentTime . ', Expiration time: ' . $expirationTime);
				Log::add(
					'jbrasso: Access token has expired or is about to expire.',
					Log::DEBUG,
					'jbrasso_log'
				);
				Log::add(
					'jbrasso: Current time: ' . $currentTime . ', Expiration time: ' . $expirationTime,
					Log::DEBUG,
					'jbrasso_log'
				);
			}
			return false;
		}

		// Token is still valid
		if ($this->debug) {
			error_log('jbrasso: Access token is valid.');
			Log::add(
				'jbrasso: Access token is valid.',
				Log::DEBUG,
				'jbrasso_log'
			);
		}
		return true;
	}

	/**
	 * Validate the Remember Me token.
	 *
	 * @param string $series The series value from the cookie.
	 * @param string $token The token value from the cookie.
	 * @return object|null Returns the user object if the token is valid, or null if invalid.
	 */
	private function validateRememberMeToken($series, $token)
	{
		if ($this->debug) {
			error_log('jbrasso: validateRememberMeToken function initialized.');
			Log::add(
				'jbrasso: validateRememberMeToken function initialized.',
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		// Get the database object
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);

		// Build the query to fetch the user details associated with the token
		$query = $db->getQuery(true)
			->select($db->quoteName(['user_id', 'token']))
			->from($db->quoteName('#__user_keys'))
			->where($db->quoteName('series') . ' = ' . $db->quote($series))
			->where($db->quoteName('time') . ' >= ' . $db->quote(time() - 30 * 86400)); // Token validity: 30 days

		// Execute the query
		$db->setQuery($query);

		try {
			$result = $db->loadObject();

			if ($result) {
				// Use password_verify to check if the plaintext token matches the hashed token in DB
				if (password_verify($token, $result->token)) {
					return $result;  // Valid token
				}
			}
		} catch (Exception $e) {
			if ($this->debug) {
				error_log('Error validating Remember Me token: ' . $e->getMessage());
				Log::add(
					'jbrasso: Error validating Remember Me token: ' . $e->getMessage(),
					Log::DEBUG,
					'jbrasso_log'
				);
			}
		}

		return null; // Token is invalid or expired
	}

	private function handleTokenRefresh($refreshToken)
	{
		$newTokens = $this->refreshAccessToken($refreshToken);

		if ($newTokens) {

			// proceed with user info processing, saving tokens and login
			$this->processUserSession($newTokens);
		} else {
			if ($this->debug) {
				error_log('Failed to refresh tokens.');
				Log::add(
					'jbrasso: Failed to refresh tokens.',
					Log::DEBUG,
					'jbrasso_log'
				);
			}
			$this->redirectWithError('Failed to refresh access token. Please log in again.');
		}
	}

	private function processUserSession($tokens)
	{
		$app = Factory::getApplication();
		$client_key = $app->isClient('administrator') ? 'admin' : 'site';

		$user = $this->processuser_info($tokens);

		if (!empty($user->id)) {
			$this->saveTokens($user->id, $tokens);
			$this->autoLoginUser($user);
			Factory::getSession()->set("oauth2.retry.$client_key", false);
		} else {
			if ($this->debug) {
				error_log('Failed to retrieve user info for valid tokens.');
				Log::add(
					'jbrasso: Failed to retrieve user info for valid tokens.',
					Log::DEBUG,
					'jbrasso_log'
				);
			}

			$this->redirectForAuthorization(Factory::getSession()->get("oauth2.state.$client_key"));
		}
	}

	private function handleOAuthCallback()
	{
		$app = Factory::getApplication();
		$client_key = $app->isClient('administrator') ? 'admin' : 'site';
		$session = Factory::getSession();
		$input = $app->input;
		$auth_code = $input->getString('code');
		$state = $input->getString('state');
		$stored_state = Factory::getSession()->get("oauth2.state.$client_key");
		$retry_flag = $session->get("oauth2.retry.$client_key", false);

		if ($this->debug) {
			error_log('--- jbrasso: handleOAuthCallback START ---');
			error_log('Request URI: ' . (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'N/A'));
			error_log('Redirect URI expected by plugin: ' . $this->redirect_uri);
			error_log('PHP session_name: ' . session_name());
			error_log('PHP session_id: ' . session_id());
			error_log('$_COOKIE keys: ' . implode(', ', array_keys($_COOKIE)));
			error_log('Raw $_COOKIE: ' . print_r($_COOKIE, true));
			error_log('Incoming state param: ' . (isset($_GET['state']) ? $_GET['state'] : 'NULL'));
			error_log('Session stored (oauth2.state.' . $client_key . '): ' . $session->get("oauth2.state.$client_key"));
			error_log('Session retry flag (oauth2.retry.' . $client_key . '): ' . var_export($session->get("oauth2.retry.$client_key", false), true));
			error_log('SESSION array: ' . print_r($_SESSION, true));
			error_log('--- jbrasso: handleOAuthCallback DEBUG END ---');

			Log::add('--- jbrasso: handleOAuthCallback START ---', Log::DEBUG, 'jbrasso_log');
			Log::add('Request URI: ' . (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'N/A'), Log::DEBUG, 'jbrasso_log');
			Log::add('Redirect URI expected by plugin: ' . $this->redirect_uri, Log::DEBUG, 'jbrasso_log');
			Log::add('PHP session_name: ' . session_name(), Log::DEBUG, 'jbrasso_log');
			Log::add('PHP session_id: ' . session_id(), Log::DEBUG, 'jbrasso_log');
			Log::add('$_COOKIE keys: ' . implode(', ', array_keys($_COOKIE)), Log::DEBUG, 'jbrasso_log');
			Log::add('Raw $_COOKIE: ' . print_r($_COOKIE, true), Log::DEBUG, 'jbrasso_log');
			Log::add('Incoming state param: ' . (isset($_GET['state']) ? $_GET['state'] : 'NULL'), Log::DEBUG, 'jbrasso_log');
			Log::add('Session stored (oauth2.state.' . $client_key . '): ' . $session->get("oauth2.state.$client_key"), Log::DEBUG, 'jbrasso_log');
			Log::add('Session retry flag (oauth2.retry.' . $client_key . '): ' . var_export($session->get("oauth2.retry.$client_key", false), true), Log::DEBUG, 'jbrasso_log');
			Log::add('SESSION array: ' . print_r($_SESSION, true), Log::DEBUG, 'jbrasso_log');
			Log::add('--- jbrasso: handleOAuthCallback DEBUG END ---', Log::DEBUG, 'jbrasso_log');
		}

		// Validate state parameter
		if ((empty($state) || empty($storedState) || $state !== $storedState)) {
			if ($this->debug) {
				error_log("Invalid state. Got: $state, Expected: $stored_state");
				Log::add("Invalid state. Got: $state, Expected: $stored_state");
			}

			if (!$retry_flag) {

				$session->set("oauth2.retry.$client_key", true);

				// Only retry with NON-EMPTY existing state
				if (!empty($storedState)) {
					$this->redirectForAuthorization($stored_state);
				} else {
					// No stored state = start clean
					$this->redirectForAuthorization(null);
				}

				return;
			}

			// If already retried once, stop and show error
			$app->enqueueMessage('Invalid state parameter.', 'error');
			return;
		}

		// authorization code provided
		if ($auth_code) {

			// Fetch access token using the authorization code
			$token_data = $this->fetchAccessToken($auth_code);

			//if no token_data found
			if (!$token_data) {
				if ($this->debug) {
					error_log('No token_data found!');
					Log::add(
						'jbrasso: No token_data found.',
						Log::DEBUG,
						'jbrasso_log'
					);
				}

				$use_state = $state ?: $stored_state;

				// Redirect to authorization endpoint for a new code
				$auth_url = $this->auth_url . '?' . http_build_query([
					'response_type' => 'code',
					'client_id' => $this->client_id,
					'redirect_uri' => $this->redirect_uri,
					'state' => $use_state,
					'scope' => $this->app_scope,
				]);
				$app->redirect($auth_url);
			} else {

				if ($this->debug) {
					error_log('token_data found');
					Log::add(
						'jbrasso: token_data found.',
						Log::DEBUG,
						'jbrasso_log'
					);
				}

				// proceed with user info processing, saving tokens and login
				$this->processUserSession($token_data);
			}
		} else {
			// No authorization code provided, check for an existing token
			$tokens = $this->loadTokens();

			if ($tokens) {
				if (!$this->isAccessTokenValid($tokens)) {
					if ($this->debug) {
						$app->enqueueMessage('access token is not valid.', 'error');
						Log::add(
							'jbrasso: access token is not valid.',
							Log::DEBUG,
							'jbrasso_log'
						);
					}

					// Access token expired, try refreshing it
					$newTokens = $this->refreshAccessToken($tokens['refresh_token']);

					if ($newTokens) {
						// proceed with user info processing, saving tokens and login
						$this->processUserSession($newTokens);
					} else {
						// Failed to refresh tokens, require re-authorization
						$app->enqueueMessage('Failed to refresh access token. Please log in again.', 'error');
						Log::add(
							'jbrasso: Failed to refresh access token. Please log in again.',
							Log::DEBUG,
							'jbrasso_log'
						);

						$use_state = $state ?: $stored_state;

						// Redirect to authorization endpoint for a new code
						$auth_url = $this->auth_url . '?' . http_build_query([
							'response_type' => 'code',
							'client_id' => $this->client_id,
							'redirect_uri' => $this->redirect_uri,
							'state' => $use_state,
							'scope' => $this->app_scope,
						]);
						$app->redirect($auth_url);
					}
				} else {
					// Access token is valid
					// proceed with user info processing, saving tokens and login
					$this->processUserSession($tokens);
				}
			} else {
				if ($this->debug) {
					error_log('No access token found');
					Log::add('No access token found');
				}
				// No token available, require authorization
				$app->enqueueMessage('No access token found. Please log in.', 'error');

				$use_state = $state ?: $stored_state;

				// Redirect to authorization endpoint for a new code
				$auth_url = $this->auth_url . '?' . http_build_query([
					'response_type' => 'code',
					'client_id' => $this->client_id,
					'redirect_uri' => $this->redirect_uri,
					'state' => $use_state,
					'scope' => $this->app_scope,
				]);
				$app->redirect($auth_url);
			}
		}
	}

	private function processuser_info($token_data)
	{
		$app = Factory::getApplication();
		if ($this->debug) {
			error_log('processuser_info executed');
			Log::add(
				'jbrasso: processuser_info executed',
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		$accessToken = $token_data['access_token'];

		try {
			$ch = curl_init($this->api_url);
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
			curl_setopt($ch, CURLOPT_ENCODING, "");
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_AUTOREFERER, true);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
			curl_setopt($ch, CURLOPT_POST, false);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array(
				'Authorization: Bearer ' . $accessToken,
				'User-Agent:web'
			));
			$content = curl_exec($ch);

			// Check if the response has the status code property
			//if (!isset($response->code) || $response->code != 200) {
			if (curl_error($ch)) {
				$app->enqueueMessage('Failed to retrieve user information. HTTP Code: ' . curl_error($ch), 'error');
				Log::add(
					'jbrasso: Failed to retrieve user information. HTTP Code: ' . curl_error($ch),
					'error',
					Log::DEBUG,
					'jbrasso_log'
				);
				return false;
			}

			$user_info = json_decode($content, true);

			if (empty($user_info)) {
				$app->enqueueMessage('Invalid user information received.', 'error');
				Log::add(
					'jbrasso: Invalid user information received.',
					Log::DEBUG,
					'jbrasso_log'
				);
				return false;
			} elseif (isset($user_info['error_description'])) {
				$app->enqueueMessage($user_info['error_description'], 'error');
				Log::add(
					'jbrasso: ' . json_encode($user_info['error_description']),
					Log::DEBUG,
					'jbrasso_log'
				);
				return false;
			} elseif (isset($user_info['error'])) {
				$app->enqueueMessage($user_info['error'], 'error');
				Log::add(
					'jbrasso: ' . json_encode($user_info['error']),
					Log::DEBUG,
					'jbrasso_log'
				);
				return false;
			}

			// Process the user information (e.g., create or update user)
			$user = $this->getUserAndCheck($user_info);
			if (empty($user)) {
				// User does not exist; create a new user
				$user = $this->createUser($user_info);
			} else {
				// User exists; update user information if necessary
				$user = $this->updateUser($user, $user_info);
			}

			if (!empty($user)) {
				return $user;
			} else {
				$app->enqueueMessage('user data is empty.');
				return false;
			}
		} catch (Exception $e) {
			$app->enqueueMessage($e->getMessage(), 'error');
			Log::add(
				'jbrasso: ' . $e->getMessage(),
				Log::DEBUG,
				'jbrasso_log'
			);
			return false;
		}
	}


	private function updateUser($user, $user_info)
	{
		$app = Factory::getApplication();
		if ($this->debug) {
			error_log('updateUser executed\n');
			Log::add(
				'jbrasso: updateUser executed',
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		// Update data with wich we created the user
		$user->setParam('email', $user_info['email']);
		$user->setParam('name', $user_info['surname'] . " " . $user_info['givenName']);
		$user->setParam('username', $user_info['userPrincipalName']);
		$user->setParam('lastvisitDate', date("Y-m-d H:i:s"));
		//? Maybe we should set the openid groups here ...
		// $user->setParam('groups', [2]); //default group is registered

		if (!$user->save()) {
			$app->enqueueMessage('Failed to update user data:' . $user->getError(), 'error');
			Log::add(
				'jbrasso: Failed to update user data:' . $user->getError(),
				Log::DEBUG,
				'jbrasso_log'
			);
			return null;
		}


		return $user;
	}

	private function createUser($user_info)
	{
		$app = Factory::getApplication();
		if ($this->debug) {
			error_log('createUser executed\n');
			Log::add(
				'jbrasso: createUser executed',
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		if (!$this->create_user) {
			if ($this->debug) error_log('createUser option is unchecked!\n');
			$app->enqueueMessage('The option to create new user account is disabled. If you want access inform the IT.', 'error');
			return;
		}


		if (!empty($user_info)) {
			// If user doesn't exist, create a new Joomla user
			$user = new User();
			$user->email = $user_info['email'];
			$user->name = $user_info['surname'] . " " . $user_info['givenName'];
			$user->username = $user_info['userPrincipalName'];
			$user->lastvisitDate = date("Y-m-d H:i:s");
			$user->groups = [2]; //default group is registered
			$user->password_clear = UserHelper::genRandomPassword(12); // Temporary random password

			if (!$user->save()) {
				$app->enqueueMessage('Failed to create user account.', 'error');
				Log::add(
					'jbrasso: Failed to create user account.',
					Log::DEBUG,
					'jbrasso_log'
				);
				return;
			}
		} else {
			$app->enqueueMessage('user_info not found.', 'error');
			Log::add(
				'jbrasso: user_info not found.',
				Log::DEBUG,
				'jbrasso_log'
			);
			return;
		}

		return $user;
	}

	private function autoLoginUser($user)
	{
		if ($this->debug) {
			error_log('autoLoginUser executed\n');
			Log::add(
				'jbrasso: autoLoginUser executed',
				Log::DEBUG,
				'jbrasso_log'
			);
		}
		$app = Factory::getApplication();
		$client_key = $app->isClient('administrator') ? 'admin' : 'site';

		if ($user instanceof User) {
			// Ensure the user object is properly loaded
			$user->set('guest', 0);
			$user->set('aid', 1); // Access level, adjust as needed

			// Assign the user's ACL groups
			$user->set('groups', $user->getAuthorisedGroups());

			$app->loadIdentity($user);

			// Store the user in the session
			$session = Factory::getSession();
			$session->set('user', $user);
			$app->set('user', $user);

			// Prepare the login response
			$options = [];
			$response = [
				'username' => $user->username,
				'fullname' => $user->name,
				'email'    => $user->email,
				'status'   => 'success',
				'user'     => $user,
				'action'   => 'login',
			];

			// Trigger the onUserAfterLogin event
			$results = $app->triggerEvent('onUserAfterLogin', [$response, $options]);

			// Check if login event plugins processed the request
			if (in_array(false, ArrayHelper::toInteger($results), true)) {
				if ($this->debug) {
					error_log("Failed to trigger login event");
					Log::add(
						'jbrasso: Failed to trigger login event',
						Log::DEBUG,
						'jbrasso_log'
					);
				}
				$app->enqueueMessage('Failed to trigger login event.', 'error');
				return false;
			} else {
				// After successful login
				$return_url = $app->getUserState("oauth2.return_url");
				$app->setUserState("oauth2.return_url", null); // Clear return_url
				$app->setUserState("oauth2.retry.$client_key", null); // Clear retry
				$app->setUserState("oauth2.state.$client_key", null); // Clear state

				// Determine the redirection URL based on context
				if ($app->isClient('administrator')) {
					if ($return_url) {
						$decodedUrl = base64_decode($return_url);
						$app->redirect($decodedUrl);
					} else {
						// Redirect to the admin dashboard
						$admin_url = Uri::root() . 'administrator/index.php';
						$app->redirect(Route::_($admin_url));
					}
				} else {

					//after successful login set the remember me cookie manually
					// Generate the series and token
					$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
					$series = UserHelper::genRandomPassword(20);
					$token = UserHelper::genRandomPassword(20);
					$hashed_token = UserHelper::hashPassword($token);
					$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

					// Check if an entry already exists for this user
					$query = $db->getQuery(true);
					$query->select('id') // Only need the ID
						->from($db->quoteName('#__user_keys'))
						->where($db->quoteName('user_id') . ' = ' . $db->quote($user->id));
					$db->setQuery($query);
					$existing_entry = $db->loadResult();

					if ($existing_entry) {
						// Delete the existing entry
						$delete_query = $db->getQuery(true);
						$delete_query->delete($db->quoteName('#__user_keys'))
							->where($db->quoteName('user_id') . ' = ' . $db->quote($user->id));
						$db->setQuery($delete_query);
						$db->execute();
						if ($this->debug) {
							error_log('jbrasso: Existing remember me token deleted for user ' . $user->id);
							Log::add(
								'jbrasso: Existing remember me token deleted for user ' . $user->id,
								Log::DEBUG,
								'jbrasso_log'
							);
						}
					}

					// Insert into the database
					$query = $db->getQuery(true)
						->insert($db->quoteName('#__user_keys'))
						->columns($db->quoteName(['user_id', 'series', 'token', 'time', 'uastring']))
						->values(implode(',', [
							(int) $user->id,
							$db->quote($series),
							$db->quote($hashed_token),
							$db->quote(time()),
							$db->quote($user_agent)
						]));
					$db->setQuery($query);
					$db->execute();

					// Set the cookie
					$remember_me_cookie_name = 'joomla_remember_me_' . UserHelper::getShortHashedUserAgent();
					$cookie_value = base64_encode($series . ':' . $token);
					$cookie_expiry = time() + 30 * 86400;
					$cookie_path = '/';

					// Use setcookie() directly
					setcookie(
						$remember_me_cookie_name,
						$cookie_value,
						[
							'expires' => $cookie_expiry,
							'path' => $cookie_path,
							'secure' => true, // Essential if using HTTPS
							'httponly' => true, // Recommended for security
							'samesite' => 'Lax', // Or 'Strict' if needed
						]
					);

					if ($this->debug) {
						error_log('jbrasso: Login succeeded and remember_me cookie has been set.');
						Log::add(
							'jbrasso: Login succeeded and remember_me cookie has been set.',
							Log::DEBUG,
							'jbrasso_log'
						);
					}

					if ($return_url) {
						$decoded_url = base64_decode($return_url);
						$app->redirect($decoded_url);
					} else {
						// Redirect to the main site homepage
						$site_url = Uri::base();
						$app->redirect(Route::_($site_url));
					}
				}

				return $user;
			}
		} else {
			// Handle error: User object is invalid
			error_log("Failed to auto-login user: Invalid user object");
			$app->enqueueMessage('Failed to auto-login user: Invalid user object.', 'error');
			Log::add(
				'jbrasso: Failed to auto-login user: Invalid user object',
				Log::DEBUG,
				'jbrasso_log'
			);
			return false;
		}
	}

	private function getUserAndCheck($userInfo)
	{
		if ($this->debug) {
			error_log("getUserAndCheck executed");
			Log::add('jbrasso: getUserAndCheck executed', Log::DEBUG, 'jbrasso_log');
		}

		if (!$this->acceptable_domains)
			return null;

		$email = $userInfo['email'];

		// Split the domain list string into an array of domains
		$acceptable_domains = explode(',', $this->acceptable_domains);

		// Trim whitespace from each domain
		$acceptable_domains = array_map('trim', $acceptable_domains);

		// Check if the email contains @
		if (strpos($email, '@') !== false) {

			// Split the email into username and domain parts
			list($username, $user_domain) = explode('@', $email, 2);

			// Check if the user's domain is in the allowed list
			if (in_array($user_domain, $acceptable_domains)) {
				return $this->getUserByEmail($email);
			} else {
				if ($this->debug) {
					error_log("Domain not allowed: " . $user_domain);
					Log::add("jbrasso: Domain not allowed: " . $user_domain, Log::DEBUG, 'jbrasso_log');
				}
				return null;
			}
		} else {
			if ($this->debug) {
				error_log("Not an email: " . $email);
				Log::add("jbrasso: Not an email: " . $email, Log::DEBUG, 'jbrasso_log');
			}
			return null;
		}
		if ($this->debug) {
			error_log("User not found for email: " . $email);
			Log::add("jbrasso: User not found for email: " . $email, Log::DEBUG, 'jbrasso_log');
		}
		return null;
	}

	private function getUserByEmail($email)
	{
		if ($this->debug) {
			error_log('getUserByEmail executed\n');
			Log::add(
				'jbrasso: getUserByEmail executed',
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		// Get the database object
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);

		// Query the user by email
		$query = $db->getQuery(true)
			->select('*')
			->from($db->quoteName('#__users'))
			->where($db->quoteName('email') . ' = ' . $db->quote($email));
		$db->setQuery($query);

		// Load the result
		$userData = $db->loadAssoc();

		if ($userData) {
			$userData["params"] = array();

			// Load the user object
			$user = new User();
			$user->bind($userData);
			return $user;
		}

		return null; // User not found
	}

	private function redirectForAuthorization($state = null)
	{
		$app = Factory::getApplication();
		$client_key = $app->isClient('administrator') ? 'admin' : 'site';
		$session = Factory::getSession();

		// Always try to reuse an existing state
		$stored_state = $session->get("oauth2.state.$client_key");

		if (empty($state)) {
			if (!empty($stored_state)) {
				// Reuse existing state
				$state = $stored_state;
			} else {
				// Generate new state
				$state = bin2hex(random_bytes(16)); // Generate a random state to prevent CSRF
				$session->fork(false); // prevents Joomla 6 session regeneration
				$session->set("oauth2.state.$client_key", $state); //NEW 29-07-2025
			}
		} else {
			// Ensure state is stored
			$session->set("oauth2.state.$client_key", $state);
		}

		$authorizeUrl = $this->auth_url . '?' . http_build_query([
			'response_type' => 'code',
			'client_id' => $this->client_id,
			'redirect_uri' => $this->redirect_uri,
			'scope' => $this->app_scope,
			'state' => $state,
		]);

		$app->redirect($authorizeUrl);
	}

	private function redirectWithError($message)
	{
		$app = Factory::getApplication();
		$client_key = $app->isClient('administrator') ? 'admin' : 'site';
		$app->enqueueMessage($message, 'error');
		//$this->redirectForAuthorization();
		$this->redirectForAuthorization(Factory::getSession()->get("oauth2.state.$client_key"));
	}

	private function fetchAccessToken($auth_code)
	{
		$app = Factory::getApplication();
		if ($this->debug) {
			error_log("fetchAccessToken executed");
			error_log("Auth Code: " . print_r($auth_code, true));
			Log::add(
				'jbrasso: fetchAccessToken executed',
				Log::DEBUG,
				'jbrasso_log'
			);
			Log::add(
				'jbrasso: Auth Code: ' . print_r($auth_code, true),
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		$httpFactory = new HttpFactory(); // Create an instance of the HttpFactory
		$http = $httpFactory->getHttp(); // Create the HTTP client instance
		$postFields = [
			'grant_type' => 'authorization_code',
			'code' => $auth_code,
			'redirect_uri' => $this->redirect_uri,
			'scope' => $this->app_scope,
			'client_id' => $this->client_id,
			'client_secret' => $this->client_secret,
		];

		try {
			$response = $http->post($this->token_url, $postFields);

			// Decode the response body
			$body = method_exists($response, 'getBody') // Joomla 4/5/6
				? $response->getBody()
				: $response->body;

			$token_data = json_decode($body, true);

			if (isset($token_data['error'])) {
				$app->enqueueMessage($token_data['error'], 'error');
				Log::add(
					'jbrasso: ' . json_encode($token_data['error']),
					Log::DEBUG,
					'jbrasso_log'
				);
				return false;
			} elseif (isset($token_data['error_description'])) {
				$app->enqueueMessage($token_data['error_description'], 'error');
				Log::add(
					'jbrasso: ' . json_encode($token_data['error_description']),
					Log::DEBUG,
					'jbrasso_log'
				);
				return false;
			}

			return $token_data;
		} catch (Exception $e) {
			$app->enqueueMessage($e->getMessage(), 'error');
			Log::add(
				'jbrasso: ' . $e->getMessage(),
				Log::DEBUG,
				'jbrasso_log'
			);
			return false;
		}
	}

	private function refreshAccessToken($refresh_token)
	{
		$app = Factory::getApplication();
		$http = HttpFactory::getHttp();

		$response = $http->post($this->token_url, [
			'refresh_token' => $refresh_token,
			'client_id' => $this->client_id,
			'client_secret' => $this->client_secret,
			'grant_type' => 'refresh_token',
		]);

		$body = method_exists($response, 'getBody') // Joomla 4/5/6
			? $response->getBody()
			: $response->body;

		$data = json_decode($body, true);

		if (isset($data['error'])) {
			$app->enqueueMessage('OAuth2 error: ' . $data['error_description'], 'error');
			Log::add(
				'jbrasso: OAuth2 error: ' . $data['error_description'],
				Log::DEBUG,
				'jbrasso_log'
			);
			return false;
		}

		// Return new access token
		return $data;
	}

	private function saveTokens($user_id, $token_data)
	{
		$app = Factory::getApplication();
		//$app->enqueueMessage(print_r($token_data, true), 'message');
		if ($this->debug) {
			error_log('saveTokens executed');
			Log::add(
				'jbrasso: saveTokens executed',
				Log::DEBUG,
				'jbrasso_log'
			);
		}
		// Ensure the token_data array has all necessary keys
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$query = $db->getQuery(true);

		if (empty($user_id)) {
			$app->enqueueMessage('User is not logged in.', 'error');
			Log::add(
				'jbrasso: User is not logged in.',
				Log::DEBUG,
				'jbrasso_log'
			);
			return; // Stop execution if user is not authenticated
		}

		// Check if a record already exists for the user
		$query
			->clear()
			->select('id')
			->from($db->quoteName('#__jbrasso_oauth_tokens'))
			->where($db->quoteName('user_id') . ' = ' . $db->quote($user_id));

		$db->setQuery($query);
		$existingRecord = $db->loadResult();

		if ($existingRecord) {
			// Update the existing record
			$query
				->clear()
				->update($db->quoteName('#__jbrasso_oauth_tokens'))
				->set($db->quoteName('access_token') . ' = ' . $db->quote($token_data['access_token']))
				->set($db->quoteName('refresh_token') . ' = ' . (isset($token_data['refresh_token']) ? $db->quote($token_data['refresh_token']) : 'NULL'))
				->set($db->quoteName('expires_in') . ' = ' . $db->quote($token_data['expires_in']))
				->set($db->quoteName('updated_at') . ' = ' . $db->quote(date('Y-m-d H:i:s')))
				->where($db->quoteName('user_id') . ' = ' . $db->quote($user_id));
		} else {
			// Insert a new record if none exists

			// Prepare the data for insertion/updating
			$columns = ['user_id', 'access_token', 'refresh_token', 'expires_in', 'created_at', 'updated_at'];
			$values = [
				$db->quote($user_id),
				$db->quote($token_data['access_token']),
				isset($token_data['refresh_token']) ? $db->quote($token_data['refresh_token']) : 'NULL',
				isset($token_data['expires_in']) ? $db->quote($token_data['expires_in']) : 0,
				$db->quote(date('Y-m-d H:i:s')),
				$db->quote(date('Y-m-d H:i:s'))
			];

			// Construct the SQL query for insertion
			$query
				->clear()
				->insert($db->quoteName('#__jbrasso_oauth_tokens'))
				->columns($db->quoteName($columns))
				->values(implode(',', $values));
		}

		try {
			// Execute the query
			$db->setQuery($query);
			$db->execute();
		} catch (\RuntimeException $e) {
			$app->enqueueMessage('Error saving tokens: ' . $e->getMessage(), 'error');
			Log::add(
				'jbrasso: Error saving tokens: ' . $e->getMessage(),
				Log::DEBUG,
				'jbrasso_log'
			);
			throw new Exception('Error saving tokens: ' . $e->getMessage());
		}
	}

	private function loadTokens()
	{
		$app = Factory::getApplication();
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);

		if ($this->debug) {
			error_log('jbrasso: loadTokens executed');
			Log::add(
				'jbrasso: loadTokens executed',
				Log::DEBUG,
				'jbrasso_log'
			);
		}
		$user = Factory::getUser();

		if (is_object($user) && isset($user->id)) {
			$user_id = (int) $user->id;
		} //check for Kerberos remote_user variable
		elseif (!empty($_SERVER['REMOTE_USER']) && empty($user->id)) {
			$username = $_SERVER['REMOTE_USER'];
			$query = $db->getQuery(true);
			$query->select('id')
				->from('#__users')
				->where('username = ' . $db->quote($username));
			$db->setQuery($query);
			$user_id = $db->loadResult();
		} else {
			if ($this->debug) {
				error_log('jbrasso: loadTokens aborted. No user ID available.');
				Log::add(
					'jbrasso: loadTokens aborted. No user ID available.',
					Log::DEBUG,
					'jbrasso_log'
				);
			}
			return null;
		}

		// Load tokens (e.g., from a database or session)
		$query = $db->getQuery(true);
		$query->select('*')
			->from('#__jbrasso_oauth_tokens')
			->where('user_id = ' . (int) $user_id);
		$db->setQuery($query);
		$result = $db->loadAssoc();

		if ($this->debug) {
			error_log('jbrasso: loadTokens loaded: ' . print_r($result, true));
			Log::add(
				'jbrasso: loadTokens loaded: ' . print_r($result, true),
				Log::DEBUG,
				'jbrasso_log'
			);
		}
		return $result ?: null;
	}

	public function logout()
	{
		$app = Factory::getApplication();

		// Clear stored tokens
		$this->clearTokens();

		// Clear Joomla session
		$session = Factory::getSession();
		$session->destroy(); // Destroys the Joomla session
		if ($this->debug) {
			error_log('User session has been destroyed.');
			Log::add(
				'jbrasso: User session has been destroyed.',
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		// Construct the remember me cookie name
		$rememberMeCookieName = 'joomla_remember_me_' . UserHelper::getShortHashedUserAgent();

		// Destroy the cookie by setting it with an expired time
		$app->input->cookie->set($rememberMeCookieName, '', time() - 3600, '/');

		if ($this->debug) {
			error_log('Remember Me cookie destroyed on logout.');
			Log::add(
				'jbrasso: Remember Me cookie destroyed on logout.',
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		//Build logout URL for Microsoft
		$logoutUrl = $this->logout_url;
		$postLogoutredirect_uri = Uri::root() . '?plugin=jbrasso&task=logout';
		$redirectUrl = $logoutUrl . '?post_logout_redirect_uri=' . urlencode($postLogoutredirect_uri);

		// Redirect the user to logout
		$app->redirect($redirectUrl);
	}

	protected function clearTokens()
	{
		if ($this->debug) {
			error_log('Clearing tokens from storage.');
			Log::add(
				'jbrasso: Clearing tokens from storage.',
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		// Example: Delete tokens from the database
		$user = Factory::getUser();

		if ($user && !$user->guest) {
			$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
			$query = $db->getQuery(true)
				->delete($db->quoteName('#__jbrasso_oauth_tokens'))
				->where($db->quoteName('user_id') . ' = ' . $db->quote($user->id));
			$db->setQuery($query);
			$db->execute();

			$query = $db->getQuery(true)
				->delete($db->quoteName('#__user_keys'))
				->where($db->quoteName('user_id') . ' = ' . $db->quote($user->id));
			$db->setQuery($query)->execute();
		}
	}

	protected function ensureTablesExist()
	{
		if ($this->debug) {
			error_log('Ensuring Database Tables exist.');
			Log::add(
				'jbrasso: Ensuring Database Tables exist.',
				Log::DEBUG,
				'jbrasso_log'
			);
		}

		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$db->setQuery($db->replacePrefix(<<<SQL
CREATE TABLE
  IF NOT EXISTS `#__jbrasso_oauth_tokens` (
    `id` INT (11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT NOT NULL,
    `access_token` TEXT NOT NULL,
    `refresh_token` TEXT NULL,
    `expires_in` INT NULL,
    `created_at` TEXT NULL,
    `updated_at` TEXT NULL,
    PRIMARY KEY (`id`)
  );
SQL));
		$db->execute();
	}
}
