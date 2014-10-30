<?php
/**
 * Ajax Login.
 * *
 * @package   Ajax_Login
 * @author    Tom
 * @license   GPL-2.0+
 * @link      @TODO
 * @copyright 2014 OllieFord&Co
 *
 * @wordpress-plugin
 * Plugin Name:       Secure-Login
 * Plugin URI:        @TODO
 * Description:       This plugin adds a login attempt system whilst storing data in multiple locations.
 * Version:           1.0.0
 * Author:            Tom
 * Author URI:        @TODO
 * Text Domain:       of-wp-secure-login
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Domain Path:       /languages
 * GitHub Plugin URI: https://github.com/<owner>/<repo>
 */

global $PROTECTION_ID,$EXPIRE_AFTER,$MAX_ATTEMPTS;

$PROTECTION_ID = 'yellowduck';
$EXPIRE_AFTER = 1200; /* 20 minutes (20 x 60 = 1200) */
$MAX_ATTEMPTS = 5; /* 5 max fails */

function get_clock_from_seconds($clock)
{
	$seconds = $minutes = $hours = 0;
	$now = intval(microtime(true));
	
	if($clock < $now)
		return "0 seconds left.";
	
	$seconds = $clock - $now;
	
	while($seconds > 3600)
	{
	
		$seconds -= 3600;
		$hours++;
	
	}
	
	while($seconds > 60)
	{
	
		$seconds -= 60;
		$minutes++;
	
	}
	
	if(0 < $hours)
		return sprintf('You must wait %s hours, %s minutes and %s seconds before you are able to try again.', $hours, $minutes, $seconds);
		
	elseif(0 < $minutes)
		return sprintf('You must wait <strong>%s minutes</strong> and <strong>%s seconds</strong> before you are able to try again.', $minutes, $seconds);
		
	else
		return sprintf('You must wait %s seconds before you are able to try again.', $seconds);
}

add_filter('authenticate', 'check_login', 9999, 3);

function check_login($user, $username, $password) {

	if(isset($_GET['demo']) && ( '::1' == get_address() || '127.0.0.1' == get_address() || 'localhost' == get_address()))
		save(get_address(), '0', '0', 0);
	
	/* If the username or password is empty then we shouldn't class it as a failed login attempt, or if $user is null. */
	if(empty($username) || empty($password) || $user == null)
		return $user;
	
	/* Bring the global variables into our function. */
	global $PROTECTION_ID, $EXPIRE_AFTER, $MAX_ATTEMPTS;

	/* Set-up our variables that we need next. */
	$COOKIE_LAST_TRY 	= 
	$SESSION_LAST_TRY 	= 
	$COOKIE_ATTEMPT 	= 
	$SESSION_ATTEMPT 	=	
	$COOKIE_EXPIRE 		= 
	$SESSION_EXPIRE		= -1;
	
	/*
	 * Test if the cookie exists, and if it matches a certain string.
	 * @NOTE Cookies aren't that important they're just an extra layer of security. (Aids blocking of VPNs)
	 */
	if( isset($_COOKIE[$PROTECTION_ID]) && 
		'i_am_alive' == $_COOKIE[$PROTECTION_ID] )
	{
		/* The last try the user made at trying to login. */
		if( isset($_COOKIE[$PROTECTION_ID . '_last_try']) )
		{
			$COOKIE_LAST_TRY = $_COOKIE[$PROTECTION_ID . '_last_try'];
			$COOKIE_LAST_TRY = preg_replace('/[^0-9]/', '', $COOKIE_LAST_TRY);
		}
		
		/* The amount of attempts the user made trying to login. */
		if( isset($_COOKIE[$PROTECTION_ID . '_attempt']) )
		{
			$COOKIE_ATTEMPT = $_COOKIE[$PROTECTION_ID . '_attempt'];
			$COOKIE_ATTEMPT = preg_replace('/[^0-9]/', '', $COOKIE_ATTEMPT);
		}
		
		/* The expiry of the last login fail. */
		if( isset($_COOKIE[$PROTECTION_ID . '_expire']) )
		{
			$COOKIE_EXPIRE = $_COOKIE[$PROTECTION_ID . '_expire'];
			$COOKIE_EXPIRE = preg_replace('/[^0-9]/', '', $COOKIE_EXPIRE);
		}
	}
	
	/* 
	 * Load the transient version of the cookie data.
	 * This is also used to check whether data has been tampered with.
	 */
	$SESSION_LAST_TRY = get_transient(get_address() . '_' . $PROTECTION_ID. '_last_try');
	$SESSION_ATTEMPT = get_transient(get_address() . '_' . $PROTECTION_ID. '_attempt');
	$SESSION_EXPIRE = get_transient(get_address() . '_' . $PROTECTION_ID. '_expire');
	
	/*
	 * Lets stop people editing their cookies.
	 */
	
	if((!isset($_COOKIE[$PROTECTION_ID . '_attempt']) || $COOKIE_ATTEMPT != $SESSION_ATTEMPT) && !empty($SESSION_ATTEMPT))
		$COOKIE_ATTEMPT = $SESSION_ATTEMPT;
	
	/*
	 * Just in case our sessions expire but the cookies do not.
	 * Used as a fall back only.
	 */
	
	elseif((empty($SESSION_ATTEMPT) || $COOKIE_ATTEMPT != $SESSION_ATTEMPT) && isset($_COOKIE[$PROTECTION_ID . '_attempt']))
		$SESSION_ATTEMPT = $COOKIE_ATTEMPT;
	
	$CURRENT_ATTEMPT = intval($SESSION_ATTEMPT);
	
	/*
	 * Lets stop people editing their cookies.
	 */
	
	if((!isset($_COOKIE[$PROTECTION_ID . '_expire']) || $COOKIE_EXPIRE != $SESSION_EXPIRE) && !empty($SESSION_EXPIRE))
		$COOKIE_EXPIRE = $SESSION_EXPIRE;
	
	/*
	 * Just in case our sessions expire but the cookies do not.
	 * Used as a fall back only.
	 */
	
	elseif((empty($SESSION_EXPIRE) || $COOKIE_EXPIRE != $SESSION_EXPIRE) && isset($_COOKIE[$PROTECTION_ID . '_expire']))
		$SESSION_EXPIRE = $COOKIE_EXPIRE;
	
	/*
	 * Lets stop people editing their cookies.
	 */
	
	if((!isset($_COOKIE[$PROTECTION_ID . '_last_try']) || $COOKIE_LAST_TRY != $SESSION_LAST_TRY) && !empty($SESSION_LAST_TRY))
		$COOKIE_LAST_TRY = $SESSION_LAST_TRY;
	
	/*
	 * Just in case our sessions expire but the cookies do not.
	 * Used as a fall back only.
	 */
	
	elseif((empty($SESSION_LAST_TRY) || $COOKIE_LAST_TRY != $SESSION_LAST_TRY) && isset($_COOKIE[$PROTECTION_ID . '_last_try']))
		$SESSION_LAST_TRY = $COOKIE_LAST_TRY;
	
	
	$NOW = intval(microtime(true));
	$EXPIRE = $NOW+$EXPIRE_AFTER;	
	
	if( $SESSION_EXPIRE <= $NOW && 
		$SESSION_EXPIRE == ($SESSION_LAST_TRY + $EXPIRE_AFTER) &&
		$SESSION_EXPIRE == ($COOKIE_LAST_TRY + $EXPIRE_AFTER) )
	{
		/* all previous fails are now not valid, so we are going to destroy them. */
		delete(get_address());
		
		return $user;
	}
	else
	{
		
		if($CURRENT_ATTEMPT == -1)
		{
			$CURRENT_ATTEMPT = 1;
		}
	
		if( $SESSION_ATTEMPT >= $MAX_ATTEMPTS || $COOKIE_ATTEMPT >= $MAX_ATTEMPTS )
		{
			/* They've already gone over their, or met the max amount of fails. */
			return new WP_Error('max-login-attempts', 'You\'ve reached the maximum amount of failed login attempts!<br/><br/>' . get_clock_from_seconds($SESSION_EXPIRE));
		}
		else
		{		
		
			if($user instanceof WP_Error)
			{
				$CURRENT_ATTEMPT++;
				save(get_address(), $EXPIRE, $NOW, $CURRENT_ATTEMPT);
				return new WP_Error('incorrect_password', $user->get_error_message('incorrect_password') . sprintf(' You have %s attempt(s) left.', ($MAX_ATTEMPTS - ($CURRENT_ATTEMPT - 1))));
			}
			elseif($user instanceof WP_User)
			{
				
			}
			
		}
	
	}
	
	save(get_address(), $EXPIRE, $NOW, $CURRENT_ATTEMPT);
    return $user;
}

function get_address()
{
	return $_SERVER['REMOTE_ADDR'];
}

function delete($ADDRESS)
{	
	global $PROTECTION_ID;
	
	delete_transient($ADDRESS . '_' . $PROTECTION_ID, 'i_am_alive');
	delete_transient($ADDRESS . '_' . $PROTECTION_ID . '_expire');
	delete_transient($ADDRESS . '_' . $PROTECTION_ID . '_last_try');
	delete_transient($ADDRESS . '_' . $PROTECTION_ID . '_attempt');
	
	setcookie($PROTECTION_ID, 'i_am_alive', -1);
	setcookie($PROTECTION_ID . '_expire', '', -1);
	setcookie($PROTECTION_ID . '_last_try', '', -1);
	setcookie($PROTECTION_ID . '_attempt', '', -1);
	
}

function save($ADDRESS, $EXPIRE, $NOW, $CURRENT_ATTEMPT)
{

	global $PROTECTION_ID, $EXPIRE_AFTER;
		
	set_transient($ADDRESS . '_' . $PROTECTION_ID, 'i_am_alive', $EXPIRE);
	set_transient($ADDRESS . '_' . $PROTECTION_ID . '_expire', $EXPIRE, $EXPIRE);
	set_transient($ADDRESS . '_' . $PROTECTION_ID . '_last_try', $NOW, $EXPIRE);
	set_transient($ADDRESS . '_' . $PROTECTION_ID . '_attempt', $CURRENT_ATTEMPT, $EXPIRE);
	
	setcookie($PROTECTION_ID, 'i_am_alive', $EXPIRE);
	setcookie($PROTECTION_ID . '_expire', $EXPIRE, $EXPIRE);
	setcookie($PROTECTION_ID . '_last_try', $NOW, $EXPIRE);
	setcookie($PROTECTION_ID . '_attempt', $CURRENT_ATTEMPT, $EXPIRE);

}

?>