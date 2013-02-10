<?php
/*
Plugin Name: dnsbl
Plugin URI: https://github.com/Diftraku/yourls_dnsbl
Description: Searches the submitter's IP from the DNSBL, based on tornevall.org's generic plugin
Version: 0.1
Author: Diftraku
Author URI: http://derpy.me/
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

/**
 * Configuration for DNSBL
 */

define('DNSBL_TABLE_PREFIX', '');			// If you need a prefix, add it here
define('DNSBL_MAX_AGE', 15);				// Time in minutes to store cached IPs
define('DNSBL_ANYTHING', false);			// Block anything that shows up as listed (not recommended)

// Tornevall - http://dnsbl.tornevall.org/?do=usage
define('DNSBL_TORNEVALL_CHECKED', 1);		// Block anything that has been checked
define('DNSBL_TORNEVALL_WORKING', 2);		// Block proxies that has been tested and works
define('DNSBL_TORNEVALL_BLITZED', 4); 		// Block if host are found in the Blitzed RBL (R.I.P) - Dead
define('DNSBL_TORNEVALL_TIMEOUT', 8);		// Block proxies that has been tested but timed out
define('DNSBL_TORNEVALL_ERROR', 16); 		// Deprecated - Block proxies that has been tested but failed
define('DNSBL_TORNEVALL_ELITE', 32);		// Block elite proxies (proxies with high anonymity)
define('DNSBL_TORNEVALL_ABUSE', 64);		// Block on "abuse"
define('DNSBL_TORNEVALL_ANONYMOUS', 128);	// Block on anonymous access (anonymizers, TOR, etc)

// NJABL - http://dnsbl.njabl.org/use.html
define('DNSBL_NJABL_RELAY', 2);				// Block open relays (as in e-mail-open-relays - be careful)
define('DNSBL_NJABL_DIALUP', 3);			// Block dialups/dynamic ip-ranges (Be careful!)
define('DNSBL_NJABL_SPAM', 4);				// Block spam sources (Again, as in e-mail
define('DNSBL_NJABL_MULTI', 5);				// Block multi-stage open relays (Don't know what this is? Leave it alone)
define('DNSBL_NJABL_PASSIVE', 6);			// Block passively detected "bad hosts" (Don't know what this is? Leave it alone)
define('DNSBL_NJABL_FORMMAIL', 8);			// Block systems with insecure scripts that make them into open relays
define('DNSBL_NJABL_OPEN', 9);				// Block open proxy servers

// EFNet - http://rbl.efnetrbl.org/
define('DNSBL_EFNET_OPEN', 1);				// Block open proxies registered at rbl.efnet.org
define('DNSBL_EFNET_SPAM666', 2);			// Block known trojan infected/spreading client (IRC-based)
define('DNSBL_EFNET_SPAM50', 3);			// Block trojan spreading client (IRC-based)
define('DNSBL_EFNET_TOR', 4);				// Block TOR Proxies
define('DNSBL_EFNET_DRONES', 5);			// Block Drones/Flooding (IRC-based)

// Abuseat - http://cbl.abuseat.org/
define('DNSBL_ABUSEAT_ALL', 2);				// Block listed address

function dnsbl_get_options() {
	// List of servers to check and what to block (see above for flags)
	//@TODO Create a proper config page for these
	$dnsbl = array();
	$dnsbl['opm.tornevall.org'] = array(
		DNSBL_TORNEVALL_WORKING,
		DNSBL_TORNEVALL_BLITZED,
		DNSBL_TORNEVALL_ELITE,
		DNSBL_TORNEVALL_ABUSE,
		DNSBL_TORNEVALL_ANONYMOUS,
	);
	$dnsbl['dnsbl.njabl.org'] = array(
		DNSBL_NJABL_FORMMAIL,
	);
	$dnsbl['rbl.efnet.org'] = array(
		DNSBL_EFNET_OPEN,
		DNSBL_EFNET_TOR,
	);
	
	// IPs to exclude from the RBL
	$dnsbl_exclude = array(
			'127.0.0.1'
	);
	
	return array($dnsbl, $dnsbl_exclude);
}

yourls_add_action('activated_dnsbl/plugin.php', 'dnsbl_activate');

function dnsbl_activate() {
	global $ydb;
	
	$init = yourls_get_option('dnsbl_init');
	if ($init === false) {
		// Create the init value
		yourls_add_option('dnsbl_init', time());
		// Create our cache table
		$ydb->query("
			CREATE TABLE ".DNSBL_TABLE_PREFIX."dnsbl_cache (
			id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
			ip VARCHAR(41) NOT NULL,
			flag TINYINT(3),
			time INTEGER UNSIGNED,
			PRIMARY KEY (`id`),
			INDEX `blacklist`(`ip`, `flag`, `time`)
		)");
		yourls_update_option('dnsbl_init', time());
		$init = yourls_get_option('dnsbl_init');
		if ($init === false) {
			die("Unable to enable DNSBL properly. There seem to be a problem with your database. Contact someone to have this problem fixed and try again.");
		}
	}
}

yourls_add_action('deactivated_dnsbl/plugin.php', 'dnsbl_deactivate');

function dnsbl_deactivate() {
	global $ydb;
	
	$init = yourls_get_option('dnsbl_init');
	if ($init !== false) {
		yourls_delete_option('dnsbl_init');
		$ydb->query("DROP TABLE IF EXISTS ".DNSBL_TABLE_PREFIX."dnsbl_cache");
	}
}

yourls_add_filter( 'pre_add_new_link', 'dnsbl_check_ip' );

/**
 * dnsbl_check_ip()
 * This monolith is a hideous piece that should die a slow painful death...
 */
function dnsbl_check_ip($url, $keyword = '', $title = '') {
	global $ydb;	
	
	list($dnsbl, $dnsbl_exclude) = dnsbl_get_options();
	
	// Clean up cache
	$delay = intval(time()-(DNSBL_MAX_AGE*60));
	$ydb->query("DELETE FROM ".DNSBL_TABLE_PREFIX."dnsbl_cache WHERE time < ".$delay);

	// Grab the remote IP
	$remote = yourls_get_IP();
	$remote = filter_var($remote, FILTER_VALIDATE_IP);
	
	// Check cache for a hit
	$result = $ydb->get_results("SELECT ip,flag FROM ".DNSBL_TABLE_PREFIX."dnsbl_cache WHERE ip = '".$remote."' LIMIT 1", ARRAY_A);
	
	if (!is_null($result)) {
		$result = $result[0];
		if (($result['flag'] > 0) && (!in_array($result['ip'], $dnsbl_exclude))) {
			// Bail!
			yourls_die('The requested URL cannot be shortened.', 'Forbidden', 403);
		}
	}
	else {
		$return_flags = array();
		// Lookup the IP from the servers (we're only interested in the server here)
		foreach ($dnsbl as $server => $flags) {
			$response = dnsbl_resolve($remote, $server);
			if ($response[0] == '127') {
				$return_flags[$server] = $response[3];
			}
		}
		
		// Check for any possible results
		if (!empty($return_flags)) {
			// Process the hits we got
			foreach ($return_flags as $server => $flag) {
				// Check if the flag should be blocked
				if (in_array($flag, $dnsbl[$server]) || (DNSBL_ANYTHING === true)) {
					// We have a hit! Bail on the first matching flag
					$flag = filter_var($flag, FILTER_SANITIZE_NUMBER_INT);
					$ydb->query("INSERT INTO ".DNSBL_TABLE_PREFIX."dnsbl_cache (ip, flag, time) VALUES ('$remote', $flag, ".time().")");
					yourls_die('The requested URL cannot be shortened.', 'Forbidden', 403);
					break;
				}
			}
		}
		else {
			// Clean as a whistle... so far!
			$ydb->query("INSERT INTO ".DNSBL_TABLE_PREFIX."dnsbl_cache (ip, flag, time) VALUES ('$remote', 0, ".time().")");
			return;
		}
	}
}

/*function dnsbl_bitmask ($bit = '')
{
	$loadbits = 8;
	for ($i = 0 ; $i < $loadbits ; ++$i) {$arr[] = pow(2,$i);}
	for ($i = 0 ; $i < count($arr) ; ++$i) {$mask[$i] = ($bit & $arr[$i]) ? '1' : '0';}
	return $mask;
}*/

function dnsbl_resolve($ip, $server) {
	$return = explode('.', gethostbyname(implode('.', array_reverse(explode('.', $ip))) . '.' . $server));           // Not ipv6-compatible!
	// 127-bug-checking
	if (implode(".", $return) != implode('.', array_reverse(explode('.', $ip))) . '.' . $server) {return $return;} else {return false;}
} 
