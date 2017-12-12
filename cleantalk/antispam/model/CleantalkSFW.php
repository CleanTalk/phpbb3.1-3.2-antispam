<?php

/*
 * Cleantalk Base class
 * Compatible only with phpBB 3.1+
 * @version 1.5-phpbb
 * author Cleantalk team (welcome@cleantalk.org)
 * copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * see https://github.com/CleanTalk/php-antispam
*/


namespace cleantalk\antispam\model;

class cleantalkSFW
{
	public $ip = 0;
	public $ip_str = '';
	public $ip_array = Array();
	public $ip_str_array = Array();
	public $blocked_ip = '';
	public $passed_ip = '';
	public $result = false;
	
	//Database variables
	private $table_prefix;
	private $db;
	private $query;
	private $db_result;
	private $db_result_data = array();
	private $cdn_cf = array(
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'104.16.0.0/12',
		'108.162.192.0/18',
		'131.0.72.0/22',
		'141.101.64.0/18',
		'162.158.0.0/15',
		'172.64.0.0/13',
		'173.245.48.0/20',
		'188.114.96.0/20',
		'190.93.240.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
	);
	
	
	public function __construct()
	{
		global $db, $table_prefix;
		$this->table_prefix = $table_prefix;
		$this->db = $db;
	}
	
	public function unversal_query($query)
	{
		$this->db_result = $this->db->sql_query($query);
	}
	
	public function unversal_fetch()
	{
		$this->db_result_data = $this->db->sql_fetchrow($this->db_result);
		$this->db->sql_freeresult($this->db_result);
	}

	public function unversal_fetch_all()
	{
		$this->db_result_data = $this->db->sql_fetchrowset($this->db_result);
		$this->db->sql_freeresult($this->db_result);
	}
	
	
	/*
	*	Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, sfw_test_ip)
	* 
	*	reutrns array
	*/
	public function get_ip($cdn = $this->cdn_cf){
		
		global $request;
		
		$result = Array();
		
		// Getting IP
		$result['remote_addr'] = filter_var( $request->server('REMOTE_ADDR'), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
		$this->ip_str_array[] = $result['remote_addr'];
		$this->ip_array[]=sprintf("%u", ip2long($result['remote_addr']));
		
		// Getting test IP
		$sfw_test_ip = $request->variable('sfw_test_ip', '');
		if($sfw_test_ip){
			$result['sfw_test_ip'] = filter_var( $sfw_test_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
			$this->ip_str_array[]=$result['sfw_test_ip'];
			$this->ip_array[]=sprintf("%u", ip2long($result['sfw_test_ip']));
		}
		
		// Getting Cloudflare IP
		$headers = function_exists('apache_request_headers')
			? apache_request_headers()
			: self::apache_request_headers();
		
		if(isset($headers['Cf_Connecting_Ip'])){
			foreach($cdn as $cidr){
				if($this->ip_mask_match($result['remote_addr'], $cidr)){
					$result['cf_connecting_ip'] = filter_var( $_SERVER['Cf_Connecting_Ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
					$this->ip_array[] = sprintf("%u", ip2long($result['cf_connecting_ip']));
					unset($result['remote_addr']);
					break;
				}
			}
		}
		
		return array_unique($result);
	}
	
	/*
	*	Checks IP via Database
	*/
	public function check_ip(){		
		
		for($i=0, $arr_count = sizeof($this->ip_array); $i < $arr_count; $i++){
			
			$query = "SELECT 
				COUNT(network) AS cnt
				FROM ".$this->table_prefix."cleantalk_sfw
				WHERE network = ".intval($this->ip_array[$i])." & mask;";
			$this->unversal_query($query);
			$this->unversal_fetch();
			
			$curr_ip = long2ip($this->ip_array[$i]);
			
			if($this->db_result_data['cnt']){
				$this->result = true;
				$this->blocked_ip=$this->ip_str_array[$i];
			}else{
				$this->passed_ip = $this->ip_str_array[$i];
			}
		}
	}
		
	/*
	*	Add entry to SFW log
	*/
	public function sfw_update_logs($ip, $result){
		
		if($ip === NULL || $result === NULL){
			return;
		}
		
		$blocked = ($result == 'blocked' ? ' + 1' : '');
		$time = time();
		$ip = $this->db->sql_escape($ip);
		
		$query = "INSERT INTO ".$this->table_prefix."cleantalk_sfw_logs
		SET 
			ip = '$ip',
			all_entries = 1,
			blocked_entries = 1,
			entries_timestamp = ".$time."
		ON DUPLICATE KEY 
		UPDATE 
			all_entries = all_entries + 1,
			blocked_entries = blocked_entries".strval($blocked).",
			entries_timestamp = ".$time."";

		$this->unversal_query($query, true);
	}
	
	/*
	* Updates SFW local base
	* 
	* return mixed true || array('error' => true, 'error_string' => STRING)
	*/
	public function sfw_update($ct_key){
		
		$result = self::get_2sBlacklistsDb($ct_key);
		
		if(empty($result['error'])){
			
			$this->unversal_query("DELETE FROM ".$this->table_prefix."cleantalk_sfw;", true);
						
			// Cast result to int
			foreach($result as $value){
				$value[0] = intval($value[0]);
				$value[1] = intval($value[1]);
			} unset($value);
			
			$query="INSERT INTO ".$this->table_prefix."cleantalk_sfw VALUES ";
			for($i=0, $arr_count = count($result); $i < $arr_count; $i++){
				if($i == count($result)-1){
					$query.="(".$result[$i][0].",".$result[$i][1].");";
				}else{
					$query.="(".$result[$i][0].",".$result[$i][1]."), ";
				}
			}
			$this->unversal_query($query, true);
			
			return true;
			
		}else{
			return $result['error_string'];
		}
	}
	
	/*
	* Sends and wipe SFW log
	* 
	* returns mixed true || array('error' => true, 'error_string' => STRING)
	*/
	public function send_logs($ct_key){
		
		//Getting logs
		$query = "SELECT * FROM ".$this->table_prefix."cleantalk_sfw_logs";
		$this->unversal_query($query);
		$this->unversal_fetch_all();
		
		if(count($this->db_result_data)){
			
			//Compile logs
			$data = array();
			foreach($this->db_result_data as $key => $value){
				$data[] = array(trim($value['ip']), $value['all_entries'], $value['all_entries']-$value['blocked_entries'], $value['entries_timestamp']);
			}
			unset($key, $value);
			
			//Sending the request
			$result = self::sfwLogs($ct_key, $data);
			
			//Checking answer and deleting all lines from the table
			if(empty($result['error'])){
				if($result['rows'] == count($data)){
					$this->unversal_query("DELETE FROM ".$this->table_prefix."cleantalk_sfw_logs", true);
					return true;
				}
			}else{
				return $result['error_string'];
			}
				
		}else{
			return 'NO_LOGS_TO_SEND';
		}
	}
	
	/*
	* Shows DIE page
	* 
	* Stops script executing
	*/	
	public function sfw_die($api_key, $cookie_prefix = '', $cookie_domain = ''){
		
		global $request, $user;
		$user->add_lang_ext('cleantalk/antispam', 'common');
		
		// File exists?
		if(file_exists(dirname(__FILE__)."/sfw_die_page.html")){
			$sfw_die_page = file_get_contents(dirname(__FILE__)."/sfw_die_page.html");
		}else{
			trigger_error($user->lang('SFW_DIE_NO_FILE'), E_USER_ERROR);
		}

		// Translation
		$request_uri = $request->server('REQUEST_URI');
		$sfw_die_page = str_replace('{SFW_DIE_NOTICE_IP}',              $user->lang('SFW_DIE_NOTICE_IP'),              $sfw_die_page);
		$sfw_die_page = str_replace('{SFW_DIE_MAKE_SURE_JS_ENABLED}',   $user->lang('SFW_DIE_MAKE_SURE_JS_ENABLED'),   $sfw_die_page);
		$sfw_die_page = str_replace('{SFW_DIE_CLICK_TO_PASS}',          $user->lang('SFW_DIE_CLICK_TO_PASS'),          $sfw_die_page);
		$sfw_die_page = str_replace('{SFW_DIE_YOU_WILL_BE_REDIRECTED}', $user->lang('SFW_DIE_YOU_WILL_BE_REDIRECTED'), $sfw_die_page);
		$sfw_die_page = str_replace('{CLEANTALK_TITLE}',                $user->lang('ACP_CLEANTALK_TITLE'),            $sfw_die_page);
		
		// Service info
		$sfw_die_page = str_replace('{REMOTE_ADDRESS}', $this->blocked_ip, $sfw_die_page);
		$sfw_die_page = str_replace('{REQUEST_URI}', $request_uri, $sfw_die_page);
		$sfw_die_page = str_replace('{COOKIE_PREFIX}', $cookie_prefix, $sfw_die_page);
		$sfw_die_page = str_replace('{COOKIE_DOMAIN}', $cookie_domain, $sfw_die_page);
		$sfw_die_page = str_replace('{SFW_COOKIE}', md5($this->blocked_ip.$api_key), $sfw_die_page);
		
		// Headers
		if(headers_sent() === false){
			header("Cache-Control: no-store, no-cache, must-revalidate");
			header("Pragma: no-cache");
			header("Last-Modified: " . gmdate("D, d M Y H:i:s") . "GMT");
			header("Expires: 0");
			header("HTTP/1.0 403 Forbidden");
			$sfw_die_page = str_replace('{GENERATED}', "", $sfw_die_page);
		}else{
			$sfw_die_page = str_replace('{GENERATED}', "<h2 class='second'>The page was generated at&nbsp;".date("D, d M Y H:i:s")."</h2>",$sfw_die_page);
		}
		trigger_error($sfw_die_page, E_USER_ERROR);
		
	}
	
	/*
	* Wrapper for sfw_logs API method
	* 
	* returns mixed STRING || array('error' => true, 'error_string' => STRING)
	*/
	static public function sfwLogs($api_key, $data, $do_check = true){
		$url='https://api.cleantalk.org';
		$request = array(
			'auth_key' => $api_key,
			'method_name' => 'sfw_logs',
			'data' => json_encode($data),
			'rows' => count($data),
			'timestamp' => time()
		);
		$result = self::sendRawRequest($url, $request);
		$result = $do_check ? self::checkRequestResult($result, 'sfw_logs') : $result;
		
		return $result;
	}
	
	/*
	* Wrapper for 2s_blacklists_db API method
	* 
	* returns mixed STRING || array('error' => true, 'error_string' => STRING)
	*/
	static public function get_2sBlacklistsDb($api_key, $do_check = true){
		$url='https://api.cleantalk.org';
		$request = array(
			'auth_key' => $api_key,
			'method_name' => '2s_blacklists_db'
		);
		
		$result = self::sendRawRequest($url, $request);
		$result = $do_check ? self::checkRequestResult($result, '2s_blacklists_db') : $result;
		
		return $result;
	}
	
	/**
	 * Function sends raw request to API server
	 *
	 * @param string url of API server
	 * @param array data to send
	 * @param boolean is data have to be JSON encoded or not
	 * @param integer connect timeout
	 * @return type
	 */
	static public function sendRawRequest($url,$data,$isJSON=false,$timeout=3){
		
		$result=null;
		if(!$isJSON){
			$data=http_build_query($data);
			$data=str_replace("&amp;", "&", $data);
		}else{
			$data= json_encode($data);
		}
		
		$curl_exec=false;
		if (function_exists('curl_init') && function_exists('json_decode')){
		
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
			
			// receive server response ...
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			// resolve 'Expect: 100-continue' issue
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:'));
			
			$result = curl_exec($ch);
			
			if($result!==false){
				$curl_exec=true;
			}
			
			curl_close($ch);
		}
		if(!$curl_exec){
			
			$opts = array(
				'http'=>array(
					'method' => "POST",
					'timeout'=> $timeout,
					'content' => $data
				)
			);
			$context = stream_context_create($opts);
			$result = @file_get_contents($url, 0, $context);
		}
		return $result;
	}
	
	/**
	 * Function checks server response
	 *
	 * @param string request_method
	 * @param string result
	 * @return mixed (array || array('error' => true, 'error_string' => STRING))
	 */
	static public function checkRequestResult($result, $method_name = null)
	{
		
		// Errors handling
		// Bad connection
		if(empty($result)){
			$result = array(
				'error' => true,
				'error_string' => 'CONNECTION_ERROR'
			);
			return $result;
		}
		
		// JSON decode errors
		$result = json_decode($result, true);
		if(empty($result)){
			$result = array(
				'error' => true,
				'error_string' => 'JSON_DECODE_ERROR'
			);
			return $result;
		}
		
		// Server errors
		if($result && (isset($result['error_no']) || isset($result['error_message']))){
			$result = array(
				'error' => true,
				'error_string' => "SERVER_ERROR NO:{$result['error_no']} MSG:{$result['error_message']}",
				'error_no' => $result['error_no'],
				'error_message' => $result['error_message']
			);
			return $result;
		}
		
		/* mehod_name = notice_validate_key */
		if($method_name == 'notice_validate_key' && isset($result['valid'])){
			$result['error'] = false;
			return $result;
		}
		
		/* Other methods */
		if(isset($result['data']) && is_array($result['data'])){
			return $result['data'];
		}
	}
	
	/* 
	 * If Apache web server is missing then making
	 * Patch for apache_request_headers() 
	 */
	static function apache_request_headers(){
		
		global $request;
		$_SERVER = $request->get_super_global(\phpbb\request\request_interface::SERVER);

		$headers = array();	
		foreach($_SERVER as $key => $val){
			if(preg_match('/\AHTTP_/', $key)){
				$server_key = preg_replace('/\AHTTP_/', '', $key);
				$key_parts = explode('_', $server_key);
				if(count($key_parts) > 0 and strlen($server_key) > 2){
					foreach($key_parts as $part_index => $part){
						$key_parts[$part_index] = mb_strtolower($part);
						$key_parts[$part_index][0] = strtoupper($key_parts[$part_index][0]);					
					}
					$server_key = implode('-', $key_parts);
				}
				$headers[$server_key] = $val;
			}
		}
		return $headers;
	}
}
