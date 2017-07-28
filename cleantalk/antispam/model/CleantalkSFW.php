<?php

/*
*	CleanTalk SpamFireWall base class
*	Version 1.0
*	Compatible only with phpBB 3.1
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
	private $db_result;
	private $db_result_data;
	
	public function __construct(){
		if(defined("IN_PHPBB")){
			global $db, $table_prefix;
			$this->table_prefix = $table_prefix;
			$this->db = $db;
		}
		if(defined("WPINC")){
			global $wpdb;
			$this->table_prefix = $wpdb->prefix;
			$this->db = $wpdb;
		}
	}
	
	public function unversal_query($query){
		if(defined("IN_PHPBB")){
			$this->db_result = $this->db->sql_query($query);
		}
		if(defined("WPINC")){
			$this->db->db_result = $this->db->query($query);
		}
	}
	
	public function unversal_fetch(){
		if(defined("IN_PHPBB")){
			$this->db_result_data = $this->db->sql_fetchrow($this->db_result);
			$this->db->sql_freeresult($this->db_result);
		}
		if(defined("WPINC")){
			$this->db->db_result = $this->db->unversal_fetch_all();
		}
	}
	public function unversal_fetch_all(){
		if(defined("IN_PHPBB")){
			$this->db_result_data = $this->db->sql_fetchrowset($this->db_result);
			$this->db->sql_freeresult($this->db_result);
		}
		if(defined("WPINC")){
			$this->db->db_result = $this->db->get_results(null, ARRAY_A);
		}
	}
	
	
	/*
	*	Getting IP function
	*	Version 1.1
	*	Compatible with any CMS
	*/
	public function cleantalk_get_real_ip(){
				
		if(function_exists('apache_request_headers'))
			$headers = apache_request_headers();
		else
			$headers = self::apache_request_headers();
				
		$headers['X-Forwarded-For'] = isset($headers['X-Forwarded-For']) ? $headers['X-Forwarded-For'] : null;
		$headers['HTTP_X_FORWARDED_FOR'] = isset($headers['HTTP_X_FORWARDED_FOR']) ? $headers['HTTP_X_FORWARDED_FOR'] : null;
		
		if(defined("IN_PHPBB")){
			global $request;
			$headers['REMOTE_ADDR'] = $request->server('REMOTE_ADDR');
			$sfw_test_ip = $request->variable('sfw_test_ip', '');
		}else{
			$headers['REMOTE_ADDR'] = $_SERVER['REMOTE_ADDR'];
			$sfw_test_ip = isset($_GET['sfw_test_ip']) ? $_GET['sfw_test_ip'] : null;
		}
		
		$result=Array();
		
		if( $headers['X-Forwarded-For'] ){
			$the_ip = explode(",", trim($headers['X-Forwarded-For']));
			$the_ip = trim($the_ip[0]);
			$result[] = $the_ip;
			$this->ip_str_array[]=$the_ip;
			$this->ip_array[]=sprintf("%u", ip2long($the_ip));
		}
		
		if( $headers['HTTP_X_FORWARDED_FOR'] ){
			$the_ip = explode(",", trim($headers['HTTP_X_FORWARDED_FOR']));
			$the_ip = trim($the_ip[0]);
			$result[] = $the_ip;
			$this->ip_str_array[]=$the_ip;
			$this->ip_array[]=sprintf("%u", ip2long($the_ip));
		}
		
		$the_ip = filter_var( $headers['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
		$result[] = $the_ip;
		$this->ip_str_array[]=$the_ip;
		$this->ip_array[]=sprintf("%u", ip2long($the_ip));

		if($sfw_test_ip){
			$result[] = $sfw_test_ip;
			$this->ip_str_array[]=$sfw_test_ip;
			$this->ip_array[]=sprintf("%u", ip2long($sfw_test_ip));
		}
		
		return $result;
	}
	
	/*
	*	Getting IP function
	*	Version 1.1
	*	Compatible with any CMS
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
	*	Add entries to SFW log
	*	Version 1.1
	*	Compatible with any CMS
	*/
	public function sfw_update_logs($ip, $result){
						
		if($ip === NULL || $result === NULL){
			return;
		}
				
		$blocked = ($result == 'blocked' ? ' + 1' : '');
		$time = time();

		$query = "INSERT INTO ".$this->table_prefix."cleantalk_sfw_logs
		SET 
			ip = '$ip',
			all_entries = 1,
			blocked_entries = 1,
			entries_timestamp = '".intval($time)."'
		ON DUPLICATE KEY 
		UPDATE 
			all_entries = all_entries + 1,
			blocked_entries = blocked_entries".strval($blocked).",
			entries_timestamp = '".intval($time)."'";

		$this->unversal_query($query);
	}
	
	/*
	*	Updates SFW local base
	*	Version 1.1
	*	Compatible only with phpBB 3.1
	*/
	public function sfw_update($ct_key){
		
		$result = self::get_2sBlacklistsDb($ct_key);

		$result = json_decode($result, true);
		
		if(isset($result['data'])){

			$this->unversal_query("DELETE FROM ".$this->table_prefix."cleantalk_sfw;");
			
			$result=$result['data'];
			
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
			
			$this->unversal_query($query);
		}
	}
	
	/*
	*	Sends and wipe SFW log
	*	Version 1.1
	*	Compatible only with phpBB 3.1
	*/
	public function send_logs($ct_key){
		
		//Getting logs
		$query = "SELECT * FROM ".$this->table_prefix."cleantalk_sfw_logs";
		$this->unversal_query($query);
		$this->unversal_fetch_all();
		
		if(count($this->db_result_data)){
			//Compile logs
			$data = array();
			
			$for_return['all_entries'] = 0;
			$for_return['blocked_entries'] = 0;
			
			foreach($this->db_result_data as $key => $value){
				//Compile log
				$data[] = array(trim($value['ip']), $value['all_entries'], $value['all_entries']-$value['blocked_entries'], $value['entries_timestamp']);
				//Compile to return;
				$for_return['all_entries'] = $for_return['all_entries'] + $value['all_entries'];
				$for_return['blocked_entries'] = $for_return['blocked_entries'] + $value['blocked_entries'];
			}
			unset($key, $value);
			
			//Sending the request
			$result = self::sfwLogs($ct_key, $data);
			
			$result = json_decode($result);
			
			//Checking answer and deleting all lines from the table
			if(isset($result->data) && isset($result->data->rows)){
				if($result->data->rows == count($data)){
					$this->unversal_query("DELETE FROM ".$this->table_prefix."cleantalk_sfw_logs");
					return $for_return;
				}
			}
				
		}else{
			return false;
		}
	}
	
	/*
	*	Shows DIE page
	*	Version 1.1
	*	Compatible with any CMS
	*/	
	public function sfw_die($api_key, $cookie_prefix = '', $cookie_domain = ''){
		
		if(defined('IN_PHPBB')){
			global $request, $user;
			$user->add_lang_ext('cleantalk/antispam', 'common');
		}
		
		// File exists?
		if(file_exists(dirname(__FILE__)."/sfw_die_page.html")){
			$sfw_die_page = file_get_contents(dirname(__FILE__)."/sfw_die_page.html");
		}else{
			die($user->lang('SFW_DIE_NO_FILE'));
		}
		
		// Translation
		if(defined("IN_PHPBB")){
			$request_uri = $request->server('REQUEST_URI');
			$sfw_die_page = str_replace('{SFW_DIE_NOTICE_IP}',              $user->lang('SFW_DIE_NOTICE_IP'),              $sfw_die_page);
			$sfw_die_page = str_replace('{SFW_DIE_MAKE_SURE_JS_ENABLED}',   $user->lang('SFW_DIE_MAKE_SURE_JS_ENABLED'),   $sfw_die_page);
			$sfw_die_page = str_replace('{SFW_DIE_CLICK_TO_PASS}',          $user->lang('SFW_DIE_CLICK_TO_PASS'),          $sfw_die_page);
			$sfw_die_page = str_replace('{SFW_DIE_YOU_WILL_BE_REDIRECTED}', $user->lang('SFW_DIE_YOU_WILL_BE_REDIRECTED'), $sfw_die_page);
			$sfw_die_page = str_replace('{CLEANTALK_TITLE}',                $user->lang('ACP_CLEANTALK_TITLE'),            $sfw_die_page);
		}else{
			$request_uri = $_SERVER['REQUEST_URI'];
		}
		
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
		
		if(defined('WPINC')){
			wp_die($sfw_die_page, "Blacklisted", Array('response'=>403));
		}else{
			die($sfw_die_page);
		}
	}
	
	
	static public function sfwLogs($api_key, $data){
		$url='https://api.cleantalk.org';
		$request = array(
			'auth_key' => $api_key,
			'method_name' => 'sfw_logs',
			'data' => json_encode($data),
			'rows' => count($data),
			'timestamp' => time()
		);
		$result = self::sendRawRequest($url, $request);
		return $result;
	}
	
	static public function get_2sBlacklistsDb($api_key){
		$url='https://api.cleantalk.org';
		$request = array(
			'auth_key' => $api_key,
			'method_name' => '2s_blacklists_db'
		);
		$result = self::sendRawRequest($url, $request);
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
	
	static function apache_request_headers(){
		
		if(defined('IN_PHPBB')){
			global $request;
			$_SERVER = $request->get_super_global(\phpbb\request\request_interface::SERVER);
		}
		
		$to_return = array();
		foreach($_SERVER as $key => $val){
			if(preg_match('/\AHTTP_/', $key)){
				$arh_key = preg_replace('/\AHTTP_/', '', $key);
				$rx_matches = array();
				$rx_matches = explode('_', $arh_key);
				if(count($rx_matches) > 0 and strlen($arh_key) > 2){
					foreach($rx_matches as $ak_key => $ak_val){
						$ak_val = strtolower($ak_val);
						$rx_matches[$ak_key] = ucfirst($ak_val);
					}
					$arh_key = implode('-', $rx_matches);
				}
				$to_return[$arh_key] = $val;
			}
		}
		return $to_return;
	}
}
