<?php

/*
*	CleanTalk SpamFireWall base class
*	Version 1.0
*	Compatible only with phpBB 3.1
*/


namespace CleanTalkBaseSFW;

class CleanTalkSFW
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
		
	}
	
	public function unversal_query($query){
		
		if(defined("IN_PHPBB"))
			$this->db_result = $this->db->sql_query($query);
				
	}
	
	public function unversal_fetch(){
		
		if(defined("IN_PHPBB")){
			$this->db_result_data = $this->db->sql_fetchrow($this->db_result);
			$this->db->sql_freeresult($this->result);
		}
		
	}
	
	
	/*
	*	Getting IP function
	*	Version 1.1
	*	Compatible with any CMS
	*/
	public function cleantalk_get_real_ip()
	{
		$result=Array();
		if(function_exists('apache_request_headers')){
			$headers = apache_request_headers();
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
		}else{
			if(defined("IN_PHPBB")){
				global $request;
				$headers['REMOTE_ADDR'] = $request->server('REMOTE_ADDR');
				$headers['X-Forwarded-For'] = $request->server('X-Forwarded-For');
				$headers['HTTP_X_FORWARDED_FOR'] = $request->server('HTTP_X_FORWARDED_FOR');
				$sfw_test_ip = $request->variable('sfw_test_ip', '');
			}else{
				$headers = $_SERVER;
				$headers['REMOTE_ADDR'] = $_SERVER['REMOTE_ADDR'];
				$headers['X-Forwarded-For'] = isset($headers['X-Forwarded-For']) ? $headers['X-Forwarded-For'] : null;
				$headers['HTTP_X_FORWARDED_FOR'] = isset($headers['HTTP_X_FORWARDED_FOR']) ? $headers['HTTP_X_FORWARDED_FOR'] : null;
				$sfw_test_ip = isset($_GET['sfw_test_ip']) ? $_GET['sfw_test_ip'] : null;
			}
		}
		
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
					
		for($i=0;$i<sizeof($this->ip_array);$i++){
			
			$query = "select count(network) as cnt from `".$this->table_prefix."cleantalk_sfw` where network = ".$this->ip_array[$i]." & mask;";
			$this->unversal_query($query);
			$this->unversal_fetch();
			
			if($this->db_result_data['cnt']){
				$this->result=true;
				$this->blocked_ip=$this->ip_str_array[$i];
			}else{
				$this->passed_ip = $this->ip_str_array[$i];
			}
			
		}
		if($this->passed_ip!=''){
			@setcookie ('ct_sfw_pass_key', md5($this->passed_ip.$ct_options['apikey']), 0, "/");
		}
	}
		
	/*
	*	Add entries to SFW log
	*	Version 1.1
	*	Compatible with any CMS
	*/
	public function sfw_update_logs($ip, $result){
						
		if($ip === NULL || $result === NULL){
			error_log('SFW log update failed');
			return;
		}
				
		$blocked = ($result == 'blocked' ? ' + 1' : '');
		$time = time();

		$query = "INSERT INTO `".$this->table_prefix."cleantalk_sfw_logs`
		SET 
			`ip` = '$ip',
			`all_entries` = 1,
			`blocked_entries` = 1,
			`entries_timestamp` = '".$time."'
		ON DUPLICATE KEY 
		UPDATE 
			`all_entries` = `all_entries` + 1,
			`blocked_entries` = `blocked_entries`".$blocked.",
			`entries_timestamp` = '".$time."'";

		$this->unversal_query($query);
	}
	
	/*
	*	Updates SFW local base
	*	Version 1.1
	*	Compatible only with phpBB 3.1
	*/
	static public function sfw_update($ct_key){
		global $db, $table_prefix;
		
		if(!function_exists('sendRawRequest'))
			require_once('cleantalk.class.php');
		
		$data = Array('auth_key' => $ct_key, 'method_name' => '2s_blacklists_db');	
		$result = \CleanTalkBase\sendRawRequest("https://api.cleantalk.org/?auth_key=$ct_key&method_name=2s_blacklists_db",$data,false);

		$result = json_decode($result, true);
		
		if(isset($result['data'])){

			$db->sql_query("TRUNCATE TABLE `".$table_prefix."cleantalk_sfw`;");
			
			$result=$result['data'];
			$query="INSERT INTO `".$table_prefix."cleantalk_sfw` VALUES ";
			for($i=0;$i<sizeof($result);$i++){
				if($i==sizeof($result)-1){
					$query.="(".$result[$i][0].",".$result[$i][1].");";
				}else{
					$query.="(".$result[$i][0].",".$result[$i][1]."), ";
				}
			}
			$db->sql_query($query);
		}
	}
	
	/*
	*	Sends and wipe SFW log
	*	Version 1.1
	*	Compatible only with phpBB 3.1
	*/
	public static function send_logs($ct_key){
		
		global $db, $table_prefix;
		
		//Getting logs
		$result = $db->sql_query("SELECT * FROM `".$table_prefix."cleantalk_sfw_logs`");
		$result = $db->sql_fetchrowset($result);
			
		if(count($result)){
			//Compile logs
			$data = array();
			
			$for_return['all_entries'] = 0;
			$for_return['blocked_entries'] = 0;
			
			foreach($result as $key => $value){
				//Compile log
				$data[] = array(trim($value['ip']), $value['all_entries'], $value['all_entries']-$value['blocked_entries'], $value['entries_timestamp']);
				//Compile to return;
				$for_return['all_entries'] = $for_return['all_entries'] + $value['all_entries'];
				$for_return['blocked_entries'] = $for_return['blocked_entries'] + $value['blocked_entries'];
			}
			unset($key, $value);
			$db->sql_freeresult($result);
			
			//Final compile
			$qdata = array (
				'data' => json_encode($data),
				'rows' => count($data),
				'timestamp' => time()
			);
			
			if(!function_exists('sendRawRequest'))
				require_once('cleantalk.class.php');
			
			//Sendings request
			$result=\CleanTalkBase\sendRawRequest("https://api.cleantalk.org/?method_name=sfw_logs&auth_key=$ct_key", $qdata, false);
			$result = json_decode($result);
						
			//Checking answer and truncate table
			if(isset($result->data) && isset($result->data->rows))
				if($result->data->rows == count($data)){
					$db->sql_query("TRUNCATE TABLE `".$table_prefix."cleantalk_sfw_logs`");
					return $for_return;
				}
				
		}else		
			return false;
	}
	
	/*
	*	Shows DIE page
	*	Version 1.1
	*	Compatible with any CMS
	*/	
	public function sfw_die($api_key){
		
		if(defined("IN_PHPBB")){
			global $request;
			$request_uri = $request->server('REQUEST_URI');
		}else{
			$request_uri = $_SERVER['REQUEST_URI'];
		}
		
		$sfw_die_page = file_get_contents(dirname(__FILE__)."/sfw_die_page.html");
		$sfw_die_page = str_replace("{REMOTE_ADDRESS}", $this->blocked_ip, $sfw_die_page);
		$sfw_die_page = str_replace("{REQUEST_URI}", $request_uri, $sfw_die_page);
		$sfw_die_page = str_replace("{SFW_COOKIE}", md5($this->blocked_ip.$api_key), $sfw_die_page);
		@header('Cache-Control: no-cache');
		@header('Expires: 0');
		@header('HTTP/1.0 403 Forbidden');
		
		if(defined('WPINC'))
			wp_die($sfw_die_page, "Blacklisted", Array('response'=>403));
		else
			die($sfw_die_page);
	}
}
