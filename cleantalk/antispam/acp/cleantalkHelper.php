<?php
/**
 * Cleantalk base class for PHPBB 3.1
 *
 * @version 2.1.3-phpbb
 * @package Cleantalk
 * @subpackage Base
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam 
 *
 */

namespace cleantalk\antispam\acp;

/**
 * Cleantalk class with differernt functions
 */
class cleantalkHelper{
		
	static public function noticeValidateKey($api_key){
		$request = array();
		$request['method_name'] = 'notice_validate_key'; 
		$request['auth_key'] = $api_key;
		$url='https://api.cleantalk.org';
		$result = self::sendRawRequest($url, $request);
		return $result;
	}
	
	/**
	 * Function gets access key automatically
	 *
	 * @param string website admin email
	 * @param string website host
	 * @param string website platform
	 * @return type
	 */
	static public function getAutoKey($email, $host, $platform, $timezone = null){
		$request = array();
		$request['method_name'] = 'get_api_key'; 
		$request['email'] = $email;
		$request['website'] = $host;
		$request['platform'] = $platform;
		$request['timezone'] = $timezone;
		$request['product_name'] = 'antispam';
		$url='https://api.cleantalk.org';
		$result = self::sendRawRequest($url, $request);
		return $result;
	}

	/**
	 * Function gets information about renew notice
	 *
	 * @param string api_key
	 * @return type
	 */

	static public function noticePaidTill($api_key)
	{
		$request = array();
		$request['method_name'] = 'notice_paid_till'; 
		$request['auth_key'] = $api_key;
		$url='https://api.cleantalk.org';
		$result = self::sendRawRequest($url, $request);
		return $result;
	}

	/**
	 * Function gets spam report
	 *
	 * @param string website host
	 * @param integer report days
	 * @return type
	 */
	static public function getAntispamReport($host, $period = 1){
		$url='https://api.cleantalk.org';
		$request = array(
			'method_name' => 'get_antispam_report',
			'hostname' => $host,
			'period' => $period
		);
		$result = self::sendRawRequest($url, $request);
		return $result;
	}	
	
	
	/**
	 * Function gets spam statistics
	 *
	 * @param string website host
	 * @param integer report days
	 * @return type
	 */

	function getAntispamReportBreif($key=''){
		
		$url="https://api.cleantalk.org?auth_key=$key";
		$request=Array(
			'method_name' => 'get_antispam_report_breif'
		);
		$result = sendRawRequest($url,$request);
						
		if($result === false){
			return "Network error. Please, check <a target='_blank' href='https://cleantalk.org/help/faq-setup#hosting'>this article</a>.";
		}
		
		$result = !empty($result) ? json_decode($result, true) : false;
				
		if(!empty($result['error_message'])){
			return  $result['error_message'];
		}else{
			$tmp = array();
			for($i=0; $i<7; $i++)
				$tmp[date("Y-m-d", time()-86400*7+86400*$i)] = 0;
			$result['data']['spam_stat'] = array_merge($tmp, $result['data']['spam_stat']);			
			return $result['data'];
		}
	}
	
	static public function spamCheckCms($api_key, $data){
		$request = array();
		$url='https://api.cleantalk.org';
		$request = array(
			'method_name' => 'spam_check_cms',
			'auth_key' => $api_key,
			'data' => $data //string "ip1,ip2,ip3..."
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
}