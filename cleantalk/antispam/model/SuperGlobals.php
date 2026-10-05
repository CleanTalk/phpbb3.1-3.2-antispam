<?php
/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (https://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
*/

namespace cleantalk\antispam\model;

/**
* Keeps the phpBB superglobals state while CleanTalk Common libraries need them enabled.
*/
class SuperGlobals
{
	/**
	* Current state of phpBB superglobals.
	* Another integration (phpBB embedded into Joomla, etc.) may have enabled them intentionally.
	* Returns false for an unusable request object, so nothing gets changed afterwards.
	*
	* @param \phpbb\request\request	$request
	* @return bool
	*/
	static public function areDisabled($request)
	{
		return is_object($request)
			&& method_exists($request, 'super_globals_disabled')
			&& $request->super_globals_disabled();
	}

	/**
	* Restores the superglobals state captured before CleanTalk processing
	*
	* @param \phpbb\request\request	$request
	* @param bool	$were_disabled
	*/
	static public function restore($request, $were_disabled)
	{
		if ($were_disabled && is_object($request) && method_exists($request, 'disable_super_globals'))
		{
			$request->disable_super_globals();
		}
	}
}
