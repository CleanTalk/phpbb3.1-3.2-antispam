<?php
/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org) 
* @copyright (C) 2014 СleanTalk team (http://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
* Translated By : Lord Phobos
*/

if (!defined('IN_PHPBB'))
{
	exit;
}

if (empty($lang) || !is_array($lang))
{
	$lang = array();
}

$lang = array_merge($lang, array(
	'ACP_CLEANTALK_TITLE'			            => 'Antispam by CleanTalk',

	'ACP_CLEANTALK_SETTINGS'		            => 'Impostazioni di protezione dallo spam',
	'ACP_CLEANTALK_SETTINGS_SAVED'		        => 'Le impostazioni di protezione dallo spam sono state salvate con successo!',

	'ACP_CLEANTALK_REGS_LABEL'		            => 'Controlla Registrazioni',
	'ACP_CLEANTALK_REGS_DESCR'		            => 'Gli Spam-bots saranno rifiutati con una dichiarazione di ragioni.',

	'ACP_CLEANTALK_GUESTS_LABEL'		        => 'Modera Ospiti',
	'ACP_CLEANTALK_GUESTS_DESCR'		        => 'Post e topic dagli utenti verranno controllati per lo spam. Lo spam sarà rifiutato o inviato per l’approvazione.',

	'ACP_CLEANTALK_NUSERS_LABEL'		        => 'Modera i Nuovi Utenti Registrati',
	'ACP_CLEANTALK_NUSERS_DESCR'		        => 'Post e topic dei nuovi utenti registrati verranno controllati per lo spam. Lo spam sarà rifiutato o inviato per l’approvazione.',

	'ACP_CLEANTALK_APIKEY_LABEL'		        => 'Chiave d’accesso',
	'ACP_CLEANTALK_APIKEY_DESCR'		        => 'Per ottenere una chiave d’accesso si prega di registrarsi al sito ',

	'MAIL_CLEANTALK_ERROR'			            => 'Errore nel tentativo di connessione al servizio CleanTalk',
	'LOG_CLEANTALK_ERROR'			            => '<strong>Errore nel tentativo di connessione al servizio CleanTalk</strong><br />%s',
	'ACP_CLEANTALK_CHECKUSERS_TITLE'			=> 'Controlla utenti per lo spam',
	'ACP_CLEANTALK_CHECKUSERS_DESCRIPTION'		=> "L’Anti-spam by CleanTalk controllerà tutti gli utenti con database delle blacklist e ti mostretà utenti che praticano attività di spam su altri siti web. Clicca semplicemente su ’Controlla gli Utenti per Spam’ per iniziare.",
	'ACP_CLEANTALK_CHECKUSERS_BUTTON'			=> 'Controlla gli Utenti per Spam',
	'ACP_CHECKUSERS_DONE_1'                     => 'Fatto. Controllati tutti gli utenti sui database delle blacklist, vedere sotto i risultati.',
	'ACP_CHECKUSERS_DONE_2'                     => 'Fatto. Controllati tutti gli utenti sui database delle blacklist, trovati 0 utenti spam.',
	'ACP_CHECKUSERS_SELECT'                     => 'Seleziona',
	'ACP_CHECKUSERS_USERNAME'                   => 'Username',
	'ACP_CHECKUSERS_MESSAGES'                   => 'Messaggi',
	'ACP_CHECKUSERS_JOINED'                     => 'Iscritto',
	'ACP_CHECKUSERS_EMAIL'                      => 'Email',
	'ACP_CHECKUSERS_IP'                         => 'IP',
	'ACP_CHECKUSERS_LASTVISIT'                  => 'Ultima visita',
	'ACP_CHECKUSERS_DELETEALL'                  => 'Cancella tutto',
	'ACP_CHECKUSERS_DELETEALL_DESCR'            => 'Anche tutti i post degli utenti cancellati verranno rimossi.',
	'ACP_CHECKUSERS_DELETESEL'                  => 'Cancella selezionati',
));
