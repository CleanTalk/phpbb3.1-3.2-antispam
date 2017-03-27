<?php
/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (http://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
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
  'ACP_CLEANTALK_TITLE'			            => 'Antispam von CleanTalk',

  'ACP_CLEANTALK_SETTINGS'		            => 'SPAM-Schutz Einstellungen',
  'ACP_CLEANTALK_SETTINGS_SAVED'		        => 'SPAM-Schutz-Einstellungen wurden erfolgreich gespeichert!',

  'ACP_CLEANTALK_REGS_LABEL'		            => 'Prüfe Registrierungen',
  'ACP_CLEANTALK_REGS_DESCR'		            => 'SPAM-Bots werden mit einer Begrüdung abgewiesen.',

  'ACP_CLEANTALK_GUESTS_LABEL'		        => 'Moderiere Gäste',
  'ACP_CLEANTALK_GUESTS_DESCR'		        => 'Beiträge und Themen von Gästen werden auf SPAM geprüft. SPAM wird abgelehnt oder zur Prüfung weitergeleitet.',

  'ACP_CLEANTALK_NUSERS_LABEL'		        => 'Moderiere neu registrierte Benutzer Newly Registered Users',
  'ACP_CLEANTALK_NUSERS_DESCR'		        => 'Beiträge und Themen von neuen Benutzern werden auf SPAM geprüft. SPAM wird abgelehnt oder zur Prüfung weitergeleitet.',

  'ACP_CLEANTALK_APIKEY_LABEL'		        => 'Zugangsschlüssel',
  'ACP_CLEANTALK_APIKEY_DESCR'		        => 'Um ein Zugangsschlüssel zu bekommen, registriere dich auf der Seite ',

  'MAIL_CLEANTALK_ERROR'			            => 'Fehler beim verbinden zum CleanTalk Service',
  'LOG_CLEANTALK_ERROR'			            => '<strong>Fehler beim verbinden zum CleanTalk Service</strong><br />%s',
  'ACP_CLEANTALK_CHECKUSERS_TITLE'			=> 'Prüfe Benutzer auf SPAM',
  'ACP_CLEANTALK_CHECKUSERS_DESCRIPTION'		=> "Antispam von CleanTalk wird Benutzer in der Sperrlisten-Daten prüfen und alle anzeigen, welche SPAM-Aktivitäten auf anderen Webseiten gezeigt haben. Klicke auf 'Prüfe Benutzer auf SPAM', um den Vorgang zu starten.",
  'ACP_CLEANTALK_CHECKUSERS_BUTTON'			=> 'Prüfe Benutzer auf SPAM',
  'ACP_CHECKUSERS_DONE_1'                     => 'Fertig. Alle Benutzer wurden in der Sperrlisten-Datenbank geprüft. Ergebnisse findest du unten.',
  'ACP_CHECKUSERS_DONE_2'                     => 'Fertig. Alle Benutzer wurden in der Sperrlisten-Datenbank geprüft und es wurde dort kein Benutzer gefunden.',
  'ACP_CHECKUSERS_SELECT'                     => 'Auswählen',
  'ACP_CHECKUSERS_USERNAME'                   => 'Benutzername',
  'ACP_CHECKUSERS_MESSAGES'                   => 'Nachricht',
  'ACP_CHECKUSERS_JOINED'                     => 'Registriert',
  'ACP_CHECKUSERS_EMAIL'                      => 'E-Mail',
  'ACP_CHECKUSERS_IP'                         => 'IP',
  'ACP_CHECKUSERS_LASTVISIT'                  => 'Letzter Besuch',
  'ACP_CHECKUSERS_DELETEALL'                  => 'Lösche alle Benutzer',
  'ACP_CHECKUSERS_DELETEALL_DESCR'            => 'Alle Beiträge der gelöschten Benutzer werden auch gelöscht.',
  'ACP_CHECKUSERS_DELETESEL'                  => 'Lösche ausgewählte Benutzer',
));
