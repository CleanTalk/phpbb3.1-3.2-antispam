<?php

/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (https://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
*/

if (!defined('IN_PHPBB')) {
    exit;
}

if (empty($lang) || !is_array($lang)) {
    $lang = array();
}

$lang = array_merge($lang, array(
    'ACP_CLEANTALK_TITLE'                       => 'Антиспам от CleanTalk',
    'ACP_CLEANTALK_SETTINGS'                    => 'Настройки защиты от спама',
    'ACP_CLEANTALK_SETTINGS_SAVED'              => 'Настройки защиты от спама сохранены!',

    'ACP_CLEANTALK_REGS_LABEL'                  => 'Проверять регистрации',
    'ACP_CLEANTALK_REGS_DESCR'                  => 'Спам-боты будут отвергнуты с выводом причины.',

    'ACP_CLEANTALK_GUESTS_LABEL'                => 'Проверять анонимных',
    'ACP_CLEANTALK_GUESTS_DESCR'                => 'Посты и темы от анонимных будут проверяться на спам. Спам будет отвергнут или направлен на одобрение.',

    'ACP_CLEANTALK_NUSERS_LABEL'                => 'Проверять вновь зарегистрированных',
    'ACP_CLEANTALK_NUSERS_DESCR'                => 'Посты и темы от вновь зарегистрированных будут проверяться на спам. Спам будет отвергнут или направлен на одобрение.',

    'ACP_CLEANTALK_ALLUSERS_LABEL'              => 'Проверять всех зарегистрированных',
    'ACP_CLEANTALK_ALLUSERS_DESCR'              => 'Посты и темы от всех зарегистрированных пользователей будут проверяться на спам, а не только от вновь зарегистрированных. Спам будет отвергнут или направлен на одобрение.',

    'ACP_CLEANTALK_CCF_LABEL'                   => 'Проверять контактные формы',
    'ACP_CLEANTALK_CCF_DESCR'                   => 'Включить антиспам тест для контактной формы. Внимание, возможны конфликты!',

    'ACP_CLEANTALK_SFW_LABEL'                   => 'SpamFireWall',
    'ACP_CLEANTALK_SFW_DESCR'                   => 'Включает SpamFireWall. Это не даст ботам зайти на сайт и позволит снизить нагрузку на веб-сервер.',

    'ACP_CLEANTALK_APIKEY_LABEL'                => 'Ключ доступа',
    'ACP_CLEANTALK_APIKEY_LABEL_PLACEHOLDER'    => 'Введите ключ доступа',
    'ACP_CLEANTALK_APIKEY_DESCR'                => 'Для получения зарегистрируйтесь на сайте ',
    'ACP_CLEANTALK_REG_NOTICE'                  => 'E-mail форума',
    'ACP_CLEANTALK_REG_NOTICE2'                 => 'будет использован для регистрации',
    'ACP_CLEANTALK_AGREEMENT'                   => 'Лицензионное соглашение',
    'ACP_CLEANTALK_APIKEY_IS_OK_LABEL'          => 'Ключ действителен.',
    'ACP_CLEANTALK_APIKEY_IS_BAD_LABEL'         => 'Ключ не действителен!',
    'ACP_CLEANTALK_APIKEY_GET_AUTO_BUTTON_LABEL'        => 'Получить ключ автоматически',
    'ACP_CLEANTALK_APIKEY_GET_MANUALLY_BUTTON_LABEL'    => 'Получить ключ вручную',
    'ACP_CLEANTALK_APIKEY_CP_LINK_BUTTON'       => 'Перейти в панель управления CleanTalk',
    'ACP_CLEANTALK_ACCOUNT_NAME_OB'             => 'Аккаунт на cleantalk.org',
    'ACP_CLEANTALK_TITLE__STATS'                => 'Статистика',
    'ACP_CLEANTALK_STATS__SFW_NETS'             => 'Количество сетей SpamFireWall',
    'ACP_CLEANTALK_CHECKUSERS_TITLE'            => 'Проверить пользователей на спам',
    'ACP_CLEANTALK_CHECKUSERS_DESCRIPTION'      => 'Антиспам от CleanTalk проверит всех пользователей по черным спискам и покажет вам тех, кто проявил спам-активность на других сайтах. ',
    'ACP_CLEANTALK_CHECKUSERS_PAGES_TITLE'      => 'Страницы:',
    'ACP_CLEANTALK_CHECKUSERS_BUTTON'           => 'Проверить на спам',
    'ACP_CLEANTALK_CHECKUSERS_NUMBER_DESCRIPTION' => 'Количество непроверенных пользователей для проверки. Оставьте его пустым, чтобы сбросить флаги и начать полное сканирование.',
    'ACP_CHECKUSERS_DONE_2'                     => 'Готово. Все пользователи проверены на спам, найдено 0 результатов',
    'ACP_CHECKUSERS_DONE_3'                     => 'Ошибка. Нет соединения с базой данных черных списков.',
    'ACP_CHECKUSERS_USERNAME'                   => 'Пользователь',
    'ACP_CHECKUSERS_MESSAGES'                   => 'Сообщений',
    'ACP_CHECKUSERS_JOINED'                     => 'Присоединился',
    'ACP_CHECKUSERS_EMAIL'                      => 'Email',
    'ACP_CHECKUSERS_IP'                         => 'IP',
    'ACP_CHECKUSERS_LASTVISIT'                  => 'Последний визит',
    'ACP_CHECKUSERS_DELETEALL'                  => 'Удалить всех',
    'ACP_CHECKUSERS_DELETEALL_DESCR'            => 'Все посты выбранных пользователей будут тоже удалены',
    'ACP_CHECKUSERS_DELETESEL'                  => 'Удалить выбранных',
    'ACP_CLEANTALK_MODERATE_IP'                 => 'Антиспам сервис оплачен вашим хостин провайдером. Лицензия #',
    'SFW_DIE_NOTICE_IP'                         => 'SpamFireWall включен для вашего IP',
    'SFW_DIE_MAKE_SURE_JS_ENABLED'              => 'Что бы продолжить работу с сайтом, убедитесь что у вас включен JavaScript.',
    'SFW_DIE_CLICK_TO_PASS'                     => 'Нажмите ниже что снять блокировку',
    'SFW_DIE_YOU_WILL_BE_REDIRECTED'            => 'Вы будете автоматически переадресовны на запрошенную вами страницу через 3 секунды.',

    'CLEANTALK_ERROR_MAIL'                      => 'Ошибка работы с сервисом CleanTalk',
    'CLEANTALK_ERROR_LOG'                       => '<strong>Ошибка работы с сервисом CleanTalk</strong><br />%s',
    'CLEANTALK_ERROR_CURL'                      => 'CURL ошибка: `%s`',
    'CLEANTALK_ERROR_NO_CURL'                   => 'Нет поддержки CURL',
    'CLEANTALK_ERROR_ADDON'                     => ' или выключена настройка allow_url_fopen в php.ini.',
    'CLEANTALK_NOTIFICATION'                    => 'Вы уверены?',

    'ACP_CLEANTALK_STATS__LAST_SPAM_REQUEST_TIME' => 'Последний спам запрос на сервер был',
    'ACP_CLEANTALK_STATS__AVERAGE_REQUEST_TIME' => 'Среднее время запроса за последние 7 дней (в секундах)',
    'ACP_CLEANTALK_STATS__LAST_SFW_BLOCK_IP' => 'В последний раз SpamFireWall сработал на IP',
    'ACP_CLEANTALK_STATS__LAST_SFW_BLOCK_TIME' => 'В последний раз SpamFireWall сработал в',
    'ACP_CLEANTALK_STATS__SFW_LAST_TIME_UPDATED' => 'SpamFireWall был обновлен',
    'ACP_CLEANTALK_STATS__SFW_LAST_TIME_SEND_LOGS' => 'SpamFireWall отправил логи',

    'ACP_CLEANTALK_BOT_DETECTOR_LABEL'          => 'Использовать JavaScript библиотеку CleanTalk',
    'ACP_CLEANTALK_BOT_DETECTOR_DESCR'          => 'Эта опция подключает внешнюю JavaScript библиотеку CleanTalk для сбора информации о посетителях. Для применения изменений необходимо очистить кеш страниц.',

    'ACP_CLEANTALK_PRIVACY_LEGEND'              => 'Конфиденциальность',
    'ACP_CLEANTALK_DATA_NOTICE'                 => 'Для проверки регистраций, сообщений и контактных форм на спам расширение передаёт на серверы CleanTalk e-mail, IP-адрес, user agent браузера, имя пользователя и текст сообщения отправителя, а также адрес страницы и реферер. SpamFireWall передаёт IP-адрес, user agent браузера и посещённые адреса заблокированных посетителей. Данные используются только для проверки на спам.',
    'ACP_CLEANTALK_PRIVACY_LINK'                => 'Политика конфиденциальности CleanTalk',
    'ACP_CLEANTALK_PRIVACY_CONFIRM_LABEL'       => 'Пользователи уведомлены',
    'ACP_CLEANTALK_PRIVACY_CONFIRM_DESCR'       => 'Защита от спама работает, только если эта опция включена. Также она добавляет раздел о CleanTalk в Политику конфиденциальности форума.',
    'ACP_CLEANTALK_PRIVACY_CONFIRM'             => 'Я уведомил пользователей, что их сообщения проверяются CleanTalk (политика конфиденциальности обновлена)',
    'ACP_CLEANTALK_PRIVACY_NOT_CONFIRMED'       => 'Защита от спама приостановлена. Данные не передаются в CleanTalk, пока вы не подтвердите, что пользователи уведомлены.',

    'CLEANTALK_PRIVACY_POLICY_TITLE'            => 'Защита от спама CleanTalk',
    'CLEANTALK_PRIVACY_POLICY_CHECKS'           => 'Когда вы регистрируетесь, публикуете сообщение или отправляете форму на конференции «%1$s», ваши e-mail, IP-адрес, user agent браузера, имя пользователя и текст сообщения, а также адрес страницы и страницы перехода передаются на серверы CleanTalk для проверки на спам.',
    'CLEANTALK_PRIVACY_POLICY_SFW'              => 'Чтобы остановить известных спам-ботов, IP-адрес каждого посетителя сравнивается с чёрным списком CleanTalk, хранящимся на этом форуме. IP-адрес, user agent браузера и посещённые адреса посетителей, которые были заблокированы или проходили проверку, периодически передаются в CleanTalk.',
    'CLEANTALK_PRIVACY_POLICY_BOT_DETECTOR'     => 'Страницы форума загружают с серверов CleanTalk JavaScript-файл, который собирает технические сведения о браузере и о том, как используется страница (например, активность мыши и клавиатуры), чтобы отличить человека от бота.',
    'CLEANTALK_PRIVACY_POLICY_COOKIES'          => 'Для проверки на спам устанавливаются cookie, например чтобы убедиться, что в браузере включены JavaScript и cookie.',
    'CLEANTALK_PRIVACY_POLICY_PURPOSE'          => 'Эти данные используются только для защиты конференции «%1$s» от спама. CleanTalk обрабатывает их в соответствии со своей политикой конфиденциальности:',

    'CLEANTALK_REQUIREMENTS_PHP'                => '??? Antispam by CleanTalk ????????? PHP %s ??? ?????.',
));
