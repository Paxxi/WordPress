<?php
/**
 * WordPress Administration Scheme API
 *
 * Here we keep the DB structure and option values.
 *
 * @package WordPress
 * @subpackage Administration
 */

/**
 * The database character collate.
 * @var string
 * @global string
 * @name $charset_collate
 */
$charset_collate = '';

// Declare these as global in case schema.php is included from a function.
global $wpdb, $wp_queries;

if ( ! empty($wpdb->charset) )
	$charset_collate = "DEFAULT CHARACTER SET $wpdb->charset";
if ( ! empty($wpdb->collate) )
	$charset_collate .= " COLLATE $wpdb->collate";

/** Create WordPress database tables SQL */
$wp_queries = "CREATE TABLE $wpdb->terms (
 term_id bigint(20) unsigned NOT NULL auto_increment,
 name varchar(200) NOT NULL default '',
 slug varchar(200) NOT NULL default '',
 term_group bigint(10) NOT NULL default 0,
 PRIMARY KEY  (term_id),
 UNIQUE KEY slug (slug),
 KEY name (name)
) $charset_collate;
CREATE TABLE $wpdb->term_taxonomy (
 term_taxonomy_id bigint(20) unsigned NOT NULL auto_increment,
 term_id bigint(20) unsigned NOT NULL default 0,
 taxonomy varchar(32) NOT NULL default '',
 description longtext NOT NULL,
 parent bigint(20) unsigned NOT NULL default 0,
 count bigint(20) NOT NULL default 0,
 PRIMARY KEY  (term_taxonomy_id),
 UNIQUE KEY term_id_taxonomy (term_id,taxonomy),
 KEY taxonomy (taxonomy)
) $charset_collate;
CREATE TABLE $wpdb->term_relationships (
 object_id bigint(20) unsigned NOT NULL default 0,
 term_taxonomy_id bigint(20) unsigned NOT NULL default 0,
 term_order int(11) NOT NULL default 0,
 PRIMARY KEY  (object_id,term_taxonomy_id),
 KEY term_taxonomy_id (term_taxonomy_id)
) $charset_collate;
CREATE TABLE $wpdb->commentmeta (
  meta_id bigint(20) unsigned NOT NULL auto_increment,
  comment_id bigint(20) unsigned NOT NULL default '0',
  meta_key varchar(255) default NULL,
  meta_value longtext,
  PRIMARY KEY  (meta_id),
  KEY comment_id (comment_id),
  KEY meta_key (meta_key)
) $charset_collate;
CREATE TABLE $wpdb->comments (
  comment_ID bigint(20) unsigned NOT NULL auto_increment,
  comment_post_ID bigint(20) unsigned NOT NULL default '0',
  comment_author tinytext NOT NULL,
  comment_author_email varchar(100) NOT NULL default '',
  comment_author_url varchar(200) NOT NULL default '',
  comment_author_IP varchar(100) NOT NULL default '',
  comment_date datetime NOT NULL default '0000-00-00 00:00:00',
  comment_date_gmt datetime NOT NULL default '0000-00-00 00:00:00',
  comment_content text NOT NULL,
  comment_karma int(11) NOT NULL default '0',
  comment_approved varchar(20) NOT NULL default '1',
  comment_agent varchar(255) NOT NULL default '',
  comment_type varchar(20) NOT NULL default '',
  comment_parent bigint(20) unsigned NOT NULL default '0',
  user_id bigint(20) unsigned NOT NULL default '0',
  PRIMARY KEY  (comment_ID),
  KEY comment_approved (comment_approved),
  KEY comment_post_ID (comment_post_ID),
  KEY comment_approved_date_gmt (comment_approved,comment_date_gmt),
  KEY comment_date_gmt (comment_date_gmt)
) $charset_collate;
CREATE TABLE $wpdb->links (
  link_id bigint(20) unsigned NOT NULL auto_increment,
  link_url varchar(255) NOT NULL default '',
  link_name varchar(255) NOT NULL default '',
  link_image varchar(255) NOT NULL default '',
  link_target varchar(25) NOT NULL default '',
  link_description varchar(255) NOT NULL default '',
  link_visible varchar(20) NOT NULL default 'Y',
  link_owner bigint(20) unsigned NOT NULL default '1',
  link_rating int(11) NOT NULL default '0',
  link_updated datetime NOT NULL default '0000-00-00 00:00:00',
  link_rel varchar(255) NOT NULL default '',
  link_notes mediumtext NOT NULL,
  link_rss varchar(255) NOT NULL default '',
  PRIMARY KEY  (link_id),
  KEY link_visible (link_visible)
) $charset_collate;
CREATE TABLE $wpdb->options (
  option_id bigint(20) unsigned NOT NULL auto_increment,
  blog_id int(11) NOT NULL default '0',
  option_name varchar(64) NOT NULL default '',
  option_value longtext NOT NULL,
  autoload varchar(20) NOT NULL default 'yes',
  PRIMARY KEY  (option_id),
  UNIQUE KEY option_name (option_name)
) $charset_collate;
CREATE TABLE $wpdb->postmeta (
  meta_id bigint(20) unsigned NOT NULL auto_increment,
  post_id bigint(20) unsigned NOT NULL default '0',
  meta_key varchar(255) default NULL,
  meta_value longtext,
  PRIMARY KEY  (meta_id),
  KEY post_id (post_id),
  KEY meta_key (meta_key)
) $charset_collate;
CREATE TABLE $wpdb->posts (
  ID bigint(20) unsigned NOT NULL auto_increment,
  post_author bigint(20) unsigned NOT NULL default '0',
  post_date datetime NOT NULL default '0000-00-00 00:00:00',
  post_date_gmt datetime NOT NULL default '0000-00-00 00:00:00',
  post_content longtext NOT NULL,
  post_title text NOT NULL,
  post_excerpt text NOT NULL,
  post_status varchar(20) NOT NULL default 'publish',
  comment_status varchar(20) NOT NULL default 'open',
  ping_status varchar(20) NOT NULL default 'open',
  post_password varchar(20) NOT NULL default '',
  post_name varchar(200) NOT NULL default '',
  to_ping text NOT NULL,
  pinged text NOT NULL,
  post_modified datetime NOT NULL default '0000-00-00 00:00:00',
  post_modified_gmt datetime NOT NULL default '0000-00-00 00:00:00',
  post_content_filtered text NOT NULL,
  post_parent bigint(20) unsigned NOT NULL default '0',
  guid varchar(255) NOT NULL default '',
  menu_order int(11) NOT NULL default '0',
  post_type varchar(20) NOT NULL default 'post',
  post_mime_type varchar(100) NOT NULL default '',
  comment_count bigint(20) NOT NULL default '0',
  PRIMARY KEY  (ID),
  KEY post_name (post_name),
  KEY type_status_date (post_type,post_status,post_date,ID),
  KEY post_parent (post_parent)
) $charset_collate;
CREATE TABLE $wpdb->users (
  ID bigint(20) unsigned NOT NULL auto_increment,
  user_login varchar(60) NOT NULL default '',
  user_pass varchar(64) NOT NULL default '',
  user_nicename varchar(50) NOT NULL default '',
  user_email varchar(100) NOT NULL default '',
  user_url varchar(100) NOT NULL default '',
  user_registered datetime NOT NULL default '0000-00-00 00:00:00',
  user_activation_key varchar(60) NOT NULL default '',
  user_status int(11) NOT NULL default '0',
  display_name varchar(250) NOT NULL default '',
  PRIMARY KEY  (ID),
  KEY user_login_key (user_login),
  KEY user_nicename (user_nicename)
) $charset_collate;
CREATE TABLE $wpdb->usermeta (
  umeta_id bigint(20) unsigned NOT NULL auto_increment,
  user_id bigint(20) unsigned NOT NULL default '0',
  meta_key varchar(255) default NULL,
  meta_value longtext,
  PRIMARY KEY  (umeta_id),
  KEY user_id (user_id),
  KEY meta_key (meta_key)
) $charset_collate;";

/**
 * Create WordPress options and set the default values.
 *
 * @since 1.5.0
 * @uses $wpdb
 * @uses $wp_db_version
 */
function populate_options() {
	global $wpdb, $wp_db_version;

	$guessurl = wp_guess_url();

	do_action('populate_options');

	if ( ini_get('safe_mode') ) {
		// Safe mode can break mkdir() so use a flat structure by default.
		$uploads_use_yearmonth_folders = 0;
	} else {
		$uploads_use_yearmonth_folders = 1;
	}

	$options = array(
	'siteurl' => $guessurl,
	'blogname' => __('My Blog'),
	'blogdescription' => __('Just another WordPress weblog'),
	'users_can_register' => 0,
	'admin_email' => 'you@example.com',
	'start_of_week' => 1,
	'use_balanceTags' => 0,
	'use_smilies' => 1,
	'require_name_email' => 1,
	'comments_notify' => 1,
	'posts_per_rss' => 10,
	'rss_use_excerpt' => 0,
	'mailserver_url' => 'mail.example.com',
	'mailserver_login' => 'login@example.com',
	'mailserver_pass' => 'password',
	'mailserver_port' => 110,
	'default_category' => 1,
	'default_comment_status' => 'open',
	'default_ping_status' => 'open',
	'default_pingback_flag' => 1,
	'default_post_edit_rows' => 10,
	'posts_per_page' => 10,
	/* translators: default date format, see http://php.net/date */
	'date_format' => __('F j, Y'),
	/* translators: default time format, see http://php.net/date */
	'time_format' => __('g:i a'),
	/* translators: links last updated date format, see http://php.net/date */
	'links_updated_date_format' => __('F j, Y g:i a'),
	'links_recently_updated_prepend' => '<em>',
	'links_recently_updated_append' => '</em>',
	'links_recently_updated_time' => 120,
	'comment_moderation' => 0,
	'moderation_notify' => 1,
	'permalink_structure' => '',
	'gzipcompression' => 0,
	'hack_file' => 0,
	'blog_charset' => 'UTF-8',
	'moderation_keys' => '',
	'active_plugins' => array(),
	'home' => $guessurl,
	'category_base' => '',
	'ping_sites' => 'http://rpc.pingomatic.com/',
	'advanced_edit' => 0,
	'comment_max_links' => 2,
	'gmt_offset' => date('Z') / 3600,

	// 1.5
	'default_email_category' => 1,
	'recently_edited' => '',
	'use_linksupdate' => 0,
	'template' => 'default',
	'stylesheet' => 'default',
	'comment_whitelist' => 1,
	'blacklist_keys' => '',
	'comment_registration' => 0,
	'rss_language' => 'en',
	'html_type' => 'text/html',

	// 1.5.1
	'use_trackback' => 0,

	// 2.0
	'default_role' => 'subscriber',
	'db_version' => $wp_db_version,

	// 2.0.1
	'uploads_use_yearmonth_folders' => $uploads_use_yearmonth_folders,
	'upload_path' => '',

	// 2.0.3
	'secret' => wp_generate_password(64),

	// 2.1
	'blog_public' => '1',
	'default_link_category' => 2,
	'show_on_front' => 'posts',

	// 2.2
	'tag_base' => '',

	// 2.5
	'show_avatars' => '1',
	'avatar_rating' => 'G',
	'upload_url_path' => '',
	'thumbnail_size_w' => 150,
	'thumbnail_size_h' => 150,
	'thumbnail_crop' => 1,
	'medium_size_w' => 300,
	'medium_size_h' => 300,

	// 2.6
	'avatar_default' => 'mystery',
	'enable_app' => 0,
	'enable_xmlrpc' => 0,

	// 2.7
	'large_size_w' => 1024,
	'large_size_h' => 1024,
	'image_default_link_type' => 'file',
	'image_default_size' => '',
	'image_default_align' => '',
	'close_comments_for_old_posts' => 0,
	'close_comments_days_old' => 14,
	'thread_comments' => 0,
	'thread_comments_depth' => 5,
	'page_comments' => 1,
	'comments_per_page' => 50,
	'default_comments_page' => 'newest',
	'comment_order' => 'asc',
	'sticky_posts' => array(),
	'widget_categories' => array(),
	'widget_text' => array(),
	'widget_rss' => array(),

	// 2.8
	'timezone_string' => '',

	// 2.9
	'embed_autourls' => 1,
	'embed_size_w' => '',
	'embed_size_h' => 600,
	);

	// 3.0 multisite
	if ( is_multisite() ) {
		$options[ 'blogdescription' ] = sprintf(__('Just another %s site'), $current_site->site_name );
		$options[ 'permalink_structure' ] = '/%year%/%monthnum%/%day%/%postname%/';
	}

	// Set autoload to no for these options
	$fat_options = array( 'moderation_keys', 'recently_edited', 'blacklist_keys' );

	$existing_options = $wpdb->get_col("SELECT option_name FROM $wpdb->options");

	$insert = '';
	foreach ( $options as $option => $value ) {
		if ( in_array($option, $existing_options) )
			continue;
		if ( in_array($option, $fat_options) )
			$autoload = 'no';
		else
			$autoload = 'yes';

		$option = $wpdb->escape($option);
		if ( is_array($value) )
			$value = serialize($value);
		$value = $wpdb->escape($value);
		if ( !empty($insert) )
			$insert .= ', ';
		$insert .= "('$option', '$value', '$autoload')";
	}

	if ( !empty($insert) )
		$wpdb->query("INSERT INTO $wpdb->options (option_name, option_value, autoload) VALUES " . $insert);

	// in case it is set, but blank, update "home"
	if ( !__get_option('home') ) update_option('home', $guessurl);

	// Delete unused options
	$unusedoptions = array ('blodotgsping_url', 'bodyterminator', 'emailtestonly', 'phoneemail_separator', 'smilies_directory', 'subjectprefix', 'use_bbcode', 'use_blodotgsping', 'use_phoneemail', 'use_quicktags', 'use_weblogsping', 'weblogs_cache_file', 'use_preview', 'use_htmltrans', 'smilies_directory', 'fileupload_allowedusers', 'use_phoneemail', 'default_post_status', 'default_post_category', 'archive_mode', 'time_difference', 'links_minadminlevel', 'links_use_adminlevels', 'links_rating_type', 'links_rating_char', 'links_rating_ignore_zero', 'links_rating_single_image', 'links_rating_image0', 'links_rating_image1', 'links_rating_image2', 'links_rating_image3', 'links_rating_image4', 'links_rating_image5', 'links_rating_image6', 'links_rating_image7', 'links_rating_image8', 'links_rating_image9', 'weblogs_cacheminutes', 'comment_allowed_tags', 'search_engine_friendly_urls', 'default_geourl_lat', 'default_geourl_lon', 'use_default_geourl', 'weblogs_xml_url', 'new_users_can_blog', '_wpnonce', '_wp_http_referer', 'Update', 'action', 'rich_editing', 'autosave_interval', 'deactivated_plugins', 'can_compress_scripts',
		'page_uris', 'update_core', 'update_plugins', 'update_themes', 'doing_cron', 'random_seed', 'rss_excerpt_length');
	foreach ($unusedoptions as $option)
		delete_option($option);

	// delete obsolete magpie stuff
	$wpdb->query("DELETE FROM $wpdb->options WHERE option_name REGEXP '^rss_[0-9a-f]{32}(_ts)?$'");
}

/**
 * Execute WordPress role creation for the various WordPress versions.
 *
 * @since 2.0.0
 */
function populate_roles() {
	populate_roles_160();
	populate_roles_210();
	populate_roles_230();
	populate_roles_250();
	populate_roles_260();
	populate_roles_270();
	populate_roles_280();
	populate_roles_300();
}

/**
 * Create the roles for WordPress 2.0
 *
 * @since 2.0.0
 */
function populate_roles_160() {
	// Add roles

	// Dummy gettext calls to get strings in the catalog.
	/* translators: user role */
	_x('Administrator', 'User role');
	/* translators: user role */
	_x('Editor', 'User role');
	/* translators: user role */
	_x('Author', 'User role');
	/* translators: user role */
	_x('Contributor', 'User role');
	/* translators: user role */
	_x('Subscriber', 'User role');

	add_role('administrator', 'Administrator');
	add_role('editor', 'Editor');
	add_role('author', 'Author');
	add_role('contributor', 'Contributor');
	add_role('subscriber', 'Subscriber');

	// Add caps for Administrator role
	$role =& get_role('administrator');
	$role->add_cap('switch_themes');
	$role->add_cap('edit_themes');
	$role->add_cap('activate_plugins');
	$role->add_cap('edit_plugins');
	$role->add_cap('edit_users');
	$role->add_cap('edit_files');
	$role->add_cap('manage_options');
	$role->add_cap('moderate_comments');
	$role->add_cap('manage_categories');
	$role->add_cap('manage_links');
	$role->add_cap('upload_files');
	$role->add_cap('import');
	$role->add_cap('unfiltered_html');
	$role->add_cap('edit_posts');
	$role->add_cap('edit_others_posts');
	$role->add_cap('edit_published_posts');
	$role->add_cap('publish_posts');
	$role->add_cap('edit_pages');
	$role->add_cap('read');
	$role->add_cap('level_10');
	$role->add_cap('level_9');
	$role->add_cap('level_8');
	$role->add_cap('level_7');
	$role->add_cap('level_6');
	$role->add_cap('level_5');
	$role->add_cap('level_4');
	$role->add_cap('level_3');
	$role->add_cap('level_2');
	$role->add_cap('level_1');
	$role->add_cap('level_0');

	// Add caps for Editor role
	$role =& get_role('editor');
	$role->add_cap('moderate_comments');
	$role->add_cap('manage_categories');
	$role->add_cap('manage_links');
	$role->add_cap('upload_files');
	$role->add_cap('unfiltered_html');
	$role->add_cap('edit_posts');
	$role->add_cap('edit_others_posts');
	$role->add_cap('edit_published_posts');
	$role->add_cap('publish_posts');
	$role->add_cap('edit_pages');
	$role->add_cap('read');
	$role->add_cap('level_7');
	$role->add_cap('level_6');
	$role->add_cap('level_5');
	$role->add_cap('level_4');
	$role->add_cap('level_3');
	$role->add_cap('level_2');
	$role->add_cap('level_1');
	$role->add_cap('level_0');

	// Add caps for Author role
	$role =& get_role('author');
	$role->add_cap('upload_files');
	$role->add_cap('edit_posts');
	$role->add_cap('edit_published_posts');
	$role->add_cap('publish_posts');
	$role->add_cap('read');
	$role->add_cap('level_2');
	$role->add_cap('level_1');
	$role->add_cap('level_0');

	// Add caps for Contributor role
	$role =& get_role('contributor');
	$role->add_cap('edit_posts');
	$role->add_cap('read');
	$role->add_cap('level_1');
	$role->add_cap('level_0');

	// Add caps for Subscriber role
	$role =& get_role('subscriber');
	$role->add_cap('read');
	$role->add_cap('level_0');
}

/**
 * Create and modify WordPress roles for WordPress 2.1.
 *
 * @since 2.1.0
 */
function populate_roles_210() {
	$roles = array('administrator', 'editor');
	foreach ($roles as $role) {
		$role =& get_role($role);
		if ( empty($role) )
			continue;

		$role->add_cap('edit_others_pages');
		$role->add_cap('edit_published_pages');
		$role->add_cap('publish_pages');
		$role->add_cap('delete_pages');
		$role->add_cap('delete_others_pages');
		$role->add_cap('delete_published_pages');
		$role->add_cap('delete_posts');
		$role->add_cap('delete_others_posts');
		$role->add_cap('delete_published_posts');
		$role->add_cap('delete_private_posts');
		$role->add_cap('edit_private_posts');
		$role->add_cap('read_private_posts');
		$role->add_cap('delete_private_pages');
		$role->add_cap('edit_private_pages');
		$role->add_cap('read_private_pages');
	}

	$role =& get_role('administrator');
	if ( ! empty($role) ) {
		$role->add_cap('delete_users');
		$role->add_cap('create_users');
	}

	$role =& get_role('author');
	if ( ! empty($role) ) {
		$role->add_cap('delete_posts');
		$role->add_cap('delete_published_posts');
	}

	$role =& get_role('contributor');
	if ( ! empty($role) ) {
		$role->add_cap('delete_posts');
	}
}

/**
 * Create and modify WordPress roles for WordPress 2.3.
 *
 * @since 2.3.0
 */
function populate_roles_230() {
	$role =& get_role( 'administrator' );

	if ( !empty( $role ) ) {
		$role->add_cap( 'unfiltered_upload' );
	}
}

/**
 * Create and modify WordPress roles for WordPress 2.5.
 *
 * @since 2.5.0
 */
function populate_roles_250() {
	$role =& get_role( 'administrator' );

	if ( !empty( $role ) ) {
		$role->add_cap( 'edit_dashboard' );
	}
}

/**
 * Create and modify WordPress roles for WordPress 2.6.
 *
 * @since 2.6.0
 */
function populate_roles_260() {
	$role =& get_role( 'administrator' );

	if ( !empty( $role ) ) {
		$role->add_cap( 'update_plugins' );
		$role->add_cap( 'delete_plugins' );
	}
}

/**
 * Create and modify WordPress roles for WordPress 2.7.
 *
 * @since 2.7.0
 */
function populate_roles_270() {
	$role =& get_role( 'administrator' );

	if ( !empty( $role ) ) {
		$role->add_cap( 'install_plugins' );
		$role->add_cap( 'update_themes' );
	}
}

/**
 * Create and modify WordPress roles for WordPress 2.8.
 *
 * @since 2.8.0
 */
function populate_roles_280() {
	$role =& get_role( 'administrator' );

	if ( !empty( $role ) ) {
		$role->add_cap( 'install_themes' );
	}
}

/**
 * Create and modify WordPress roles for WordPress 3.0.
 *
 * @since 3.0
 */
function populate_roles_300() {
	$role =& get_role( 'administrator' );

	if ( !empty( $role ) ) {
		$role->add_cap( 'update_core' );
		$role->add_cap( 'remove_user' );
		$role->add_cap( 'remove_users' );
	}
}

/**
 * populate network settings
 *
 * @since 3.0
 *
 * @param int $network_id id of network to populate
 */
function populate_network( $network_id = 1, $domain = '', $email = '', $site_name = '', $path = '/', $vhost = 'no' ) {
	global $wpdb, $current_site, $wp_version, $wp_db_version, $wp_rewrite;

	//@todo: turn these checks into returned messages
	if ( $domain == '' )
		die( 'You must provide a domain name!' );
	if ( $site_name == '' )
		die( 'You must provide a site name!' );

	// check for network collision
	$existing_network = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$wpdb->site} WHERE id = %d", $network_id ) );
	if ( $existing_network == $network_id )
		die( 'That network already exists!' );

	$site_user = get_user_by_email( $email );
	if ( !$site_user )
		die( 'You must provide an email address!' );
	// set up site tables
	$template = get_option( 'template' );
	$stylesheet = get_option( 'stylesheet' );
	if ( $template != $stylesheet )
		$allowed_themes = array( $template, $stylesheet );
	else
		$allowed_themes = array( $stylesheet );

	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'site_name', %s)", $network_id, $site_name ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'admin_email', %s)", $network_id, $site_user->user_email ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'admin_user_id', %d)", $network_id, $site_user->ID ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'registration', 'none')", $network_id ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->site." ( id, domain, path ) VALUES ( %d, %s, %s )", $network_id, $domain, $path ) );
	if ( !is_multisite() ) {
		$wpdb->query( "INSERT INTO " . $wpdb->sitecategories . " ( cat_ID, cat_name, category_nicename, last_updated ) VALUES (1, 'Uncategorized', 'uncategorized', NOW())" );
		$wpdb->query( "INSERT INTO " . $wpdb->sitecategories . " ( cat_ID, cat_name, category_nicename, last_updated ) VALUES (2, 'Blogroll', 'blogroll', NOW())" );
	}
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'upload_filetypes', 'jpg jpeg png gif mp3 mov avi wmv midi mid pdf' )", $network_id ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'blog_upload_space', '10' )", $network_id ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'fileupload_maxk', '1500' )", $network_id ) );
	if ( !is_multisite() ) {
		$site_admins = array( $site_user->user_login );
		$users = get_users_of_blog();
		if ( $users ) {
			foreach ( $users as $user ) {
				if ( is_super_admin( $user->ID ) && !in_array( $user->user_login, $site_admins ) )
					$site_admins[] = $user->user_login;
			}
		}
	} else {
		$site_admins = get_site_option( 'site_admins' );
	}
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'site_admins', '" . serialize( $site_admins ) . "' )", $network_id ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'allowedthemes', '" . serialize( $allowed_themes ) . "' )", $network_id ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'illegal_names', '" . serialize( array(  "www", "web", "root", "admin", "main", "invite", "administrator" ) ) . "' )", $network_id ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'wpmu_upgrade_site', '{$wp_db_version}')", $network_id ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'welcome_email', 'Dear User,

Your new SITE_NAME blog has been successfully set up at:
BLOG_URL

You can log in to the administrator account with the following information:
Username: USERNAME
Password: PASSWORD
Login Here: BLOG_URLwp-login.php

We hope you enjoy your new blog.
Thanks!

--The Team @ SITE_NAME')", $network_id ) );
	$wpdb->query( $wpdb->prepare( "INSERT INTO ".$wpdb->sitemeta." (meta_id, site_id, meta_key, meta_value) VALUES (NULL, %d, 'first_post', 'Welcome to <a href=\"SITE_URL\">SITE_NAME</a>. This is your first post. Edit or delete it, then start blogging!' )", $network_id ) );
	$weblog_title = stripslashes( $_POST[ 'weblog_title' ] );

	$current_site->domain = $domain;
	$current_site->path = $base;
	$current_site->site_name = ucfirst( $domain );

	if ( !is_multisite() ) {
		$wpdb->query( $wpdb->prepare( "INSERT INTO {$wpdb->blogs} (site_id, domain, path) VALUES (%s, %s, %s)", $network_id, $domain, $path ) );
		update_usermeta( $site_user->ID, 'source_domain', $domain );
		update_usermeta( $site_user->ID, 'primary_blog', 1 );
	}

	if ( $vhost == 'yes' )
		update_option( 'permalink_structure', '/%year%/%monthnum%/%day%/%postname%/');
	else
		update_option( 'permalink_structure', '/blog/%year%/%monthnum%/%day%/%postname%/');

	$wp_rewrite->flush_rules();

	if ( $vhost == 'yes' ) {
		$vhost_ok = false;
		$hostname = substr( md5( time() ), 0, 6 ) . '.' . $domain; // Very random hostname!
		$page = wp_remote_get( 'http://' . $hostname, array( 'timeout' => 5, 'httpversion' => '1.1' ) );
		if ( is_object( $page ) && is_wp_error( $page ) ) {
			foreach ( $page->get_error_messages() as $err ) {
				$errstr = $err;
			}
		} elseif( $page[ 'response' ][ 'code' ] == 200 ) {
				$vhost_ok = true;
		}
		if ( !$vhost_ok ) {
			$msg = "<h2>Warning! Wildcard DNS may not be configured correctly!</h2>";
			$msg .= "<p>To use the subdomain feature of WordPress MU you must have a wildcard entry in your dns. The installer attempted to contact a random hostname ($hostname) on your domain but failed. It returned this error message:<br /> <strong>$errstr</strong></p><p>From the README.txt:</p>";
			$msg .= "<p><blockquote> If you want to host blogs of the form http://blog.domain.tld/ where domain.tld is the domain name of your machine then you must add a wildcard record to your DNS records.<br />
This usually means adding a '*' hostname record pointing at your webserver in your DNS configuration tool.  Matt has a more detailed <a href='http://ma.tt/2003/10/10/wildcard-dns-and-sub-domains/'>explanation</a> on his blog. If you still have problems, these <a href='http://mu.wordpress.org/forums/tags/wildcard'>forum messages</a> may help.</blockquote></p>";
			$msg .= "<p>You can still use your site but any subdomain you create may not be accessible. This check is not foolproof so ignore if you know your dns is correct.</p>";
		}
	}
	return $msg;
}

?>
